/*
 * Copyright (C) 2024 Network RADIUS SAS (legal@networkradius.com)
 *
 * This software may not be redistributed in any form without the prior
 * written consent of Network RADIUS.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * $Id$
 * @file rlm_proxy_rate_limit.c
 * @brief Rate limiting when proxying requests
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/dlist.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>

#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

/*
 *	The default configuration will use all 256 subtables, but may
 *	be configured to use fewer to simplify testing
 */
#define MAX_NUM_SUBTABLES		(256)

typedef struct rlm_proxy_rate_limit_s rlm_proxy_rate_limit_t;

/*
 *	A subtable, together with an associated expiry list and mutex.
 */
typedef struct {
	int			id;
	rbtree_t		*tree;
	fr_dlist_t		expiry_list;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		mutex;
#endif
} rlm_proxy_rate_limit_table_t;

typedef struct {
	char				*key;
	size_t				key_len;

	time_t				expires;

	/*
	 *	Track the last RADIUS ID for the last request to
	 *	differentiate retransmissions versus new requests (at
	 *	least for serialised authentication attampts).
	 */
	int				last_id;

	/*
	 *	Time that last reject was received from the home server
	 */
	time_t				last_reject;

	/*
	 *	Time that last request was received from the end station
	 */
	time_t				last_request;

	/*
	 *	We only actively suppress after receiving two Access-Rejects from
	 *	home servers within the same second.
	 */
	bool				active;

	/*
	 *	Rough count of number of times the rate has been
	 *	exceeded since suppression began.
	 */
	int				count;

	/*
	 *	Table containing this entry so we can lookup relevant
	 *	expiry_list and mutex during rbtree callbacks
	 */
	rlm_proxy_rate_limit_table_t	*table;

	fr_dlist_t			dlist;
} rlm_proxy_rate_limit_entry_t;

struct rlm_proxy_rate_limit_s {

	uint32_t			max_entries;
	uint32_t			idle_timeout;
	uint32_t			num_subtables;
	uint32_t			window;

	rlm_proxy_rate_limit_table_t	tables[MAX_NUM_SUBTABLES];

};

static const CONF_PARSER module_config[] = {
	{ "max_entries", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_proxy_rate_limit_t, max_entries), "65536" },
	{ "idle_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_proxy_rate_limit_t, idle_timeout), "2" },
	{ "num_subtables", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_proxy_rate_limit_t, num_subtables), "256" },
	{ "window", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_proxy_rate_limit_t, window), "1"},
	CONF_PARSER_TERMINATOR
};

static inline CC_HINT(nonnull) rlm_proxy_rate_limit_entry_t *fr_dlist_head(fr_dlist_t const *head)
{
	if (head->prev == head) return NULL;

	return (rlm_proxy_rate_limit_entry_t *) (((uintptr_t) head->next) - offsetof(rlm_proxy_rate_limit_entry_t, dlist));
}

static rlm_proxy_rate_limit_table_t* derive_key_and_table(rlm_proxy_rate_limit_t *inst, REQUEST *request, char *key, size_t *key_len) {

	uint32_t	hash;
	char		hash_hex[9];
	VALUE_PAIR	*vp1, *vp2;

	fr_assert(*key_len >= 6);	/* Satisfy analyser */

	if ((vp1 = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY)) == NULL) {
		RDEBUG("Not rate limiting a request without a User-Name attribute");
		return NULL;
	}

	if ((vp2 = fr_pair_find_by_num(request->packet->vps, PW_CALLING_STATION_ID, 0, TAG_ANY)) == NULL) {
		RDEBUG("Not rate limiting a request without a Calling-Station-ID attribute");
		return NULL;
	}

	/*
	 *	Should not happen since the buffer we are given is sufficient: 512 = 253 + 253 + 6
	 */
	if (unlikely(6 + vp1->vp_length + vp2->vp_length > *key_len)) {
		RDEBUG("Not rate limiting a request where the key expansion is too large.");
		return NULL;
	}

	/*
	 *	key will be "HHHHHH{User-Name}{Calling-Station-Id}"
	 */
        memcpy(key + 6, vp1->vp_strvalue, vp1->vp_length);
	memcpy(key + 6 + vp1->vp_length, vp2->vp_strvalue, vp2->vp_length);
	*key_len = 6 + vp1->vp_length + vp2->vp_length;

	/*
	 *	Stable map of the key to a 4-octet value. Provides
	 *	good distribution with similar prefixes.
	 */
	hash = fr_hash(key + 6, (*key_len) - 6);

	/*
	 *	First three octets are used as a prefix of the key,
	 *	since usernames have much in common.
	 */
	snprintf(hash_hex, 9, "%08X", hash);
	memcpy(key, hash_hex, 6);

	/*
	 *	Last octet used to pick one of the tables.
	 */
	return &inst->tables[(hash & 0xff) % inst->num_subtables];

}

/*
 *	Check whether we have recently seen repeated Access-Rejects for this username
 *      and calling station, and if this is a new request then issue an Access-Reject
 */
static int CC_HINT(nonnull) mod_common(void * instance, REQUEST *request)
{
	rlm_proxy_rate_limit_t		*inst = instance;
	char				key[512];
	size_t				key_len = sizeof(key);
	rlm_proxy_rate_limit_table_t	*table;
	rlm_proxy_rate_limit_entry_t	*entry, my_entry;

	if (!(table = derive_key_and_table(inst, request, key, &key_len)))
		return 0;

	my_entry.key = key;
	my_entry.key_len = key_len;
	entry = rbtree_finddata(table->tree, &my_entry);

	if (!entry)
		return 0;

	if (entry->expires <= request->timestamp) {
		RDEBUG3("Rate limit entry %.*s (%d) has expired", 6, entry->key, entry->table->id);
		rbtree_deletebydata(table->tree, entry);
		return 0;
	};

	/*
	 *	@todo - add configurable threshold. For now, it's only one packet.
	 */

	/*
	 *	Limit only when active and for new requests, not
	 *	retransmissions.
	 */
	if (!entry->active || entry->last_id == request->packet->id)
		return 0;

	RDEBUG("Active rate limit entry %.*s (%d) matched for new request. Cancelling proxy "
		"and sending Access-Reject. Instance %d.", 6, entry->key, entry->table->id, entry->count);

	/*
	 *	Extend the suppression period for misbehaving devices that are continuing
	 *	to send rapid requests (within the same second), i.e. they are not waiting
	 *	for our (delayed) responses.
	 *
	 *	We don't do this unless the requests are very
	 *	frequent, otherwise suppression would continue for so
	 *	long as the end stations continues to periodically
	 *	retry, which is likely not what we want.
	 */
	if ((request->timestamp - entry->last_request) < inst->window &&
	    (entry->expires < request->timestamp + inst->idle_timeout)) {
		entry->expires = request->timestamp + inst->idle_timeout;

		PTHREAD_MUTEX_LOCK(&table->mutex);
		fr_dlist_entry_unlink(&entry->dlist);
		fr_dlist_insert_tail(&table->expiry_list, &entry->dlist);
		PTHREAD_MUTEX_UNLOCK(&table->mutex);
		RDEBUG3("Active rate limit entry %.*s (%d) extended", 6, entry->key, entry->table->id);
	}

	entry->last_request = request->timestamp;
	entry->count++;
	return -1;
}

static rlm_rcode_t CC_HINT(nonnull) mod_pre_proxy(void * instance, REQUEST *request)
{
	VALUE_PAIR			*vp;

	if (mod_common(instance, request) == 0) return RLM_MODULE_NOOP;

	/*
	 *  This new request arrived within the suppression interval. Don't proxy but
	 *  return our own Access-Reject instead.
	 *
	 *  Allocating a proxy_reply and setting dst_port to 0 ensures that we send a
	 *  delayed response.
	 */
	request->proxy_reply = rad_alloc_reply(request, request->proxy);
	request->proxy_reply->code = PW_CODE_ACCESS_REJECT;
	request->proxy->dst_port = 0;

	vp = pair_make_reply("Reply-Message", "Proxy rate limit exceeded", T_OP_EQ);
	if (!vp)
		REDEBUG("Failed creating Reply-Message");

	return RLM_MODULE_FAIL;
}

static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void * instance, REQUEST *request)
{
	VALUE_PAIR			*vp;

	if (mod_common(instance, request) == 0) return RLM_MODULE_NOOP;

	fr_pair_list_free(&request->reply->vps);

	vp = pair_make_reply("Reply-Message", "Proxy rate limit exceeded", T_OP_EQ);
	if (!vp)
		REDEBUG("Failed creating Reply-Message");

	return RLM_MODULE_REJECT;
}

/*
 *	Record Access-Rejects for (username + calling station) a key and store the ID.
 *
 *      Trigger suppression after receiving two Access Rejects within the same second.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_proxy(void *instance, REQUEST *request)
{
	rlm_proxy_rate_limit_t		*inst = instance;
	char				key[512];
	size_t				key_len = sizeof(key);
	rlm_proxy_rate_limit_table_t	*table;
	rlm_proxy_rate_limit_entry_t	*entry, my_entry;

	if (request->proxy_reply->code != PW_CODE_ACCESS_REJECT)
		return RLM_MODULE_NOOP;

	if (!(table = derive_key_and_table(inst, request, key, &key_len)))
		return RLM_MODULE_OK;

	my_entry.key = (char *)key;
	my_entry.key_len = key_len;
	entry = rbtree_finddata(table->tree, &my_entry);
	if (!entry) {

		/*
		 *	Too many entries in the table.  Delete the oldest one.
		 */
		if (rbtree_num_elements(table->tree) > inst->max_entries) {
			PTHREAD_MUTEX_LOCK(&table->mutex);
			entry = fr_dlist_head(&table->expiry_list);
			PTHREAD_MUTEX_UNLOCK(&table->mutex);

			rbtree_deletebydata(table->tree, entry);
		}

		MEM(entry = talloc_zero(NULL, rlm_proxy_rate_limit_entry_t));

		MEM(entry->key = talloc_memdup(entry, key, key_len));
		entry->key_len = key_len;

		fr_dlist_entry_init(&entry->dlist);
		entry->table = table;
		entry->active = false;
		entry->last_request = entry->last_reject = request->timestamp;
		entry->last_id = request->packet->id;

		/*
		 *	Set to "request->timestamp +
		 *	inst->idle_timeout" if we at some point decide
		 *	to periodically walk from the head of the
		 *	expiry list to free expired entries.  (To
		 *	maintain list in order of expiry time, without
		 *	requiring two lists.)
		 */
		entry->expires = request->timestamp + 1;

		/*
		 *	Save it.
		 */
		if (!rbtree_insert(table->tree, entry)) {
			talloc_free(entry);
			return RLM_MODULE_OK;
		}
		RDEBUG3("Inactive rate limit entry %.*s (%d) saved", 6, entry->key, entry->table->id);

	} else {

		/*
		 * Trigger suppression after two Access-Rejects from a home server
		 * for different requests (not retransmissions) are received within
		 * the same second.
		 */
		if (!entry->active && entry->last_id != request->packet->id &&
		    request->timestamp - entry->last_reject < 1) {
			entry->active = true;
			entry->count = 0;
			RDEBUG("Rate limit entry %.*s (%d) activated", 6, entry->key, entry->table->id);
		} else {
			RDEBUG3("Rate limit entry %.*s (%d) updated", 6, entry->key, entry->table->id);
		}

		entry->last_request = entry->last_reject = request->timestamp;
		entry->last_id = request->packet->id;

		/*
		 * Ditto comment above ("request->timestamp + inst->idle_timeout") should we later
		 * decide to proactively free expiry list entries.
		 */
		entry->expires = request->timestamp +
			(entry->active ? inst->idle_timeout : 1);

	}

	PTHREAD_MUTEX_LOCK(&table->mutex);
	fr_dlist_entry_unlink(&entry->dlist);
	fr_dlist_insert_tail(&table->expiry_list, &entry->dlist);
	PTHREAD_MUTEX_UNLOCK(&table->mutex);

	return RLM_MODULE_OK;
}

static int cmp_table_entry(void const *one, void const *two)
{
	rlm_proxy_rate_limit_entry_t const *a = (rlm_proxy_rate_limit_entry_t const *) one;
	rlm_proxy_rate_limit_entry_t const *b = (rlm_proxy_rate_limit_entry_t const *) two;

	if (a->key_len < b->key_len) return -1;
	if (a->key_len > b->key_len) return +1;

	return memcmp(a->key, b->key, a->key_len);
}

static void free_table_entry(void *data)
{
	rlm_proxy_rate_limit_entry_t *entry = (rlm_proxy_rate_limit_entry_t *) data;

	PTHREAD_MUTEX_LOCK(&entry->table->mutex);
	fr_dlist_entry_unlink(&entry->dlist);
	PTHREAD_MUTEX_UNLOCK(&entry->table->mutex);

	talloc_free(entry);
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	int i;
	rlm_proxy_rate_limit_t *inst = instance;

	FR_INTEGER_BOUND_CHECK("max_entries", inst->max_entries, <=, ((uint32_t) 1) << 20);
	FR_INTEGER_BOUND_CHECK("max_entries", inst->max_entries, >=, 1);

	FR_INTEGER_BOUND_CHECK("idle_timeout", inst->idle_timeout, <=, 10);
	FR_INTEGER_BOUND_CHECK("idle_timeout", inst->idle_timeout, >=, 1);

	if (!inst->window) {
		inst->window = 1;
	} else {
		FR_INTEGER_BOUND_CHECK("window", inst->window, <=, 5);
	}

	/* Undocumented. Intended to simplify testing. */
	if (!inst->num_subtables) {
		inst->num_subtables = MAX_NUM_SUBTABLES;
	} else {
		FR_INTEGER_BOUND_CHECK("num_subtables", inst->num_subtables, <=, MAX_NUM_SUBTABLES);
		FR_INTEGER_BOUND_CHECK("num_subtables", inst->num_subtables, >=, 1);
	}

	/*
	 *	Don't worry the user about sub-tables.
	 */
	inst->max_entries /= inst->num_subtables;

	/*
	 *	Create a set of tables containing an rbtree, with
	 *	associated expiry list and mutex
	 *
	 *	Multiple such structures mitigates lock contention.
	 */
	for (i = 0; i < (int)inst->num_subtables; i++) {

		rlm_proxy_rate_limit_table_t *table = &inst->tables[i];

		table->id = i;

		if (!(table->tree = rbtree_create(inst, cmp_table_entry, free_table_entry, RBTREE_FLAG_LOCK))) {
			cf_log_err_cs(conf, "Failed creating internal data structure for tracking table %d", i);
			goto fail;
		}

		fr_dlist_entry_init(&table->expiry_list);
#ifdef HAVE_PTHREAD_H
		if (pthread_mutex_init(&table->mutex, NULL) < 0) {
			rbtree_free(table->tree);		/* We just allocated this */
			cf_log_err_cs(conf, "Failed creating mutex for tracking table %d", i);
			goto fail;
		}
#endif

	}

	return 0;

fail:

	/*
	 *  Release what we allocated prior to failure.
	 *
	 */
	for (i--; i > 0; i--) {
#ifdef HAVE_PTHREAD_H
		pthread_mutex_destroy(&inst->tables[i].mutex);
#endif
		rbtree_free(inst->tables[i].tree);
	}

	return -1;

}

static int mod_detach(void *instance)
{
	rlm_proxy_rate_limit_t *inst = instance;
	int i;

	for (i = 0; i < (int)inst->num_subtables; i++) {
#ifdef HAVE_PTHREAD_H
		pthread_mutex_destroy(&inst->tables[i].mutex);
#endif
		rbtree_free(inst->tables[i].tree);
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_proxy_rate_limit;
module_t rlm_proxy_rate_limit = {
	.magic		= RLM_MODULE_INIT,
	.name		= "proxy_rate_limit",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_proxy_rate_limit_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
	},
};
