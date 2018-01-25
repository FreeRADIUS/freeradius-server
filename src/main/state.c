/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @brief Multi-packet state handling
 * @file main/state.c
 *
 * @ingroup AVP
 *
 * @copyright 2014 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/rad_assert.h>

typedef struct state_entry_t {
	uint8_t		state[AUTH_VECTOR_LEN];

	time_t		cleanup;
	struct state_entry_t *prev;
	struct state_entry_t *next;

	int		tries;

	TALLOC_CTX		*ctx;
	VALUE_PAIR		*vps;

	void 		*opaque;
	void 		(*free_opaque)(void *opaque);
} state_entry_t;

struct fr_state_t {
	rbtree_t *tree;

	state_entry_t *head, *tail;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t mutex;
#endif
};

static fr_state_t global_state;

#ifdef HAVE_PTHREAD_H

#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock

#else
/*
 *	This is easier than ifdef's throughout the code.
 */
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)

#endif

/*
 *	rbtree callback.
 */
static int state_entry_cmp(void const *one, void const *two)
{
	state_entry_t const *a = one;
	state_entry_t const *b = two;

	return memcmp(a->state, b->state, sizeof(a->state));
}

/*
 *	When an entry is free'd, it's removed from the linked list of
 *	cleanup times.
 *
 *	Note that
 */
static void state_entry_free(fr_state_t *state, state_entry_t *entry)
{
	state_entry_t *prev, *next;

	/*
	 *	If we're deleting the whole tree, don't bother doing
	 *	all of the fixups.
	 */
	if (!state || !state->tree) return;

	prev = entry->prev;
	next = entry->next;

	if (prev) {
		rad_assert(state->head != entry);
		prev->next = next;
	} else if (state->head) {
		rad_assert(state->head == entry);
		state->head = next;
	}

	if (next) {
		rad_assert(state->tail != entry);
		next->prev = prev;
	} else if (state->tail) {
		rad_assert(state->tail == entry);
		state->tail = prev;
	}

	if (entry->opaque) {
		entry->free_opaque(entry->opaque);
	}

#ifdef WITH_VERIFY_PTR
	(void) talloc_get_type_abort(entry, state_entry_t);
#endif
	rbtree_deletebydata(state->tree, entry);

	if (entry->ctx) talloc_free(entry->ctx);

	talloc_free(entry);
}

fr_state_t *fr_state_init(TALLOC_CTX *ctx)
{
	fr_state_t *state;

	if (!ctx) {
		state = &global_state;
		if (state->tree) return state;
	} else {
		state = talloc_zero(ctx, fr_state_t);
		if (!state) return 0;
	}

#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&state->mutex, NULL) != 0) {
		talloc_free(state);
		return NULL;
	}
#endif

	state->tree = rbtree_create(NULL, state_entry_cmp, NULL, 0);
	if (!state->tree) {
		talloc_free(state);
		return NULL;
	}

	return state;
}

void fr_state_delete(fr_state_t *state)
{
	rbtree_t *my_tree;

	if (!state) return;

	PTHREAD_MUTEX_LOCK(&state->mutex);

	/*
	 *	Tell the talloc callback to NOT delete the entry from
	 *	the tree.  We're deleting the entire tree.
	 */
	my_tree = state->tree;
	state->tree = NULL;

	rbtree_free(my_tree);
	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	if (state != &global_state) talloc_free(state);
}

/*
 *	Create a new entry.  Called with the mutex held.
 */
static state_entry_t *fr_state_create(fr_state_t *state, const char *server, RADIUS_PACKET *packet, state_entry_t *old)
{
	size_t i;
	uint32_t x;
	time_t now = time(NULL);
	VALUE_PAIR *vp;
	state_entry_t *entry, *next;

	/*
	 *	Clean up old entries.
	 */
	for (entry = state->head; entry != NULL; entry = next) {
		next = entry->next;

		if (entry == old) continue;

		/*
		 *	Too old, we can delete it.
		 */
		if (entry->cleanup < now) {
			state_entry_free(state, entry);
			continue;
		}

		/*
		 *	Unused.  We can delete it, even if now isn't
		 *	the time to clean it up.
		 */
		if (!entry->ctx && !entry->opaque) {
			state_entry_free(state, entry);
			continue;
		}

		break;
	}

	/*
	 *	Limit the size of the cache based on how many requests
	 *	we can handle at the same time.
	 */
	if (rbtree_num_elements(state->tree) >= main_config.max_requests * 2) {
		return NULL;
	}

	/*
	 *	Allocate a new one.
	 */
	entry = talloc_zero(state->tree, state_entry_t);
	if (!entry) return NULL;

	/*
	 *	Limit the lifetime of this entry based on how long the
	 *	server takes to process a request.  Doing it this way
	 *	isn't perfect, but it's reasonable, and it's one less
	 *	thing for an administrator to configure.
	 */
	entry->cleanup = now + main_config.max_request_time * 10;

	/*
	 *	Hacks for EAP, until we convert EAP to using the state API.
	 *
	 *	The EAP module creates it's own State attribute, so we
	 *	want to use that one in preference to one we create.
	 */
	vp = fr_pair_find_by_num(packet->vps, PW_STATE, 0, TAG_ANY);

	/*
	 *	If possible, base the new one off of the old one.
	 */
	if (old) {
		entry->tries = old->tries + 1;

		/*
		 *	Track State
		 */
		if (!vp) {
			memcpy(entry->state, old->state, sizeof(entry->state));

			entry->state[1] = entry->state[0] ^ entry->tries;
			entry->state[8] = entry->state[2] ^ ((((uint32_t) HEXIFY(RADIUSD_VERSION)) >> 16) & 0xff);
			entry->state[10] = entry->state[2] ^ ((((uint32_t) HEXIFY(RADIUSD_VERSION)) >> 8) & 0xff);
			entry->state[12] = entry->state[2] ^ (((uint32_t) HEXIFY(RADIUSD_VERSION)) & 0xff);
		}

		/*
		 *	The old one isn't used any more, so we can free it.
		 */
		if (!old->opaque) state_entry_free(state, old);

	} else if (!vp) {
		/*
		 *	16 octets of randomness should be enough to
		 *	have a globally unique state.
		 */
		for (i = 0; i < sizeof(entry->state) / sizeof(x); i++) {
			x = fr_rand();
			memcpy(entry->state + (i * 4), &x, sizeof(x));
		}
	}

	/*
	 *	If EAP created a State, use that.  Otherwise, use the
	 *	one we created above.
	 */
	if (vp) {
		if (rad_debug_lvl && (vp->vp_length > sizeof(entry->state))) {
			WARN("State should be %zd octets!",
			     sizeof(entry->state));
		}
		memcpy(entry->state, vp->vp_octets, sizeof(entry->state));

	} else {
		vp = fr_pair_afrom_num(packet, PW_STATE, 0);
		fr_pair_value_memcpy(vp, entry->state, sizeof(entry->state));
		fr_pair_add(&packet->vps, vp);
	}

	/*	Make unique for different virtual servers handling same request
	 */
	if (server) *((uint32_t *)(&entry->state[4])) ^= fr_hash_string(server);

	if (!rbtree_insert(state->tree, entry)) {
		talloc_free(entry);
		return NULL;
	}

	/*
	 *	Link it to the end of the list, which is implicitely
	 *	ordered by cleanup time.
	 */
	if (!state->head) {
		entry->prev = entry->next = NULL;
		state->head = state->tail = entry;
	} else {
		rad_assert(state->tail != NULL);

		entry->prev = state->tail;
		state->tail->next = entry;

		entry->next = NULL;
		state->tail = entry;
	}

	return entry;
}


/*
 *	Find the entry, based on the State attribute.
 */
static state_entry_t *fr_state_find(fr_state_t *state, const char *server, RADIUS_PACKET *packet)
{
	VALUE_PAIR *vp;
	state_entry_t *entry, my_entry;

	vp = fr_pair_find_by_num(packet->vps, PW_STATE, 0, TAG_ANY);
	if (!vp) return NULL;

	if (vp->vp_length != sizeof(my_entry.state)) return NULL;

	memcpy(my_entry.state, vp->vp_octets, sizeof(my_entry.state));

	/*	Make unique for different virtual servers handling same request
	 */
	if (server) *((uint32_t *)(&my_entry.state[4])) ^= fr_hash_string(server);

	entry = rbtree_finddata(state->tree, &my_entry);

#ifdef WITH_VERIFY_PTR
	if (entry)  (void) talloc_get_type_abort(entry, state_entry_t);
#endif

	return entry;
}

/*
 *	Called when sending Access-Reject, so that all State is
 *	discarded.
 */
void fr_state_discard(REQUEST *request, RADIUS_PACKET *original)
{
	state_entry_t *entry;
	fr_state_t *state = &global_state;

	fr_pair_list_free(&request->state);
	request->state = NULL;

	PTHREAD_MUTEX_LOCK(&state->mutex);
	entry = fr_state_find(state, request->server, original);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state->mutex);
		return;
	}

	state_entry_free(state, entry);
	PTHREAD_MUTEX_UNLOCK(&state->mutex);
	return;
}

/*
 *	Get the VPS from the state.
 */
void fr_state_get_vps(REQUEST *request, RADIUS_PACKET *packet)
{
	state_entry_t *entry;
	fr_state_t *state = &global_state;
	TALLOC_CTX *old_ctx = NULL;

	rad_assert(request->state == NULL);

	/*
	 *	No State, don't do anything.
	 */
	if (!fr_pair_find_by_num(request->packet->vps, PW_STATE, 0, TAG_ANY)) {
		RDEBUG3("session-state: No State attribute");
		return;
	}

	PTHREAD_MUTEX_LOCK(&state->mutex);
	entry = fr_state_find(state, request->server, packet);

	/*
	 *	This has to be done in a mutex lock, because talloc
	 *	isn't thread-safe.
	 */
	if (entry) {
		RDEBUG2("Restoring &session-state");

		if (request->state_ctx) old_ctx = request->state_ctx;

		request->state_ctx = entry->ctx;
		request->state = entry->vps;

		entry->ctx = NULL;
		entry->vps = NULL;

		rdebug_pair_list(L_DBG_LVL_2, request, request->state, "&session-state:");

	} else {
		RDEBUG2("session-state: No cached attributes");
	}

	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	/*
	 *	Free this outside of the mutex for less contention.
	 */
	if (old_ctx) talloc_free(old_ctx);

	VERIFY_REQUEST(request);
	return;
}


/*
 *	Put request->state into the State attribute.  Put the State
 *	attribute into the vps list.  Delete the original entry, if it
 *	exists.
 */
bool fr_state_put_vps(REQUEST *request, RADIUS_PACKET *original, RADIUS_PACKET *packet)
{
	state_entry_t *entry, *old;
	fr_state_t *state = &global_state;

	if (!request->state) {
		size_t i;
		uint32_t x;
		VALUE_PAIR *vp;
		uint8_t buffer[16];

		RDEBUG3("session-state: Nothing to cache");

		if (packet->code != PW_CODE_ACCESS_CHALLENGE) return true;

		vp = fr_pair_find_by_num(packet->vps, PW_STATE, 0, TAG_ANY);
		if (vp) return true;

		/*
		 *
		 */
		for (i = 0; i < sizeof(buffer) / sizeof(x); i++) {
			x = fr_rand();
			memcpy(buffer + (i * 4), &x, sizeof(x));
		}

		vp = fr_pair_afrom_num(packet, PW_STATE, 0);
		fr_pair_value_memcpy(vp, buffer, sizeof(buffer));
		fr_pair_add(&packet->vps, vp);

		return true;
	}

	RDEBUG2("session-state: Saving cached attributes");
	rdebug_pair_list(L_DBG_LVL_1, request, request->state, NULL);

	PTHREAD_MUTEX_LOCK(&state->mutex);

	if (original) {
		old = fr_state_find(state, request->server, original);
	} else {
		old = NULL;
	}

	entry = fr_state_create(state, request->server, packet, old);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state->mutex);
		return false;
	}

	rad_assert(entry->ctx == NULL);
	entry->ctx = request->state_ctx;
	entry->vps = request->state;

	request->state_ctx = NULL;
	request->state = NULL;

	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	VERIFY_REQUEST(request);
	return true;
}

/*
 *	Find the opaque data associated with a State attribute.
 *	Leave the data in the entry.
 */
void *fr_state_find_data(fr_state_t *state, REQUEST *request, RADIUS_PACKET *packet)
{
	void *data;
	state_entry_t *entry;

	if (!state) return false;

	PTHREAD_MUTEX_LOCK(&state->mutex);
	entry = fr_state_find(state, request->server, packet);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state->mutex);
		return NULL;
	}

	data = entry->opaque;
	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	return data;
}


/*
 *	Get the opaque data associated with a State attribute.
 *	and remove the data from the entry.
 */
void *fr_state_get_data(fr_state_t *state, REQUEST *request, RADIUS_PACKET *packet)
{
	void *data;
	state_entry_t *entry;

	if (!state) return NULL;

	PTHREAD_MUTEX_LOCK(&state->mutex);
	entry = fr_state_find(state, request->server, packet);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state->mutex);
		return NULL;
	}

	data = entry->opaque;
	entry->opaque = NULL;
	PTHREAD_MUTEX_UNLOCK(&state->mutex);

	return data;
}


/*
 *	Get the opaque data associated with a State attribute.
 *	and remove the data from the entry.
 */
bool fr_state_put_data(fr_state_t *state, REQUEST *request, RADIUS_PACKET *original, RADIUS_PACKET *packet,
		       void *data, void (*free_data)(void *))
{
	state_entry_t *entry, *old;

	if (!state) return false;

	PTHREAD_MUTEX_LOCK(&state->mutex);

	if (original) {
		old = fr_state_find(state, request->server, original);
	} else {
		old = NULL;
	}

	entry = fr_state_create(state, request->server, packet, old);
	if (!entry) {
		PTHREAD_MUTEX_UNLOCK(&state->mutex);
		return false;
	}

	/*
	 *	If we're moving the data, ensure that we delete it
	 *	from the old state.
	 */
	if (old && (old->opaque == data)) {
		old->opaque = NULL;
	}

	entry->opaque = data;
	entry->free_opaque = free_data;

	PTHREAD_MUTEX_UNLOCK(&state->mutex);
	return true;
}
