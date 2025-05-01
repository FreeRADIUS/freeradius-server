/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_kafka.c
 * @brief Produces messages to a Kafka messaging queue.
 *
 * @copyright 2021  TheBinary <binary4bytes@gmail.com>
 * @copyright 2025  The FreeRADIUS server project
 * @copyright 2025  NetworkRADIUS SAS
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <librdkafka/rdkafka.h>
#include <ctype.h>

#define LOG_PREFIX "rlm_kafka"

#define RLM_KAFKA_PROP_SET(CONF, PROP, VALUE, BUF_ERRSTR) 								\
	do {														\
		if (rd_kafka_conf_set(CONF, PROP, VALUE, BUF_ERRSTR, sizeof(BUF_ERRSTR)) != RD_KAFKA_CONF_OK )		\
			ERROR("Error setting Kafka global property: '%s=%s' : %s\n", PROP, VALUE, BUF_ERRSTR);		\
	} while (0)

#define RLM_KAFKA_TOPIC_PROP_SET(CONF, PROP, VALUE, BUF_ERRSTR)								\
	do {														\
		if (rd_kafka_topic_conf_set(CONF, PROP, VALUE, BUF_ERRSTR, sizeof(BUF_ERRSTR)) != RD_KAFKA_CONF_OK )	\
			ERROR("Error setting Kafka topic property: '%s=%s' : %s\n", PROP, VALUE, BUF_ERRSTR);		\
	} while (0)

typedef struct rlm_kafka_section_config {

	CONF_SECTION *cs;
	char const *reference;
	char const *key;
	char const *headers;

	/*
	 *  Topic handle to avoid rbtree lookups for section-based calls
	 *
	 */
	rd_kafka_topic_t *rkt;

} rlm_kafka_section_config_t;

typedef struct rlm_kafka_rkt_by_name {

	const char *name;
	rd_kafka_topic_t *rkt;

	/*
	 *  Only one entry is the "owner" for a topic, and all others are
	 *  references to it (having ref = true)
	 */
	bool ref;

} rlm_kafka_rkt_by_name_t;

typedef struct rlm_kafka_t {

	char const *name;

	bool async;

	char const *bootstrap;
	char const *schema;

	char const *stats_filename;
	FILE *stats_file;

	rd_kafka_t *rk;

	rbtree_t *rkt_by_name_tree;

	rlm_kafka_section_config_t authorize;
	rlm_kafka_section_config_t postauth;
	rlm_kafka_section_config_t accounting;

} rlm_kafka_t;

static const CONF_PARSER global_config[] = {
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER topic_config[] = {
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER authorize_config[] = {
	{ "reference", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, authorize.reference), ".message" },
	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, authorize.key), NULL},
	{ "headers", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, authorize.headers), NULL},
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER postauth_config[] = {
	{ "reference", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, postauth.reference), ".message" },
	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, postauth.key), NULL},
	{ "headers", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, postauth.headers), NULL},
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER accounting_config[] = {
	{ "reference", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, accounting.reference), ".message" },
	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, accounting.key), NULL},
	{ "headers", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, accounting.headers), NULL},
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER stats_config[] = {
	{"file", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_kafka_t, stats_filename), NULL},
	CONF_PARSER_TERMINATOR
};

/*
 *  It would be nice to have a/synchronous delivery be a property set for each
 *  topic, but unfortunately this is not possible.
 *
 *  High-throughput asynchronous requires a sufficiently large linger.ms to
 *  ensure batched message delivery.
 *
 *  Synchronous delivery requires linger.ms = 0 to avoid unnecessary delays.
 *
 *  However, linger.ms is a global property, and rd_kafka_flush() purges the
 *  queue of all topics.
 *
 */
static const CONF_PARSER module_config[] = {
	{ "bootstrap-servers", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_kafka_t, bootstrap), NULL },
	{ "asynchronous", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_kafka_t, async), "no" },
	{ "global-config", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const*) global_config },
	{ "topic-config", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const*) topic_config },
	{ "authorize", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const*) authorize_config },
	{ "post-auth", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const*) postauth_config },
	{ "accounting", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const*) accounting_config },
	{ "statistics", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const*) stats_config },
	CONF_PARSER_TERMINATOR
};

static int stats_cb (UNUSED rd_kafka_t *rk, char *json, size_t json_len, void *opaque) {
	rlm_kafka_t	*inst = opaque;

	/*
	 *  Apparently this callback does not need to be re-entrant...
	 */
	DEBUG3("stats callback");
	fprintf(inst->stats_file, "%.*s\n", (int)json_len, json);
	fflush(inst->stats_file);

	return 0;
}

/*
 * This callback is triggered exactly once per message from either
 * rd_kafka_poll() or rd_kafka_flush() and executes on the application's
 * thread.
 */
static void dr_msg_cb(UNUSED rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, UNUSED void *opaque) {
	rd_kafka_resp_err_t	*status;
	int32_t 		broker_id = -1;
	const char		*persisted = "unknown";

	/*
	 *  For synchronous send, acknowledge by writing err into the message's opaque.
	 *
	 *  Any error is reported immediately by the thread that was waiting for this.
	 */
	if (rkmessage->_private) {
		status = (rd_kafka_resp_err_t *)rkmessage->_private;
		*status = rkmessage->err;
		return;
	}

	/*
	 *  Message must have been sent asynchronously if we get this far.
	 */
	if (!rkmessage->err) return;

#if RD_KAFKA_VERSION >= 0x010500ff
        broker_id = rd_kafka_message_broker_id(rkmessage);
#endif

#if RD_KAFKA_VERSION >= 0x010000ff
	switch (rd_kafka_message_status(rkmessage)) {
	case RD_KAFKA_MSG_STATUS_PERSISTED:
		persisted = "definately";
		break;

	case RD_KAFKA_MSG_STATUS_NOT_PERSISTED:
		persisted = "not";
		break;

	case RD_KAFKA_MSG_STATUS_POSSIBLY_PERSISTED:
		persisted = "possibly";
		break;

	}
#endif

	ERROR("Kafka delivery report '%s' for key: %.*s (%s persisted to broker %" PRId32 ")\n",
	      rd_kafka_err2str(rkmessage->err),
	      (int)rkmessage->key_len, (char *)rkmessage->key,
	      persisted,
	      broker_id
	     );
}

/*
 * This callback may be triggered spontaneously from any thread at any time.
 *
 */
static void log_cb(const rd_kafka_t *rk, int level, UNUSED const char *facility, const char *buf)
{

	rlm_kafka_t *inst = rd_kafka_opaque(rk);

	/*
	 *  Map Kafka error levels (based on syslog severities) to FR log levels
	 */
	switch (level) {
	case 4:
		WARN(LOG_PREFIX " (%s): %s", inst->name, buf);
		break;
	case 5:
	case 6:
		INFO(LOG_PREFIX " (%s): %s", inst->name, buf);
		break;
	case 7:
		DEBUG(LOG_PREFIX " (%s): %s", inst->name, buf);
		break;
	default:
		ERROR(LOG_PREFIX " (%s): %s", inst->name, buf);
	}
}

/*
 *  Note: No error_cb function: "If no error_cb is registered ... then the
 *  errors will be logged [log_cb] instead."
 *
 */

/*
 * A wrapper around rd_kafka_producev() that implements synchronous semantics
 * and retries on queue full.
 *
 */
#define NO_DELIVERY_REPORT INT_MIN
#define RETRIES 2
static int kafka_produce(rlm_kafka_t *inst, UNUSED REQUEST *request, rd_kafka_topic_t *rkt,
			 char* const key, const size_t key_len, char* const message, const size_t len,
			 rd_kafka_headers_t *hdrs, const bool async) {

	rd_kafka_resp_err_t	status = NO_DELIVERY_REPORT;
	rd_kafka_resp_err_t	err;
	int			attempt;

	/*
	 *  Non-blocking poll to service queue callbacks
	 */
	rd_kafka_poll(inst->rk, 0);

	/*
	 * This is an asynchronous call, on success it will only enqueue the
	 * message on the internal producer queue.
	 *
	 * The actual delivery attempts to the broker are handled by background
	 * threads.
	 *
	 * RD_KAFKA_MSG_F_COPY is set for async delivery to ensure that the
	 * message persists even after the request is cleaned up.
	 *
	 * key is always copied.
	 *
	 */
	for (attempt = 1; attempt <= RETRIES + 1; attempt++) {
		err = rd_kafka_producev(inst->rk,
					RD_KAFKA_V_RKT(rkt),
					RD_KAFKA_V_MSGFLAGS(async ? RD_KAFKA_MSG_F_COPY : 0),
					RD_KAFKA_V_KEY(key, key_len),
					RD_KAFKA_V_VALUE(message, len),
					RD_KAFKA_V_HEADERS(hdrs),
					RD_KAFKA_V_OPAQUE(async ? NULL : &status),
					RD_KAFKA_V_END
				       );

		if (err != RD_KAFKA_RESP_ERR__QUEUE_FULL) break;

		RERROR("Kafka queue full: %s. Produce attempt %d/%d\n",
		       rd_kafka_err2str(err), attempt, RETRIES + 1);
		rd_kafka_poll(inst->rk, 1000);
	}

	/*
	 *  If rd_kafka_producev() failed then we still own any headers.
	 *
	 */
	if (err != RD_KAFKA_RESP_ERR_NO_ERROR && hdrs)
		rd_kafka_headers_destroy(hdrs);

	/*
	 *  If the delivery is specified as synchronous and we did not
	 *  encounter an immediate error when producing to the queue then
	 *  enforce synchronous behaviour. We do this by polling for changes to
	 *  the stack-allocated err component of the message's opaque made by
	 *  the delivery report callback once the message is durably received
	 *  by brokers.
	 *
	 *  Note: We cannot implement a local timeout here, otherwise we
	 *  invalidate the message's stack-allocated opaque as soon as this
	 *  function exits such that a later callback would write into invalid
	 *  memory! Instead, we rely on the delivery report callback firing
	 *  after the topic's message.timeout.ms.
	 *
	 */
	if (!async && err == RD_KAFKA_RESP_ERR_NO_ERROR) {
		while (status == NO_DELIVERY_REPORT)
			rd_kafka_poll(inst->rk, 1000);	/* Timeout avoids busy waiting */
		err = status;
	}

	if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
		RERROR("Failed to produce to Kafka topic: %s: %s\n",
		       rd_kafka_topic_name(rkt), rd_kafka_err2str(err));
		return -1;
	}

	return 0;

}
#undef NO_DELIVERY_REPORT

static int create_headers(REQUEST *request, const char *in, rd_kafka_headers_t **out)
{
	rd_kafka_headers_t	*hdrs = NULL;
	const char		*p;
	VALUE_PAIR		*header_vps = NULL, *vps, *vp;
	int			num_vps;
	vp_cursor_t		cursor;

	if (!in)
		return 0;

	/*
	 *  Decode the headers string to derive a set of VPs from which to
	 *  create Kafka headers
	 *
	 */
	p = in;

	while (isspace((uint8_t) *p)) p++;
	if (*p == '\0') return -1;

	while (*p) {
		bool		negate = false;
		vp_tmpl_t	*vpt = NULL;
		ssize_t		slen;

		while (isspace((uint8_t) *p)) p++;

		if (*p == '\0') break;

		/* Check if we should be removing attributes */
		if (*p == '!') {
			p++;
			negate = true;
		}

		if (*p == '\0') {
			/* May happen e.g. with '!' on its own at the end */
			REMARKER(in, (p - in), "Missing attribute name");
		error:
			fr_pair_list_free(&header_vps);
			talloc_free(vpt);
			return -1;
		}

		/* Decode next attr template */
		slen = tmpl_afrom_attr_substr(request, &vpt, p, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false);

		if (slen <= 0) {
			REMARKER(in, (p - in) - slen, fr_strerror());
			goto error;
		}

		/*
		 * Get attributes from the template.
		 * Missing attribute isn't an error (so -1, not 0).
		 */
		if (tmpl_copy_vps(request, &vps, request, vpt) < -1) {
			REDEBUG("Error copying attributes");
			goto error;
		}

		if (negate) {
			/* Remove all template attributes from header list */
			for (vp = vps; vp; vp = vp->next)
				fr_pair_delete_by_da(&header_vps, vp->da);

			fr_pair_list_free(&vps);
		} else {
			/* Add template VPs to header list */
			fr_pair_add(&header_vps, vps);
		}

		TALLOC_FREE(vpt);

		/* Jump forward to next attr */
		p += slen;

		if (*p != '\0' && !isspace((uint8_t)*p)) {
			REMARKER(in, (p - in), "Missing whitespace");
			goto error;
		}

	}

	/*
	 *  Create the Kafka headers for the derived VPs
	 *
	 */
	for (vp = header_vps, num_vps = 0; vp; vp = vp->next, num_vps++);
	if (num_vps == 0) return 0;

	hdrs = rd_kafka_headers_new(num_vps);
	for (vp = fr_cursor_init(&cursor, &header_vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		rd_kafka_resp_err_t err;
		const char *attr = vp->da->name;
		char *value;

		value = vp_aprints_value(NULL, vp, '\0');
		err = rd_kafka_header_add(hdrs, attr, -1, value, -1);
		talloc_free(value);
		if (err) {
			rd_kafka_headers_destroy(hdrs);
			return -1;
		}
	}

	*out = hdrs;
	return 0;

}

/*
 *  Format is one of the following:
 *
 *  - "%{kafka:<topic> (<header-list>) &Key-Attr-Ref <message data>}"
 *  - "%{kafka:<topic> (<header-list>)  <message data>}"  (no key => space)
 *  - "%{kafka:<topic> &Key-Attr-Ref <message data>}"
 *  - "%{kafka:<topic>  <message data>}"                  (no key => space)
 *
 */
static ssize_t kafka_xlat(void *instance, REQUEST *request, char const *fmt, char *out, UNUSED size_t outlen)
{
	rlm_kafka_t		*inst = instance;
	char const		*p = fmt, *q;
	ssize_t			key_len = 0;
	char			*expanded = NULL;
	char			*headers = NULL;
	char 			buf[256];
	rlm_kafka_rkt_by_name_t	*entry, my_topic;
	rd_kafka_headers_t	*hdrs = NULL;

	union {
		const uint8_t *key_const;
		char* const key_unconst;
	} k;
	k.key_const = NULL;

	*out = '\0';

	/*
	 *  Extract and lookup the topic.
	 *
	 */
	p = strchr(fmt, ' ');
        if (!p || *fmt == ' ' || *(p+1) == '\0') {
		REDEBUG("Kafka xlat must begin with a topic, optionally followed by headers, then the payload");
error:
		talloc_free(expanded);
		if (hdrs) rd_kafka_headers_destroy(hdrs);
		return -1;
	}
	if ((size_t)(p - fmt) >= sizeof(buf)) {
		REDEBUG("Insufficient space to store Kafka topic name, needed %zu bytes, have %zu bytes",
			(p - fmt) + 1, sizeof(buf));
		goto error;
	}
	strlcpy(buf, fmt, (p - fmt) + 1);
	p++;

	my_topic.name = buf;
	entry = rbtree_finddata(inst->rkt_by_name_tree, &my_topic);
	if (!entry || !entry->rkt) {
		RWARN("No configuration section exists for kafka topic \"%s\"", buf);
		goto error;
	}

	/*
	 *  Extract the header specification, and generate the headers
	 *
	 */
	q = p;
	if (*p == '(') {
		p = strchr(p, ')');
		if (!p) {
			REDEBUG("Header list is missing closing parenthesis)");
			goto error;
		}
		MEM(headers = talloc_strndup(NULL, q + 1, p - q - 1));
		if (*headers && create_headers(request, headers, &hdrs) < 0) {
			REDEBUG("Failed to create headers");
			talloc_free(headers);
			goto error;
		}
		talloc_free(headers);
		p++;
		if (*p != ' ') {
			REDEBUG("Kafka xlat must begin with a topic, optionally followed by headers, then the payload");
			goto error;
		}
		p++;
	}

	/*
	 *  Extract the key, if there is one, otherwise expect a space.
	 *
	 */
	q = p;
	if (*p == '&') {
		p = strchr(p, ' ');
		if (!p) {
			REDEBUG("Key attribute form requires a message after the key (... &Key-Attr-Ref <message data>)");
			goto error;
		}

		if ((size_t)(p - q) >= sizeof(buf)) {
			REDEBUG("Insufficient space to store key attribute ref, needed %zu bytes, have %zu bytes",
			        (p - q) + 1, sizeof(buf));
			goto error;
		}
		strlcpy(buf, q, (p - q) + 1);

		key_len = xlat_fmt_to_ref(&k.key_const, request, buf);
		if (key_len < 0) goto error;

		RDEBUG3("message key=%.*s\n", (int)key_len, k.key_const);
	} else if (*p != ' ') {
		/*
		 * Require a space to disambiguate data starting with "&"
		 *
		 */
		REDEBUG("Kafka payload must begin with an attribute reference or a space");
		goto error;
	}

	p++;

	/*
	 *  The remainder is the message.
	 *
	 */
	if (radius_axlat(&expanded, request, p, NULL, NULL) < 0) {
		REDEBUG("Message expansion failed");
		goto error;
	}

	kafka_produce(inst, request, entry->rkt, k.key_unconst, key_len,
		      expanded, strlen(expanded), hdrs, inst->async);

	talloc_free(expanded);

	return 0;
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_kafka_t *inst = instance;

	inst->name = cf_section_name2(conf);
	if (!inst->name) {
		inst->name = cf_section_name1(conf);
	}

	xlat_register(inst->name, kafka_xlat, NULL, inst);

	return 0;
}

static int rkt_by_name_cmp(void const *one, void const *two)
{
	rlm_kafka_rkt_by_name_t const *a = (rlm_kafka_rkt_by_name_t const *) one;
	rlm_kafka_rkt_by_name_t const *b = (rlm_kafka_rkt_by_name_t const *) two;

	return strcmp(a->name, b->name);
}

static int destruct_entry(rlm_kafka_rkt_by_name_t *entry) {
	/*
	 *  Destroy rkt only if we are the owner (not a reference)
	 *
	 */
	if (!entry->ref && entry->rkt)
		rd_kafka_topic_destroy(entry->rkt);
	entry->rkt = NULL;
	return 0;
}

static void free_rkt_by_name_entry(void *data)
{
	rlm_kafka_rkt_by_name_t *entry = (rlm_kafka_rkt_by_name_t *) data;
	talloc_free(entry);
}

static int instantiate_topic(CONF_SECTION *cs, rlm_kafka_t *inst, char *errstr) {

	CONF_PAIR		*cp;
	rd_kafka_topic_conf_t	*tconf;
	rd_kafka_topic_t	*rkt;
	bool			ref = false;
	rlm_kafka_rkt_by_name_t	*entry = NULL;
	const char		*name = cf_section_name2(cs);

	/*
	 *  Short circuit for when we are given a reference to an existing topic
	 *
	 */
	cp = cf_pair_find_next(cs, NULL, NULL);
	if (cp) {
		char const *attr = cf_pair_attr(cp);
		char const *value = cf_pair_value(cp);

		if (strcmp(attr, "reference") == 0) {
			rlm_kafka_rkt_by_name_t my_topic;

			my_topic.name = value;
			entry = rbtree_finddata(inst->rkt_by_name_tree, &my_topic);
			if (!entry || !entry->rkt) {
				ERROR("Couldn't reference Kafka topic \"%s\" for \"%s\"",
				      value, cf_section_name2(cs));
				return -1;
			}
			if (cf_pair_find_next(cs, cp, NULL)) {
				ERROR("A reference for another Kafka topic must be the only attribute");
				return -1;
			}
			DEBUG3("Kafka topic \"%s\" configured as a reference to \"%s\"",
			       cf_section_name2(cs), value);
			rkt = entry->rkt;
			ref = true;
			goto finalise;
		}
	}

	/*
	 *  Configuration for the new topic
	 *
	 */
	tconf = rd_kafka_topic_conf_new();

	/*
	 *  When synchronous, don't block for longer than a typical request timeout.
	 *
	 *  Can be overridden by message.timeout.ms in the topic conf_section
	 */
	if (!inst->async)
		RLM_KAFKA_TOPIC_PROP_SET(tconf, "message.timeout.ms", "30000", errstr);

	/*
	 *  Set topic properties from the topic conf_section
	 */
	cp = NULL;
	do {

		cp = cf_pair_find_next(cs, cp, NULL);
		if (cp) {
			char const *attr = cf_pair_attr(cp);
			char const *value = cf_pair_value(cp);
			if (strcmp(attr, "name") == 0) {  /* Override section name */
				name = value;
				continue;
			} else if (strcmp(attr, "reference") == 0) {
				ERROR("A reference for another Kafka topic must be the only attribute");
				rd_kafka_topic_conf_destroy(tconf);
				return -1;
			}
			RLM_KAFKA_TOPIC_PROP_SET(tconf, attr, value, errstr);
		}
	} while (cp != NULL);

	/*
	 *  Show the topic configurations for debugging
	 */
	if (rad_debug_lvl >= L_DBG_LVL_3) {
		size_t		cnt, i;
		const char	**arr;

		DEBUG3("Configuration for Kafka topic \"%s\":", name);
		for (i = 0, arr = rd_kafka_topic_conf_dump(tconf, &cnt); i < cnt; i += 2)
			DEBUG3("\t%s = %s", arr[i], arr[i + 1]);
	}

	/*
	 *  And create the topic according to the configuration.
	 *
	 *  Upon success, the rkt assumes responsibility for tconf
	 *
	 */
	rkt = rd_kafka_topic_new(inst->rk, name, tconf);
	if (!rkt) {
		ERROR("Failed to create Kafka topic \"%s\"", name);
		rd_kafka_topic_conf_destroy(tconf);
		return -1;
	}

finalise:

	/*
	 *  Finally insert the entry into the rbtree.
	 *
	 */
	entry = talloc(NULL, rlm_kafka_rkt_by_name_t);
	if (!entry)
		return -1;
	talloc_set_destructor(entry, destruct_entry);
	entry->name = talloc_strdup(entry, cf_section_name2(cs));
	if (!entry->name) {
	fail:
		talloc_free(entry);
		return -1;
	}
	entry->rkt = rkt;
	entry->ref = ref;

	if (!rbtree_insert(inst->rkt_by_name_tree, entry))
		goto fail;

	DEBUG("Created Kafka topic for \"%s\"", name);

	return 0;

}

static inline void set_section_rkt(rlm_kafka_t *inst, rlm_kafka_section_config_t *section)
{
	rlm_kafka_rkt_by_name_t	*entry, my_topic;

	my_topic.name = cf_section_name1(section->cs);
	entry = rbtree_finddata(inst->rkt_by_name_tree, &my_topic);
	section->rkt = entry && entry->rkt ? entry->rkt : NULL;
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_kafka_t		*inst = instance;
	rd_kafka_conf_t		*kconf;
	char			errstr[512];
	CONF_PAIR		*cp = NULL;
	CONF_SECTION		*cs;

	/*
	 *  Configuration for the global producer
	 */
	kconf = rd_kafka_conf_new();

	rd_kafka_conf_set_opaque(kconf, inst);

	DEBUG3("Registering Kafka logging callback");
	rd_kafka_conf_set_log_cb(kconf, log_cb);

	DEBUG3("Registering Kafka delivery report callback");
	rd_kafka_conf_set_dr_msg_cb(kconf, dr_msg_cb);

	if (inst->stats_filename) {
		DEBUG3("Opening Kafka statistics file for writing: %s", inst->stats_filename);
		inst->stats_file = fopen(inst->stats_filename, "a");
		if (!inst->stats_file) {
			ERROR("Error opening Kafka statistics file: %s", inst->stats_filename);
			/* Carry on, just don't log stats */
		} else {
			DEBUG3("Registering Kafka statistics callback");
			rd_kafka_conf_set_stats_cb(kconf, stats_cb);
		}
	}

	RLM_KAFKA_PROP_SET(kconf, "bootstrap.servers", inst->bootstrap, errstr);

	/*
	 *  Set global properties from the global conf_section
	 */
	do {
		CONF_SECTION	*gc = cf_section_sub_find(conf, "global-config");

		cp = cf_pair_find_next(gc, cp, NULL);
		if (cp) {
			char const *attr, *value;
			attr = cf_pair_attr(cp);
			value = cf_pair_value(cp);
			RLM_KAFKA_PROP_SET(kconf, attr, value, errstr);
		}
	} while (cp != NULL);

	/*
	 *  When configured to send synchronously, avoid plugging the requests
	 *  since we are not batching and desire immediate responses.
	 *
	 *  Overrides and linger.ms that is set in the global conf_section.
	 */
	if (!inst->async)
		RLM_KAFKA_PROP_SET(kconf, "linger.ms", "0", errstr);

	/*
	 *  Show the global configuration for debugging
	 */
	if (rad_debug_lvl >= L_DBG_LVL_3) {
		size_t		cnt, i;
		const char	**arr;

		DEBUG3("Kafka global configuration:");
		for (i = 0, arr = rd_kafka_conf_dump(kconf, &cnt); i < cnt; i += 2)
			DEBUG3("\t%s = %s", arr[i], arr[i + 1]);
	}

	/*
	 *  And create the producer according to the configuration, which sets
	 *  up a separate handler ("rdk:main") thread and a set of
	 *  "rdk:brokerN" threads, one per broker.
	 *
	 *  librdkafka attempts a lot of blunt (unconfigurable), global
	 *  initialisation of dependent libraries here:
	 *
	 *    - cJSON library has it's allocation functions overridden, but
	 *      just to wrappers around malloc / realloc / free, etc. so this
	 *      is harmless.
	 *    - An attempt is made to initialise cURL, however the cURL library
	 *      maintains a reference count that prevents duplicate
	 *      reinitialisation.
	 *    - Cyrus SASL is similarly reference counted.
	 *    - For OpenSSL < 1.1.0 there is an attempted reinitialisation that
	 *      would clobber settings so at build time we enforce a minimum
	 *      version that no longer requires global initialisation.
	 *
	 *  There may still be unknown cases where other module's configuration
	 *  is trampled on, so best to test overall server functionality
	 *  carefully when enabling this module.
	 *
	 */
	inst->rk = rd_kafka_new(RD_KAFKA_PRODUCER, kconf, errstr, sizeof(errstr));
	if (!inst->rk) {
		ERROR("Failed to create new Kafka producer: %s\n", errstr);
		rd_kafka_conf_destroy(kconf);
		return -1;
	}

	/*
	 *  Instantiate a topic for each named topic-config section
	 *
	 */
	inst->rkt_by_name_tree = rbtree_create(instance, rkt_by_name_cmp, free_rkt_by_name_entry, 0);
	if (!inst->rkt_by_name_tree) return -1;

	for (cs = cf_subsection_find_next(conf, NULL, "topic-config");
		cs != NULL;
		cs = cf_subsection_find_next(conf, cs, "topic-config")) {

		if (!cf_section_name2(cs)) {
			WARN("Ignoring unnamed Kafka topic-config");
			continue;
		}

		if (instantiate_topic(cs, inst, errstr) != 0) {
			ERROR("Failed to instantiate new Kafka topic for %s\n",
			      cf_section_name2(cs));
			rbtree_free(inst->rkt_by_name_tree);
			rd_kafka_destroy(inst->rk);
			return -1;
		}

	}

	/*
	 *  Capture a self-reference for the sections
	 */
	inst->authorize.cs = cf_section_sub_find(conf, "authorize");
	inst->postauth.cs = cf_section_sub_find(conf, "post-auth");
	inst->accounting.cs = cf_section_sub_find(conf, "accounting");

	/*
	 *  Set the rkt for each section, where such configuration exists
	 */
	set_section_rkt(inst, &inst->authorize);
	set_section_rkt(inst, &inst->postauth);
	set_section_rkt(inst, &inst->accounting);

	return 0;
}

static int mod_detach(UNUSED void *instance)
{
	rd_kafka_resp_err_t	err;
	rlm_kafka_t		*inst = instance;

	if (inst->stats_file) {
		DEBUG3("Closing Kafka statistics file");
		fclose(inst->stats_file);
	}

	DEBUG3("Flushing Kafka queues");
	if ((err = rd_kafka_flush(inst->rk, 10*1000)) == RD_KAFKA_RESP_ERR__TIMED_OUT)
		ERROR("Flush failed: %s\n", rd_kafka_err2str(err));

	rbtree_free(inst->rkt_by_name_tree);

	rd_kafka_destroy(inst->rk);

	return 0;
}

/*
 *      Common code called by everything below.
 */
static rlm_rcode_t CC_HINT(nonnull) kafka_common(void *instance, REQUEST *request, rlm_kafka_section_config_t *section)
{

	rlm_kafka_t		*inst = instance;
	char			*key = NULL;
	char			*message = NULL;
	rd_kafka_headers_t	*hdrs = NULL;
	CONF_ITEM		*item;
	CONF_PAIR		*cp;
	const char		*schema;
	rlm_rcode_t		ret = RLM_MODULE_OK;
	char			path[MAX_STRING_LEN];
	char			*p = path;

	if (!section->rkt) {
		RWARN("No configuration exists for Kafka topic for %s section",
			cf_section_name1(section->cs));
		return RLM_MODULE_NOOP;
	}

	if (section->reference[0] != '.') {
		*p++ = '.';
	}

	if (radius_xlat(p, sizeof(path) - (p - path), request, section->reference, NULL, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	item = cf_reference_item(NULL, section->cs, path);
	if (!item) {
		RDEBUG3("No such configuration item %s", path);
		return RLM_MODULE_NOOP;
	}
	if (cf_item_is_section(item)) {
		RDEBUG3("Sections are not supported as references");
		return RLM_MODULE_NOOP;
	}

	cp = cf_item_to_pair(item);
	schema = cf_pair_value(cp);

	if (radius_axlat(&message, request, schema, NULL, NULL) < 0) {
		REDEBUG("Failed to expand message schema");
		return RLM_MODULE_FAIL;
	}

	if (section->key) {
		if (radius_axlat(&key, request, section->key, NULL, NULL) < 0) {
			REDEBUG("Failed to expand key");
			talloc_free(message);
			return RLM_MODULE_FAIL;
		}
	}

	if (section->headers) {
		if (create_headers(request, section->headers, &hdrs) < 0) {
			REDEBUG("Failed to create headers");
			talloc_free(message);
			return RLM_MODULE_FAIL;
		}
	}

	if (kafka_produce(inst, request, section->rkt,
			  key, key ? strlen(key) : 0,
			  message, strlen(message),
			  hdrs, inst->async
			 ) != 0)
		ret = RLM_MODULE_FAIL;

	talloc_free(key);
	talloc_free(message);

	return ret;
}

static inline rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	if (!((rlm_kafka_t*)instance)->authorize.cs)
		return RLM_MODULE_NOOP;

	return kafka_common(instance, request, &((rlm_kafka_t*)instance)->authorize);
}

static inline rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	if (!((rlm_kafka_t*)instance)->postauth.cs)
		return RLM_MODULE_NOOP;

	return kafka_common(instance, request, &((rlm_kafka_t*)instance)->postauth);
}

#ifdef WITH_ACCOUNTING
static inline rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	if (!((rlm_kafka_t*)instance)->accounting.cs)
		return RLM_MODULE_NOOP;

	return kafka_common(instance, request, &((rlm_kafka_t*)instance)->accounting);
}
#endif


/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_kafka;
module_t rlm_kafka = {
	.magic		= RLM_MODULE_INIT,
	.name		= "kafka",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_kafka_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods	= {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_POST_AUTH]		= mod_post_auth,
#ifdef WITH_ACCOUNTING
		[MOD_ACCOUNTING]	= mod_accounting,
#endif
	},
};
