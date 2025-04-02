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

#define LOG_PREFIX "rlm_kafka"

#define RLM_KAFKA_PROP_SET(CONF, PROP, VALUE, BUF_ERRSTR) 								\
	do {														\
		if (rd_kafka_conf_set(CONF, PROP, VALUE, BUF_ERRSTR, sizeof(BUF_ERRSTR)) != RD_KAFKA_CONF_OK )		\
			ERROR("Error setting global property: '%s=%s' : %s\n", PROP, VALUE, BUF_ERRSTR);		\
	} while (0)

#define RLM_KAFKA_TOPIC_PROP_SET(CONF, PROP, VALUE, BUF_ERRSTR)								\
	do {														\
		if (rd_kafka_topic_conf_set(CONF, PROP, VALUE, BUF_ERRSTR, sizeof(BUF_ERRSTR)) != RD_KAFKA_CONF_OK )	\
			ERROR("Error setting topic property: '%s=%s' : %s\n", PROP, VALUE, BUF_ERRSTR);			\
	} while (0)

typedef struct rlm_kafka_section_config {
	CONF_SECTION *cs;
	char const *reference;
	char const *key;
} rlm_kafka_section_config_t;

typedef struct rlm_kafka_t {

	char const *name;

	bool async;

	char const *bootstrap;
	char const *topic;
	char const *schema;

	char const *stats_filename;
	FILE *stats_file;

	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;

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
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER postauth_config[] = {
	{ "reference", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, postauth.reference), ".message" },
	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, postauth.key), NULL},
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER accounting_config[] = {
	{ "reference", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, accounting.reference), ".message" },
	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT, rlm_kafka_t, accounting.key), NULL},
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
	{ "topic", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_kafka_t, topic), NULL },
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
			 const bool async) {

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
					RD_KAFKA_V_OPAQUE(async ? NULL : &status),
					RD_KAFKA_V_END
				       );

		if (err != RD_KAFKA_RESP_ERR__QUEUE_FULL) break;

		RERROR("Queue full: %s. Produce attempt %d/%d\n", rd_kafka_err2str(err), attempt, RETRIES + 1);
		rd_kafka_poll(inst->rk, 1000);
	}

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
		RERROR("Failed to produce to topic: %s: %s\n", inst->topic, rd_kafka_err2str(err));
		return -1;
	}

	return 0;

}
#undef NO_DELIVERY_REPORT

/*
 *  Either "%{kafka:&Key-Attr-Ref <message data>}" or "%{kafka:<space><message data>}"
 *
 */
static ssize_t kafka_xlat(void *instance, REQUEST *request, char const *fmt, char *out, UNUSED size_t outlen)
{
	rlm_kafka_t	*inst = instance;
	char const	*p = fmt;
	uint8_t const	*key;
	ssize_t		key_len = 0;
	char		*expanded = NULL;

	union {
		const uint8_t *key_const;
		char* const key_unconst;
	} k;
	key = k.key_const = NULL;

	*out = '\0';

	if (*p == '&') {
		char	key_ref[256];

		p = strchr(fmt, ' ');
		if (!p) {
			REDEBUG("Key attribute form requires a message after the key (&Key-Attr-Ref <message data>)");
			return -1;
		}

		if ((size_t)(p - fmt) >= sizeof(key_ref)) {
			REDEBUG("Insufficient space to store key attribute ref, needed %zu bytes, have %zu bytes",
			        (p - fmt) + 1, sizeof(key_ref));
			return -1;
		}
		strlcpy(key_ref, fmt, (p - fmt) + 1);

		key_len = xlat_fmt_to_ref(&key, request, key_ref);
		if (key_len < 0) return -1;

		RDEBUG3("message key=%.*s\n", (int)key_len, key);
	} else if (*p != ' ') {
		/*
		 * Require a space to disambiguate data starting with "&"
		 *
		 */
		REDEBUG("Must begin with an attribute reference or a space");
		return -1;
	}

	p++;

	if (radius_axlat(&expanded, request, p, NULL, NULL) < 0) {
		REDEBUG("Message expansion failed");
		return -1;
	}

	kafka_produce(inst, request, inst->rkt, k.key_unconst, key_len, expanded, strlen(expanded), inst->async);

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

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_kafka_t		*inst = instance;
	rd_kafka_conf_t		*kconf;
	rd_kafka_topic_conf_t	*tconf;
	char			errstr[512];
	CONF_PAIR		*cp = NULL;

	/*
	 *  Capture a self-reference for the sections
	 */
	inst->authorize.cs = cf_section_sub_find(conf, "authorize");
	inst->postauth.cs = cf_section_sub_find(conf, "post-auth");
	inst->accounting.cs = cf_section_sub_find(conf, "accounting");

	/*
	 *  Configuration for the global producer
	 */
	kconf = rd_kafka_conf_new();

	rd_kafka_conf_set_opaque(kconf, inst);

	DEBUG3("Registering logging callback");
	rd_kafka_conf_set_log_cb(kconf, log_cb);

	DEBUG3("Registering delivery report callback");
	rd_kafka_conf_set_dr_msg_cb(kconf, dr_msg_cb);

	if (inst->stats_filename) {
		DEBUG3("Opening statistics file for writing: %s", inst->stats_filename);
		inst->stats_file = fopen(inst->stats_filename, "a");
		if (!inst->stats_file) {
			ERROR("Error opening statistics file: %s", inst->stats_filename);
			/* Carry on, just don't log stats */
		} else {
			DEBUG3("Registering statistics callback");
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
		ERROR("Failed to create new producer: %s\n", errstr);
		rd_kafka_conf_destroy(kconf);
		return -1;
	}

	/*
	 *  Configuration for the topic
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
	do {
		CONF_SECTION	*tc = cf_section_sub_find(conf, "topic-config");

		cp = cf_pair_find_next(tc, cp, NULL);
		if (cp) {
			char const *attr = cf_pair_attr(cp);
			char const *value = cf_pair_value(cp);
			RLM_KAFKA_TOPIC_PROP_SET(tconf, attr, value, errstr);
		}
	} while (cp != NULL);

	/*
	 *  Show the topic configurations for debugging
	 */
	if (rad_debug_lvl >= L_DBG_LVL_3) {
		size_t		cnt, i;
		const char	**arr;

		DEBUG3("Topic configuration:");
		for (i = 0, arr = rd_kafka_topic_conf_dump(tconf, &cnt); i < cnt; i += 2)
			DEBUG3("\t%s = %s", arr[i], arr[i + 1]);
	}

	/*
	 *  And create the topic according to the configuration
	 */
	inst->rkt = rd_kafka_topic_new(inst->rk, inst->topic, tconf);
	if (!inst->rkt) {
		ERROR("Failed to create new topic: %s\n", errstr);
		rd_kafka_topic_conf_destroy(tconf);
		rd_kafka_destroy(inst->rk);
		return -1;
	}

	return 0;
}

static int mod_detach(UNUSED void *instance)
{
	rd_kafka_resp_err_t err;
	rlm_kafka_t *inst = instance;

	if (inst->stats_file) {
		DEBUG3("Closing statistics file");
		fclose(inst->stats_file);
	}

	DEBUG3("Flushing");
	if ((err = rd_kafka_flush(inst->rk, 10*1000)) == RD_KAFKA_RESP_ERR__TIMED_OUT)
		ERROR("Flush failed: %s\n", rd_kafka_err2str(err));

	rd_kafka_topic_destroy(inst->rkt);
	rd_kafka_destroy(inst->rk);

	return 0;
}

/*
 *      Common code called by everything below.
 */
static rlm_rcode_t CC_HINT(nonnull) kafka_common(void *instance, REQUEST *request, rlm_kafka_section_config_t *section)
{

	rlm_kafka_t	*inst = instance;
	char		*key = NULL;
	char		*message = NULL;
	CONF_ITEM	*item;
	CONF_PAIR	*cp;
	const char	*schema;
	rlm_rcode_t	ret = RLM_MODULE_OK;
	char		path[MAX_STRING_LEN];
	char		*p = path;

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
		RDEBUG3("Failed to expand message schema");
		return RLM_MODULE_FAIL;
	}

	if (radius_axlat(&key, request, section->key, NULL, NULL) < 0) {
		RDEBUG3("Failed to expand key");
		talloc_free(message);
		return RLM_MODULE_FAIL;
	}

	if (kafka_produce(inst, request, inst->rkt,
			  key, strlen(key), message, strlen(message),
			  inst->async
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
