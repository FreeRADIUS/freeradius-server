/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @brief Asynchronous Kafka producer module.
 *
 * A single shared `rd_kafka_t` serves every worker in the module
 * instance.  Delivery reports are fanned out to the originating worker
 * via librdkafka's own background thread: at `mod_instantiate` we set
 * `rd_kafka_conf_set_background_event_cb` and forward the producer's
 * main queue to the background queue, so DRs arrive at our bg cb
 * (`_kafka_background_event_cb`).  The cb pushes each DR's opaque onto
 * the originating worker's `fr_atomic_ring_t` mailbox and triggers its
 * `EVFILT_USER` wake event; the worker's event loop drains the mailbox
 * on its own stack and marks the request runnable itself - resumption
 * never crosses threads.
 *
 * pctx is `malloc`'d, not talloc'd, so the bg thread can free it
 * directly without racing worker-thread talloc.  `pctx->request` is
 * atomic and is NULLed by the cancel signal handler on the worker;
 * by the time `mod_thread_detach` runs the framework has already
 * cancelled every yielded request this worker owned, so the bg cb
 * sees NULL and frees inline without touching the (about-to-be-freed)
 * thread_inst.
 *
 * The schema for the module config is just @ref kafka_base_producer_config
 * from the kafka base library (librdkafka passthrough plus
 * `flush_timeout`), with `fr_kafka_conf_t` embedded as the first member
 * of @ref rlm_kafka_t so `FR_CONF_OFFSET` entries resolve correctly.
 * Topics are declared once in the module config and referenced by name at
 * method/xlat invocation time; unknown topics are rejected at config-parse
 * time rather than being created on the fly, so per-topic settings (acks,
 * compression, partitioner) always match the declared configuration.
 *
 * See @ref mod_produce and @ref kafka_xlat_produce for the caller-facing
 * surfaces.
 *
 * @copyright 2022,2026 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/value.h>

#include <freeradius-devel/io/atomic_queue.h>
#include <freeradius-devel/kafka/base.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>

#include <freeradius-devel/unlang/call_env.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/xlat_ctx.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/xlat_priv.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>

/** Module instance data
 *
 * `fr_kafka_conf_t` is embedded as the first member so
 * `KAFKA_BASE_CONFIG` / `KAFKA_PRODUCER_CONFIG` `FR_CONF_OFFSET`
 * entries (relative to `fr_kafka_conf_t`) address correctly when the
 * framework passes `rlm_kafka_t` as the parse base.  The librdkafka
 * handle and per-topic tree inside `kconf` are released automatically
 * by talloc when the module instance is torn down (the library attaches
 * a lifecycle sentinel during config parse).
 */
typedef struct {
	fr_kafka_conf_t			kconf;		//!< parsed producer conf - MUST be first
	fr_time_delta_t			flush_timeout;	//!< How long `mod_detach` waits for in-flight
							//!< produces to drain before `rd_kafka_destroy`.
	char const			*log_prefix;	//!< pre-rendered `"rlm_kafka (<instance>)"`, used by
							//!< librdkafka's log_cb which fires from internal
							//!< threads with no mctx in scope.  Built once in
							//!< mod_instantiate so we don't reformat per line.

	rd_kafka_t			*rk;		//!< shared producer, created at mod_instantiate.
	fr_rb_tree_t			*topics;	//!< rlm_kafka_topic_t keyed by name, read-only
							//!< after mod_instantiate.
} rlm_kafka_t;

/** Topic handle
 *
 * One per declared topic, created at mod_instantiate.  `rd_kafka_topic_t`
 * is bound to the producer that created it; we have one shared producer
 * per module instance so the topic handles are inst-scoped.
 */
typedef struct {
	char const		*name;
	rd_kafka_topic_t	*kt;
	fr_rb_node_t		node;
} rlm_kafka_topic_t;

typedef struct rlm_kafka_thread_s {
	fr_event_list_t		*el;

	fr_event_user_t		*wake;		//!< EVFILT_USER handle; bg cb triggers it to wake the
						//!< worker's event loop on this thread.

	fr_atomic_ring_t	*queue;		//!< rlm_kafka_msg_ctx_t pushed by bg cb on librdkafka's
						//!< thread, popped by our event loop on this worker.
						//!< Segmented SPSC ring: grows on demand, so the bg cb
						//!< never has to drop a delivery report.

#ifndef NDEBUG
	pthread_t		worker_tid;	//!< pthread_self() captured at thread_instantiate.
						//!< Debug-build sanity check: the bg cb must NOT run on
						//!< this thread, and the mailbox drain must.
#endif
} rlm_kafka_thread_t;

/** Per produce() invocation context
 *
 * Raw `malloc`'d (not talloc) so the background dispatch thread can
 * `free()` it directly without racing worker-thread talloc activity.
 * `request` is atomic because the cancel signal handler (worker) and
 * bg cb (librdkafka's own thread) access it from different threads.
 * Reused as the rctx for both module-method and xlat invocations so
 * we don't need a separate wrapper.
 */
typedef struct {
	_Atomic(request_t *)	request;	//!< NULL once cancelled; bg cb / mailbox drain frees
						//!< when NULL, resume path frees on success.
	rlm_kafka_thread_t	*target;	//!< worker's thread_inst; bg cb pushes to its mailbox
						//!< and writes its wake pipe.
	rd_kafka_resp_err_t	err;		//!< stashed by bg cb for resume
	int32_t			partition;
	int64_t			offset;
} rlm_kafka_msg_ctx_t;

/** Call env for `kafka.produce.<topic>`
 *
 * Topic comes from the method's second identifier and is validated
 * against the declared-topic list at call_env parse time, then stashed
 * here as a plain name string.
 */
typedef struct {
	char const		*topic;	//!< resolved topic name (validated at parse time)
	fr_value_box_t		*key;	//!< optional message key
	fr_value_box_t		*value;	//!< message payload
} rlm_kafka_env_t;

/** Module config: just the kafka base producer config for now
 *
 * Kept as a local array rather than pointing `common.config` directly
 * at `KAFKA_BASE_PRODUCER_CONFIG` so we can drop in rlm_kafka-specific
 * entries (or additional librdkafka properties) alongside it later
 * without touching the library.
 */
static conf_parser_t const module_config[] = {
	KAFKA_BASE_CONFIG,
	KAFKA_PRODUCER_CONFIG,

	/*
	 *	How long `mod_detach` waits for the shared producer's
	 *	outstanding produces to drain before `rd_kafka_destroy`.
	 *	Module-level (not a librdkafka property) so we own the
	 *	CONF_PARSER entry rather than the kafka base library.
	 */
	{ FR_CONF_OFFSET("flush_timeout", rlm_kafka_t, flush_timeout), .dflt = "5s" },

	CONF_PARSER_TERMINATOR
};

/** @param[in] a  rlm_kafka_topic_t
 *  @param[in] b  same.
 *  @return `strcmp` ordering of `a->name` and `b->name`. */
static int8_t topic_name_cmp(void const *a, void const *b)
{
	rlm_kafka_topic_t const *ta = a;
	rlm_kafka_topic_t const *tb = b;
	return CMP(strcmp(ta->name, tb->name), 0);
}

/** Look up a shared topic handle on the module instance by name
 *
 * @param[in] inst module instance.
 * @param[in] name topic name (must have been declared at config time).
 * @return `rd_kafka_topic_t` if found, `NULL` otherwise.
 */
static inline CC_HINT(always_inline)
rd_kafka_topic_t *kafka_find_topic(rlm_kafka_t const *inst, char const *name)
{
	rlm_kafka_topic_t	key = { .name = name };
	rlm_kafka_topic_t	*h;

	if (!inst->topics) return NULL;

	h = fr_rb_find(inst->topics, &key);
	return h ? h->kt : NULL;
}

/** librdkafka log callback - bridge internal library messages into the server log
 *
 * Called from librdkafka's internal threads (no request context, no mctx in
 * scope), so we pull the pre-rendered log prefix off the producer's opaque
 * pointer (the `rlm_kafka_t` we attached at mod_instantiate).
 * Which librdkafka categories are actually emitted is controlled by the
 * top-level `debug` config knob.
 *
 * @param[in] rk    producer handle.  `rd_kafka_opaque(rk)` is the
 *                  `rlm_kafka_t` set during mod_instantiate.
 * @param[in] level syslog-style severity (0 emerg .. 7 debug).
 * @param[in] fac   librdkafka facility / category, e.g. `BROKER`, `MSG`.
 * @param[in] buf   pre-formatted message body.
 */
static void _kafka_log_cb(rd_kafka_t const *rk, int level, char const *fac, char const *buf)
{
	rlm_kafka_t	*inst = talloc_get_type_abort(rd_kafka_opaque(rk), rlm_kafka_t);

	switch (level) {
	case 0:		/* LOG_EMERG   */
	case 1:		/* LOG_ALERT   */
	case 2:		/* LOG_CRIT    */
	case 3:		/* LOG_ERR     */
		ERROR("%s - %s - %s", inst->log_prefix, fac, buf);
		break;

	case 4:		/* LOG_WARNING */
		WARN("%s - %s - %s", inst->log_prefix, fac, buf);
		break;

	case 5:		/* LOG_NOTICE  */
	case 6:		/* LOG_INFO    */
		INFO("%s - %s - %s", inst->log_prefix, fac, buf);
		break;

	default:	/* LOG_DEBUG and anything else */
		DEBUG("%s - %s - %s", inst->log_prefix, fac, buf);
		break;
	}
}

/** Worker wake-up callback - the bg cb triggered our EVFILT_USER event
 *
 * Pops everything sitting in the mailbox and dispatches each pctx on
 * this worker's stack.
 *
 * @param[in] el	UNUSED.
 * @param[in] uctx	`rlm_kafka_thread_t` pointer.
 */
static void _kafka_wake(UNUSED fr_event_list_t *el, void *uctx)
{
	rlm_kafka_thread_t	*t = talloc_get_type_abort(uctx, rlm_kafka_thread_t);
	rlm_kafka_msg_ctx_t	*pctx;

#ifndef NDEBUG
	fr_assert(pthread_equal(pthread_self(), t->worker_tid) != 0);
#endif

	while (fr_atomic_ring_pop(t->queue, (void **)&pctx)) {
		/* See kafka_delivery_notification() for why relaxed is sufficient here. */
		request_t	*request = atomic_load_explicit(&pctx->request, memory_order_relaxed);

		if (!request) {
			free(pctx);
			continue;
		}
		unlang_interpret_mark_runnable(request);
	}
}

/** Translate a librdkafka delivery-report error into a module rcode
 *
 * @param[in] request  associated request (for logging).
 * @param[in] pctx     produce context with the stashed error.
 * @return an `rlm_rcode_t` summarising the outcome.
 */
static rlm_rcode_t kafka_err_to_rcode(request_t *request, rlm_kafka_msg_ctx_t const *pctx)
{
	switch (pctx->err) {
	case RD_KAFKA_RESP_ERR_NO_ERROR:
		RDEBUG2("Delivered to partition %" PRId32 " offset %" PRId64, pctx->partition, pctx->offset);
		return RLM_MODULE_OK;

	case RD_KAFKA_RESP_ERR__MSG_TIMED_OUT:
	case RD_KAFKA_RESP_ERR__TIMED_OUT:
	case RD_KAFKA_RESP_ERR__TIMED_OUT_QUEUE:
		REDEBUG("Kafka delivery timed out - %s", rd_kafka_err2str(pctx->err));
		return RLM_MODULE_TIMEOUT;

	case RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE:
	case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART:
	case RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED:
	case RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC:
		REDEBUG("Kafka rejected message - %s", rd_kafka_err2str(pctx->err));
		return RLM_MODULE_REJECT;

	default:
		REDEBUG("Kafka delivery failed - %s (%s)",
			rd_kafka_err2name(pctx->err), rd_kafka_err2str(pctx->err));
		return RLM_MODULE_FAIL;
	}
}

/** Common produce-and-yield helper
 *
 * Submits a message to the shared producer and returns the produce
 * context on success.  The caller is responsible for yielding the
 * request with the returned pctx as rctx.  On synchronous failure the
 * pctx is freed and `NULL` is returned.
 *
 * pctx is `malloc`'d (not talloc'd) so the bg cb can `free()` it
 * directly without racing worker-thread talloc.
 *
 * @param[in] t         originating worker's thread_inst.
 * @param[in] request   request to yield on.
 * @param[in] topic     preconfigured inst-scoped topic handle.
 * @param[in] key       optional message key, may be `NULL`.
 * @param[in] key_len   length of `key`, 0 if `key` is `NULL`.
 * @param[in] value     message payload.
 * @param[in] value_len length of `value`.
 * @return the rlm_kafka_msg_ctx_t tracking the request, or `NULL` on failure.
 */
static inline CC_HINT(always_inline)
rlm_kafka_msg_ctx_t *kafka_produce_enqueue(rlm_kafka_thread_t *t, request_t *request,
					   rd_kafka_topic_t *topic,
					   uint8_t const *key, size_t key_len,
					   uint8_t const *value, size_t value_len)
{
	rlm_kafka_msg_ctx_t	*pctx;

	MEM(pctx = malloc(sizeof(*pctx)));
	pctx->target = t;
	pctx->err = RD_KAFKA_RESP_ERR_NO_ERROR;
	pctx->partition = RD_KAFKA_PARTITION_UA;
	pctx->offset = -1;
	atomic_init(&pctx->request, request);

	if (unlikely(rd_kafka_produce(topic, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
				      /* librdkafka copies under MSG_F_COPY */
				      (void *)(uintptr_t) value, value_len,
				      key, key_len,
				      pctx) != 0)) {
		rd_kafka_resp_err_t	err = rd_kafka_last_error();

		free(pctx);

		REDEBUG("Failed enqueuing message - %s", rd_kafka_err2str(err));
		return NULL;
	}

	return pctx;
}

/** Per-topic call_env rules, applied against the `topic <name>` subsection
 *
 * Invoked recursively from @ref _kafka_topic_env_parse via `call_env_parse()`
 * so the framework handles pair lookup / tmpl compilation / offset writes
 * for us.
 *
 * Both `value` and `key` are typed `FR_TYPE_OCTETS`.  Kafka payloads and
 * keys are opaque byte strings on the wire, and casting to octets keeps
 * binary content (embedded NULs, high-bit bytes) intact without any
 * UTF-8/string-termination assumptions creeping in from intermediate
 * tmpl expansion.  It also means an integer-typed `key` attribute is
 * serialised in network byte order, which matches the keying convention
 * other Kafka clients use so the same numeric key hashes to the same
 * partition across producers.
 */
static call_env_parser_t const topic_env[] = {
	{ FR_CALL_ENV_OFFSET("value", FR_TYPE_OCTETS, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT,
			     rlm_kafka_env_t, value) },
	{ FR_CALL_ENV_OFFSET("key", FR_TYPE_OCTETS, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE,
			     rlm_kafka_env_t, key) },
	CALL_ENV_TERMINATOR
};

/** Resolve the topic named in the method's second identifier, then hand its
 *  subsection back to the call_env framework for per-topic `value` / `key`
 *  tmpl parsing.
 *
 * Invocations look like `kafka.produce.<topic_name>`.  We:
 *
 *  1. Validate the topic against the declared-topic tree.  Unknown topics
 *     fail here so typos surface at startup instead of at first produce.
 *  2. Emit a synthetic call_env entry carrying the topic name.
 *  3. Recurse into `call_env_parse()` with @ref topic_env pointed at the
 *     topic's CONF_SECTION - the framework walks `value` and `key` for us.
 *
 * Per-topic `value` and `key` means each declared topic carries its own
 * payload template; operators can publish different shapes to different
 * topics from one module instance.
 */
static int _kafka_topic_env_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out,
				  tmpl_rules_t const *t_rules, CONF_ITEM *ci,
				  call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_kafka_t const	*inst = talloc_get_type_abort_const(cec->mi->data, rlm_kafka_t);
	fr_kafka_topic_t	*topic;
	call_env_parsed_t	*parsed;
	char const		*topic_name = cec->asked->name2;

	if (!topic_name) {
		cf_log_err(ci, "kafka.produce requires a topic name, e.g. kafka.produce.<topic>");
		return -1;
	}

	topic = kafka_topic_conf_find(&inst->kconf, topic_name);
	if (!topic) {
		cf_log_err(ci, "Kafka topic '%s' is not declared in the '%s' module config",
			   topic_name, cec->mi->name);
		return -1;
	}

	/*
	 *	Topic name (plain string).
	 */
	MEM(parsed = call_env_parsed_add(ctx, out,
					 &(call_env_parser_t){
						.name = "topic",
						.flags = CALL_ENV_FLAG_PARSE_ONLY,
						.pair = {
							.parsed = {
								.offset = offsetof(rlm_kafka_env_t, topic),
								.type = CALL_ENV_PARSE_TYPE_VOID
							}
						}
					 }));
	call_env_parsed_set_data(parsed, talloc_strdup(ctx, topic_name));

	/*
	 *	Framework walks `value` / `key` inside the topic subsection
	 *	according to topic_env.
	 */
	return call_env_parse(ctx, out, "kafka", t_rules, topic->cs, cec, topic_env);
}

static const call_env_method_t rlm_kafka_produce_env = {
	FR_CALL_ENV_METHOD_OUT(rlm_kafka_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_SUBSECTION_FUNC(CF_IDENT_ANY, CF_IDENT_ANY,
					      CALL_ENV_FLAG_PARSE_MISSING, _kafka_topic_env_parse) },
		CALL_ENV_TERMINATOR
	}
};

/** Resume a yielded module method after its delivery report has arrived
 *
 * Runs on the same worker as the originating produce (per-thread
 * producer), with `mctx->rctx` being the @ref rlm_kafka_msg_ctx_t the
 * method stashed on yield.  Translates the dr_msg_cb-populated error
 * into an rcode, frees the pctx, and hands control back to unlang.
 *
 * @param[out] p_result where to write the resulting rcode.
 * @param[in] mctx      module ctx carrying the pctx as rctx.
 * @param[in] request   the request being resumed.
 * @return `UNLANG_ACTION_CALCULATE_RESULT` always.
 */
static unlang_action_t mod_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_kafka_msg_ctx_t	*pctx = mctx->rctx;		/* malloc'd, not talloc */
	rlm_rcode_t		rcode = kafka_err_to_rcode(request, pctx);

	free(pctx);
	RETURN_UNLANG_RCODE(rcode);
}

/** Module-method cancellation
 *
 * Do NOT free the pctx - librdkafka still owns the in-flight message and
 * will fire a DR later with our opaque pointer.  Atomic-store NULL to
 * `pctx->request` so the bg cb sees the cancellation when it unpacks
 * the DR and frees the pctx inline without touching the mailbox.
 *
 * Cross-thread: the store is release, matched by the acquire-load in
 * `_kafka_background_event_cb`.
 *
 * @param[in] mctx    module ctx with pctx as rctx.
 * @param[in] request associated request.
 * @param[in] action  UNUSED (we mask off everything except CANCEL).
 */
static void mod_signal(module_ctx_t const *mctx, request_t *request, UNUSED fr_signal_t action)
{
	rlm_kafka_msg_ctx_t	*pctx = mctx->rctx;

	RDEBUG2("Cancellation signal received - detaching delivery report");
	atomic_store_explicit(&pctx->request, NULL, memory_order_release);
}

/** Module method entry point for `kafka.produce.<topic>`
 *
 * The topic is the method's second identifier; `key` and `value` are
 * pulled from the module config via @ref rlm_kafka_produce_env:
 *
 * @code
 *     kafka {
 *         server = "broker1:9092"
 *         topic {
 *             Accounting-Request {
 *	           request_required_acks = -1
 *                 value = %json.encode(&request.[*])
 *                 key   = &User-Name
 *             }
 *         }
 *     }
 *
 *     recv Accounting-Request {
 *         kafka
 *     }
 * @endcode
 *
 * The topic name in `name2` is resolved against the declared-topic
 * tree at config-parse time (see @ref _kafka_topic_env_parse), so
 * typos fail fast.  Different topics reuse the same module instance -
 * e.g. `kafka.produce.auth` and `kafka.produce.accounting` both
 * dispatch through the same per-worker producer handle.
 *
 * Runtime behaviour: looks up the per-thread `rd_kafka_topic_t` by the
 * parse-time-resolved topic declaration, extracts the expanded
 * `key`/value tmpls from the call_env, hands everything to
 * @ref kafka_produce_enqueue, and yields until the delivery report
 * arrives (see @ref kafka_produce_resume for rcode mapping).
 *
 * @param[out] p_result UNUSED (resume writes the real rcode).
 * @param[in] mctx      module ctx (mctx->thread is the rlm_kafka_thread_t,
 *                      mctx->env_data is the rlm_kafka_env_t).
 * @param[in] request   the request being handled.
 * @return yielded on success, UNLANG_ACTION_FAIL if the produce couldn't
 *         even be enqueued.
 */
static unlang_action_t CC_HINT(nonnull) mod_produce(UNUSED unlang_result_t *p_result,
						    module_ctx_t const *mctx, request_t *request)
{
	rlm_kafka_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_kafka_t);
	rlm_kafka_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_kafka_thread_t);
	rlm_kafka_env_t		*env = talloc_get_type_abort(mctx->env_data, rlm_kafka_env_t);
	rd_kafka_topic_t	*topic;
	rlm_kafka_msg_ctx_t	*pctx;

	uint8_t const		*key = NULL;
	size_t			key_len = 0;

	topic = kafka_find_topic(inst, env->topic);
	if (unlikely(!topic)) {
		/*
		 *	Can't happen if parsing succeeded, but defensive.
		 */
		REDEBUG("Kafka topic '%s' has no handle on this module instance", env->topic);
		RETURN_UNLANG_FAIL;
	}

	if (env->key) {
		key = env->key->vb_octets;
		key_len = env->key->vb_length;
	}

	pctx = kafka_produce_enqueue(t, request, topic,
				     key, key_len,
				     env->value->vb_octets, env->value->vb_length);
	if (unlikely(!pctx)) RETURN_UNLANG_FAIL;

	return unlang_module_yield(request, mod_resume, mod_signal,
				   ~FR_SIGNAL_CANCEL, pctx);
}

/** Xlat instance data - cached topic handle for literal-topic calls
 *
 * Topics are inst-scoped (shared producer), so the lookup can be
 * resolved once at xlat_instantiate and the `rd_kafka_topic_t *`
 * cached directly - no per-thread hop needed.
 */
typedef struct {
	rd_kafka_topic_t	*topic;		//!< pre-resolved handle, NULL if topic arg is dynamic.
} rlm_kafka_xlat_inst_t;

/** Xlat instance init: if the topic arg is a compile-time literal, resolve
 *  and cache the inst-scoped `rd_kafka_topic_t` handle.
 *
 * Runs after `mod_instantiate` has created the shared producer and all
 * topic handles, so the lookup is an rbtree walk against `inst->topics`.
 * Dynamic topic args (attribute refs, nested xlats) are left to the
 * per-call lookup in the xlat runtime; validation happens there.
 */
static int kafka_xlat_instantiate(xlat_inst_ctx_t const *xctx)
{
	rlm_kafka_xlat_inst_t	*inst = talloc_get_type_abort(xctx->inst, rlm_kafka_xlat_inst_t);
	rlm_kafka_t const	*mod_inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_kafka_t);
	xlat_exp_t		*topic_arg;
	xlat_exp_t const	*topic_node;
	char const		*topic_name;
	fr_value_box_t		topic_vb = FR_VALUE_BOX_INITIALISER_NULL(topic_vb);

	/*
	 *	ex is the XLAT_FUNC node; its args are wrapped as
	 *	XLAT_GROUP children, one per positional argument.
	 */
	topic_arg = xlat_exp_head(xctx->ex->call.args);
	if (!topic_arg || topic_arg->type != XLAT_GROUP) return 0;

	if (!xlat_is_literal(topic_arg->group)) return 0;

	topic_node = xlat_exp_head(topic_arg->group);
	if (!topic_node) return 0;

	/*
	 *	Attempt to cast to a string
	 */
	if (topic_node->data.type != FR_TYPE_STRING) {
		if (unlikely(fr_value_box_cast(inst, &topic_vb, FR_TYPE_STRING, NULL, &topic_node->data) < 0)) {
			PERROR("First argument of %%<module>.produce() must be stringlike");
			return -1;
		}
		topic_name = topic_vb.vb_strvalue;
	} else {
		topic_name = topic_node->data.vb_strvalue;
	}

	/*
	 *	Resolve to the inst-scoped handle now so the xlat
	 *	runtime can skip the rbtree walk.  Unknown topics fail
	 *	here at config-compile time.
	 */
	inst->topic = kafka_find_topic(mod_inst, topic_name);
	if (!inst->topic) {
		cf_log_err(xctx->mctx->mi->conf,
			   "Kafka topic '%s' is not declared in the '%s' module config",
			   topic_name, xctx->mctx->mi->name);
		fr_value_box_clear_value(&topic_vb);
		return -1;
	}
	fr_value_box_clear_value(&topic_vb);

	return 0;
}

/** Xlat resume: translate delivery report into a "partition:offset" string
 *
 * @param[in] xctx_ctx talloc context for the returned value box.
 * @param[in] out      cursor to append the result to.
 * @param[in] xctx     xlat ctx, rctx points at the rlm_kafka_msg_ctx_t.
 * @param[in] request  associated request (for logging).
 * @param[in] in       UNUSED (original args).
 */
static xlat_action_t kafka_xlat_produce_resume(TALLOC_CTX *xctx_ctx, fr_dcursor_t *out,
					       xlat_ctx_t const *xctx,
					       request_t *request, UNUSED fr_value_box_list_t *in)
{
	rlm_kafka_msg_ctx_t	*pctx = xctx->rctx;		/* malloc'd, not talloc */
	fr_value_box_t		*vb;
	bool			delivered = (pctx->err == RD_KAFKA_RESP_ERR_NO_ERROR);

	if (unlikely(!delivered)) REDEBUG("Kafka produce failed - %s", rd_kafka_err2str(pctx->err));

	MEM(vb = fr_value_box_alloc(xctx_ctx, FR_TYPE_BOOL, NULL));
	vb->vb_bool = delivered;
	fr_dcursor_append(out, vb);

	free(pctx);
	return XLAT_ACTION_DONE;
}

/** Xlat cancellation
 *
 * Same semantics as @ref mod_signal: detach the request from the
 * in-flight `pctx` so the eventual bg cb discards silently rather than
 * resuming a cancelled request.  The bg cb owns the free.
 *
 * @param[in] xctx    xlat ctx (xctx->rctx is the rlm_kafka_msg_ctx_t).
 * @param[in] request UNUSED.
 * @param[in] action  UNUSED (we mask off everything except CANCEL).
 */
static void kafka_xlat_produce_signal(xlat_ctx_t const *xctx, UNUSED request_t *request, UNUSED fr_signal_t action)
{
	rlm_kafka_msg_ctx_t	*pctx = xctx->rctx;

	atomic_store_explicit(&pctx->request, NULL, memory_order_release);
}

static xlat_arg_parser_t const kafka_xlat_produce_args[] = {
	{ .required = true,  .concat = true, .type = FR_TYPE_STRING },	/* topic */
	{ .required = false, .concat = true, .type = FR_TYPE_OCTETS },	/* key (null / empty / absent = no key on the wire) */
	{ .required = true,  .concat = true, .type = FR_TYPE_OCTETS },	/* value */
	XLAT_ARG_PARSER_TERMINATOR
};

/** `%kafka.produce(topic, key, value)` - runtime-named produce
 *
 * Unlike the @ref mod_produce method form (which resolves topics at
 * config-parse time), the xlat takes the topic name as a runtime
 * argument.  Use this when the topic or payload is chosen per-request:
 *
 * @code
 *     send Accounting-Response {
 *         if (!%kafka.produce('accounting', %{Acct-Session-Id}, %json.encode(&request.[*]))) {
 *             reject
 *         }
 *     }
 * @endcode
 *
 * `key` is optional.  Pass `null`, an empty string, `(octets) ""`, or
 * an attribute that expands to nothing to produce without a key -
 * librdkafka then uses the configured partitioner to spread records
 * across partitions.  When a non-empty key is supplied, librdkafka
 * hashes it to pick a partition, so records with the same key end up
 * on the same partition and preserve per-key produce order on the
 * consumer side.
 *
 * Returns a bool: `true` on successful delivery, `false` on failure.
 * The topic must have been declared in the module config (unknown
 * topics fail the xlat) so librdkafka per-topic settings continue to
 * apply to whichever topic is selected.
 *
 * Runtime behaviour mirrors the method: submit via
 * @ref kafka_produce_enqueue, yield until the delivery report arrives,
 * then resume in @ref kafka_xlat_produce_resume.
 */
static xlat_action_t kafka_xlat_produce(UNUSED TALLOC_CTX *xctx_ctx, UNUSED fr_dcursor_t *out,
					xlat_ctx_t const *xctx,
					request_t *request, fr_value_box_list_t *in)
{
	rlm_kafka_t const		*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_kafka_t);
	rlm_kafka_thread_t		*t = talloc_get_type_abort(xctx->mctx->thread, rlm_kafka_thread_t);
	rlm_kafka_xlat_inst_t const	*xlat_inst = talloc_get_type_abort_const(xctx->inst, rlm_kafka_xlat_inst_t);
	fr_value_box_t			*topic_vb = fr_value_box_list_head(in);
	fr_value_box_t			*key_vb   = fr_value_box_list_next(in, topic_vb);
	fr_value_box_t			*value_vb = fr_value_box_list_next(in, key_vb);
	rd_kafka_topic_t		*topic;
	rlm_kafka_msg_ctx_t		*pctx;
	uint8_t const			*key = NULL;
	size_t				key_len = 0;

	/*
	 *	The xlat framework enforces the arg contract before calling
	 *	us: `required = true` for topic + value, and the required
	 *	value slot after key keeps key's position filled even when
	 *	the caller passes `null`.  Assert the invariant so Coverity
	 *	stops flagging the downstream derefs.
	 */
	fr_assert(topic_vb && key_vb && value_vb);

	/*
	 *	Fast path: a literal topic argument was pre-resolved to
	 *	an rd_kafka_topic_t at xlat_instantiate time.
	 */
	topic = xlat_inst->topic;
	if (!topic) topic = kafka_find_topic(inst, topic_vb->vb_strvalue);
	if (unlikely(!topic)) {
		REDEBUG("Kafka topic '%s' is not declared in the module config", topic_vb->vb_strvalue);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	`null`, a zero-length literal, or an attribute expanding
	 *	to nothing all map to "no key" on the wire - librdkafka
	 *	then uses the configured partitioner instead of key-hash
	 *	partitioning.  The key box itself is always present here -
	 *	the required value slot after it forces the caller to
	 *	provide three args or fail at arg validation.
	 */
	if (!fr_type_is_null(key_vb->type) && key_vb->vb_length > 0) {
		key = key_vb->vb_octets;
		key_len = key_vb->vb_length;
	}

	pctx = kafka_produce_enqueue(t, request, topic,
				     key, key_len,
				     value_vb->vb_octets, value_vb->vb_length);
	if (unlikely(!pctx)) return XLAT_ACTION_FAIL;

	return unlang_xlat_yield(request, kafka_xlat_produce_resume, kafka_xlat_produce_signal,
				 ~FR_SIGNAL_CANCEL, pctx);
}

/** Background event callback, runs on librdkafka's bg thread
 *
 * Dispatches delivery reports to the originating worker's mailbox.
 * Runs on a librdkafka-owned thread, so MUST NOT touch talloc (races
 * worker-thread allocs) or the FR logger (`fr_log` is talloc-backed).
 * Allowed: plain pointer deref, atomic load/store, `fr_atomic_ring_push`,
 * `fr_event_user_trigger`, `malloc`/`free`, `rd_kafka_event_destroy`.
 *
 * For each DR:
 *   1. Acquire-load `pctx->request`.  If NULL the request was cancelled
 *      via the signal handler - just `free(pctx)` inline; no thread_inst
 *      or mailbox access.  Safe even if the owning worker has since
 *      detached.
 *   2. Otherwise stash err / partition / offset, push onto
 *      `target->mailbox`, and `fr_event_user_trigger()` the worker's
 *      wake event.  The worker is guaranteed alive because cancellation
 *      happens before thread_detach and any still-live request pins
 *      its worker.
 *
 * `NULL` opaque indicates a fire-and-forget produce - nothing to do.
 *
 * @param[in] rk    UNUSED.
 * @param[in] ev    librdkafka event batch; destroyed at end.
 * @param[in] uctx  UNUSED (we don't need the inst here).
 */
static void _kafka_background_event_cb(UNUSED rd_kafka_t *rk, rd_kafka_event_t *ev, UNUSED void *uctx)
{
	switch (rd_kafka_event_type(ev)) {
	case RD_KAFKA_EVENT_DR:
	{
		rd_kafka_message_t const *msg;
		while ((msg = rd_kafka_event_message_next(ev))) {
			rlm_kafka_msg_ctx_t	*pctx;
			rlm_kafka_thread_t	*t;

			if (!msg->_private) continue;		/* fire-and-forget */

			pctx = msg->_private;			/* plain cast; no talloc ops */

			/*
			 *	Advisory: if the request was already cancelled
			 *	on the worker side, short-circuit and drop the
			 *	pctx here rather than walking the full dispatch
			 *	path just for the worker to see NULL again and
			 *	free it.  Correctness does NOT depend on this
			 *	check - a missed cancel just means the pctx
			 *	takes the slow path through the mailbox.  The
			 *	shutdown barrier is `rd_kafka_flush` in
			 *	`mod_thread_detach`, not this early-out.
			 */
			if (atomic_load_explicit(&pctx->request, memory_order_acquire) == NULL) {
				free(pctx);
				continue;
			}

			pctx->err = msg->err;
			pctx->partition	= msg->partition;
			pctx->offset = msg->offset;
			t = pctx->target;

#ifndef NDEBUG
			fr_assert(pthread_equal(pthread_self(), t->worker_tid) == 0);
#endif

			MEM(fr_atomic_ring_push(t->queue, pctx) == true);

			(void) fr_event_user_trigger(t->wake);
		}
		break;
	}

	default:
		/*
		 *	Broker-level errors surface via `_kafka_log_cb`
		 *	on librdkafka's broker threads; anything else
		 *	reaching this bg cb (instance-scoped errors,
		 *	throttle events, etc.) is currently swallowed.
		 *	Add a relaxed-atomic counter off `inst` if we
		 *	ever need observability here.
		 */
		break;
	}

	rd_kafka_event_destroy(ev);
}

/** Destructor for inst-scoped topic handles.  Releases the rd_kafka_topic_t. */
static int _topic_free(rlm_kafka_topic_t *h)
{
	if (h->kt) rd_kafka_topic_destroy(h->kt);
	return 0;
}

/** Create a shared rd_kafka_topic_t for every declared topic
 *
 * Called at mod_instantiate.  Walks the `topic { <name> { ... } }`
 * subsections directly off the module's CONF_SECTION - the kafka base
 * library has already parsed each per-topic conf into an
 * `fr_kafka_topic_conf_t` stashed via cf_data on the topic's section,
 * so we just fetch and dup it.
 */
static int kafka_topics_alloc(rlm_kafka_t *inst)
{
	MEM(inst->topics = fr_rb_inline_talloc_alloc(inst, rlm_kafka_topic_t, node, topic_name_cmp, NULL));

	if (!inst->kconf.topics) return 0;

	fr_rb_inorder_foreach(inst->kconf.topics, fr_kafka_topic_t, topic) {
		rlm_kafka_topic_t	*topic_t;
		rd_kafka_topic_conf_t	*ktc;

		MEM(ktc = rd_kafka_topic_conf_dup(topic->conf->rdtc));
		MEM(topic_t = talloc_zero(inst->topics, rlm_kafka_topic_t));
		MEM(topic_t->name = talloc_strdup(topic_t, topic->name));
		topic_t->kt = rd_kafka_topic_new(inst->rk, topic_t->name, ktc);
		if (!topic_t->kt) {
			/* librdkafka consumes tc only on success */
			rd_kafka_topic_conf_destroy(ktc);
			ERROR("Failed creating topic '%s' - %s",
			      topic_t->name, rd_kafka_err2str(rd_kafka_last_error()));
			talloc_free(topic_t);
			return -1;
		}
		talloc_set_destructor(topic_t, _topic_free);

		if (!fr_cond_assert_msg(fr_rb_insert(inst->topics, topic_t), "duplicate topic handle")) {
			talloc_free(topic_t);
			return -1;
		}
	}
	endforeach

	return 0;
}

/** Tear down a worker's kafka state
 *
 * The barrier we need is "no bg cb is mid-invocation for any of our
 * pctxs when the framework frees `t` / `t->el`".  `rd_kafka_flush`
 * waits for every outstanding produce's DR to be fired AND the bg cb
 * to have returned, which gives us exactly that.  If flush times out
 * (broker unreachable mid-shutdown) we purge all inflight messages -
 * librdkafka synthesises `ERR__PURGE_QUEUE` DRs for them locally, no
 * broker round-trip - and a second flush drains those through the
 * bg cb with an unbounded wait (purge makes the drain finite without
 * needing a user-configured timeout).
 *
 * Every worker flushes.  The first one through actually drains
 * librdkafka's queues; subsequent calls return immediately because
 * `outq_len` is already zero.  The cost is one extra flush call per
 * worker (cheap when there's nothing to wait for), the gain is that
 * each worker has its own barrier guaranteeing no bg cb invocation
 * is mid-flight against this worker's `t->queue` / `t->wake`.
 *
 * Order: flush -> drain mailbox -> free wake.  Freeing the wake
 * before draining would race a bg cb that loaded a non-NULL
 * `pctx->request` just before cancellation propagated and is about
 * to call `fr_event_user_trigger(t->wake)`.
 *
 * @param[in] mctx thread-instance ctx.
 * @return 0 (never fails fatally).
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_kafka_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_kafka_t);
	rlm_kafka_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_kafka_thread_t);
	rlm_kafka_msg_ctx_t	*pctx;
	rd_kafka_resp_err_t	err;

	/*
	 *	Flush is thread safe, and only returns after
	 *	all in flight kafka requests have had their
	 *	delivery reports run through the callback.
	 *
	 *	At the point where thread_detach is called
	 *	there are no more request_t in progress, so
	 *	we guarantee the callback will never add additional
	 *	delivery reports to this thread's queue.
	 *
	 *	We call kafka flush in every thread, because
	 *	there is no explicit synchronisation which
	 *	guarantees all workers have stopped processing
	 *	requests by the time the first thread is being
	 *	detached, so theoretically new requests can
	 *	be enqueued by other threads after the first
	 *	thread has called flush.
	 */
	err = rd_kafka_flush(inst->rk, fr_time_delta_to_msec(inst->flush_timeout));
	if (unlikely(err != RD_KAFKA_RESP_ERR_NO_ERROR)) {
		WARN("Shutdown flush timed out, purging %d in-flight message(s)",
		     rd_kafka_outq_len(inst->rk));

		rd_kafka_purge(inst->rk, RD_KAFKA_PURGE_F_QUEUE | RD_KAFKA_PURGE_F_INFLIGHT);

		/*
		 *	Drain the purge-generated DRs.  No broker
		 *	round-trip left; drain time is bounded by
		 *	bg cb processing speed (us per pctx).
		 *	-1 == wait indefinitely.
		 */
		(void) rd_kafka_flush(inst->rk, -1);
	}

	/*
	 *	Drain anything the bg cb pushed onto us.  Every pctx
	 *	here must have `request == NULL` because the framework
	 *	cancels every yielded request this worker owned before
	 *	calling thread_detach - assert that to catch any future
	 *	change to that ordering immediately.
	 */
	while (fr_atomic_ring_pop(t->queue, (void **)&pctx)) {
		fr_assert(atomic_load_explicit(&pctx->request, memory_order_relaxed) == NULL);
		free(pctx);
	}

	TALLOC_FREE(t->wake);

	return 0;
}

/** Stand up this worker's kafka mailbox + wake event
 *
 * Allocates the segmented SPSC ring that the bg cb will push delivery
 * reports onto and registers the `EVFILT_USER` wake event the cb uses
 * to kick us.  The shared producer itself is created once at
 * `mod_instantiate` - there's nothing per-worker to wire up there.
 *
 * @param[in] mctx thread-instance ctx (`mctx->thread` is our
 *                 rlm_kafka_thread_t, `mctx->el` is the worker's
 *                 event list).
 * @return 0 on success, -1 on any setup failure.
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_kafka_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_kafka_thread_t);

	t->el = mctx->el;

#ifndef NDEBUG
	t->worker_tid = pthread_self();
#endif

	/*
	 *	Segment size is a growth-granularity knob, not a cap: the
	 *	ring grows on demand, so 1024 just controls how often the
	 *	bg thread has to malloc a fresh segment during bursts.
	 */
	MEM(t->queue = fr_atomic_ring_alloc(t, 1024));

	if (fr_event_user_insert(t, t->el, &t->wake, false, _kafka_wake, t) < 0) {
		PERROR("fr_event_user_insert failed");
		return -1;
	}

	return 0;
}

/** Module-instance setup
 *
 * Builds the log prefix, wires up the log + background event callbacks
 * on the shared conf, enables DR / ERROR events, creates the single
 * shared producer, forwards the main queue to the background queue
 * (so DRs reach `_kafka_background_event_cb` via librdkafka's own bg
 * thread), and finally creates the inst-scoped topic handles.
 *
 * @param[in] mctx module-instance ctx.
 * @return 0 on success, -1 on error.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_kafka_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_kafka_t);
	rd_kafka_conf_t	*conf;
	char		errstr[512];

	/*
	 *	rd_kafka_new consumes the conf on success.  The original
	 *	lives under a talloc sentinel that destroys it at inst
	 *	teardown, so dup it before handing ownership off.
	 */
	MEM(inst->log_prefix = talloc_typed_asprintf(inst, "rlm_kafka (%s)", mctx->mi->name));

	MEM(conf = rd_kafka_conf_dup(inst->kconf.conf));
	rd_kafka_conf_set_log_cb(conf, _kafka_log_cb);
	rd_kafka_conf_set_background_event_cb(conf, _kafka_background_event_cb);
	rd_kafka_conf_set_events(conf, RD_KAFKA_EVENT_DR | RD_KAFKA_EVENT_ERROR);
	rd_kafka_conf_set_opaque(conf, inst);

	inst->rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if (!inst->rk) {
		rd_kafka_conf_destroy(conf);			/* only consumed on success */
		ERROR("rd_kafka_new failed - %s", errstr);
		return -1;
	}

	/*
	 *	Producer DRs land on the main queue by default; the bg cb
	 *	only runs for events on the background queue.  Forward
	 *	main -> bg so delivery reports reach our cb.
	 */
	{
		rd_kafka_queue_t *main_q = rd_kafka_queue_get_main(inst->rk);
		rd_kafka_queue_t *bg_q   = rd_kafka_queue_get_background(inst->rk);

		rd_kafka_queue_forward(main_q, bg_q);
		rd_kafka_queue_destroy(main_q);
		rd_kafka_queue_destroy(bg_q);
	}

	if (kafka_topics_alloc(inst) < 0) {
		rd_kafka_destroy(inst->rk);
		inst->rk = NULL;
		return -1;
	}

	return 0;
}

/** Module detach: tear down the shared producer
 *
 *  1. `rd_kafka_flush` gives in-flight produces a grace window to
 *     complete and fire their DRs through the bg cb.  By this point
 *     every worker has already detached; any remaining pctxs have
 *     `request == NULL` and will be freed inline by the bg cb.
 *  2. Free the topic rbtree explicitly BEFORE `rd_kafka_destroy` -
 *     destroy auto-tears-down topic handles attached to the producer,
 *     and we'd double-free via `_topic_free` otherwise.
 *  3. `rd_kafka_destroy` blocks until the bg thread exits; after that
 *     no more callbacks can fire.
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_kafka_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_kafka_t);

	if (inst->rk) {
		rd_kafka_resp_err_t	ferr;

		ferr = rd_kafka_flush(inst->rk, fr_time_delta_to_msec(inst->flush_timeout));
		if (ferr != RD_KAFKA_RESP_ERR_NO_ERROR) {
			WARN("kafka - flush timed out; %d messages remain in queue",
			     rd_kafka_outq_len(inst->rk));
		}
	}

	TALLOC_FREE(inst->topics);

	if (inst->rk) {
		rd_kafka_destroy(inst->rk);
		inst->rk = NULL;
	}

	return 0;
}

/** Bootstrap-phase setup
 *
 * Just registers the `%kafka.produce()` xlat.  Topic declarations are
 * looked up directly via `cf_section_find` at call_env parse time
 * (see `_kafka_topic_env_parse`), and at worker thread_instantiate
 * time via `cf_section_find_next`, so there's nothing to build here.
 *
 * @param[in] mctx module-instance ctx.
 * @return 0 on success, -1 on error.
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t	*xlat;

	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "produce", kafka_xlat_produce, FR_TYPE_BOOL);
	if (!xlat) return -1;
	xlat_func_args_set(xlat, kafka_xlat_produce_args);
	xlat_func_instantiate_set(xlat, kafka_xlat_instantiate,
				  rlm_kafka_xlat_inst_t, NULL, NULL);

	return 0;
}

/** One-time library load hook
 *
 * Prime librdkafka's lazy global init (SSL lock callbacks on legacy
 * OpenSSL, SASL globals if compiled in) so the first real
 * `rd_kafka_new()` in a worker thread doesn't race the server's own
 * OpenSSL setup.  Ref-counted against any other kafka-using module.
 */
static int mod_load(void)
{
	return fr_kafka_init();
}

/** Paired with mod_load */
static void mod_unload(void)
{
	fr_kafka_free();
}

module_rlm_t rlm_kafka = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "kafka",
		.inst_size		= sizeof(rlm_kafka_t),
		.thread_inst_size	= sizeof(rlm_kafka_thread_t),
		.config			= module_config,
		.onload			= mod_load,
		.unload			= mod_unload,
		.bootstrap		= mod_bootstrap,
		.instantiate		= mod_instantiate,
		.detach			= mod_detach,
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach
	},
	/*
	 *	`send` and `recv` alias `produce` so the call reads naturally
	 *	in its surrounding section - e.g. `recv Access-Request {
	 *	kafka.recv.auth }` or `send Access-Accept { kafka.send.audit }`.
	 *	All three dispatch to the same producer path.
	 */
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{
				.section = SECTION_NAME("produce", CF_IDENT_ANY),
				.method = mod_produce,
				.method_env = &rlm_kafka_produce_env
			},
			{
				.section = SECTION_NAME("send", CF_IDENT_ANY),
				.method = mod_produce,
				.method_env = &rlm_kafka_produce_env
			},
			{
				.section = SECTION_NAME("recv", CF_IDENT_ANY),
				.method = mod_produce,
				.method_env = &rlm_kafka_produce_env
			},
			MODULE_BINDING_TERMINATOR
		}
	}
};
