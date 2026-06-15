#pragma once
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
 * @file lib/kafka/base.h
 * @brief Common functions for interacting with kafka
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(kafka_base_h, "$Id$")

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation-deprecated-sync)
DIAG_OFF(documentation)
#endif
#include <librdkafka/rdkafka.h>
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
DIAG_ON(documentation-deprecated-sync)
#endif

#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/util/rb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_kafka_topic_s fr_kafka_topic_t;

typedef struct {
	rd_kafka_conf_t		*conf;

	fr_rb_tree_t		*topics;	//!< Declared topics, keyed by name.  Populated during
						//!< config parsing by the per-topic hook on the `topic { }`
						//!< subsection; use `kafka_topic_conf_find` to query.
} fr_kafka_conf_t;

typedef struct {
	rd_kafka_topic_conf_t	*rdtc;
} fr_kafka_topic_conf_t;

/** Declared topic record - one per `topic { <name> { ... } }` subsection
 *
 * Built by the library's per-topic parse hook, indexed on the parent
 * `fr_kafka_conf_t.topics` tree.  Callers typically retrieve via
 * `kafka_topic_conf_find` rather than poking this struct directly.
 */
struct fr_kafka_topic_s {
	char const		*name;		//!< as it appeared in config
	fr_kafka_topic_conf_t	*conf;		//!< parsed per-topic librdkafka conf
	CONF_SECTION		*cs;		//!< topic's CONF_SECTION (for call_env lookups
						//!< of per-topic pairs like `value` / `key`)
	fr_rb_node_t		node;
};

/** uctx attached to each entry in `KAFKA_BASE_PRODUCER_CONFIG`
 *
 * Public so the config macro's struct literals resolve in caller TUs.
 * You only touch this directly if you're extending the library's
 * producer config with additional librdkafka pass-through properties.
 */
typedef struct {
	fr_table_ptr_sorted_t	*mapping;	//!< Mapping table between string constant.
	size_t			*mapping_len;	//!< Length of the mapping tables
	bool			empty_default;	//!< Don't produce messages saying the default is missing.
	size_t			size_scale;	//!< Divide/multiply FR_TYPE_SIZE by this amount.
	char const		*property;	//!< Kafka configuration property.
	char const		*string_sep;	//!< Used for multi-value configuration items.
						//!< Kafka uses ', ' or ';' seemingly at random.
} fr_kafka_conf_ctx_t;

/** Generic librdkafka-property parser used by `KAFKA_BASE_PRODUCER_CONFIG` entries
 *
 * Exposed so the macro's FR_CONF_PAIR_GLOBAL entries can reference it from any TU.
 */
int kafka_config_parse(TALLOC_CTX *ctx, void *out, void *base, CONF_ITEM *ci, conf_parser_t const *rule);

/** Default-generator counterpart to @ref kafka_config_parse - reads the
 *  librdkafka default for the property and materialises it as a CONF_PAIR.
 */
int kafka_config_dflt(CONF_PAIR **out, void *parent, CONF_SECTION *cs, fr_token_t quote, conf_parser_t const *rule);

/** Untyped passthrough parser used by `KAFKA_RAW_CONFIG`
 *
 * Hands the CONF_PAIR's attribute/value straight to `rd_kafka_conf_set`.
 * No type dispatch - user is responsible for librdkafka-native units.
 */
int kafka_config_raw_parse(TALLOC_CTX *ctx, void *out, void *base, CONF_ITEM *ci, conf_parser_t const *rule);

/** Topic-level raw passthrough.  Counterpart to `kafka_config_raw_parse`
 *  for use inside a declared topic's subsection, dispatching to
 *  `rd_kafka_topic_conf_set`.
 */
int kafka_topic_config_raw_parse(TALLOC_CTX *ctx, void *out, void *base, CONF_ITEM *ci, conf_parser_t const *rule);

/** Per-topic subsection hook used by KAFKA_PRODUCER_CONFIG / KAFKA_CONSUMER_CONFIG
 *
 * Runs the inner rules against each `topic { <name> { ... } }` block
 * then inserts an `fr_kafka_topic_t` into the parent `fr_kafka_conf_t.topics`
 * tree so callers can look topics up by name without re-walking CONF_SECTIONs.
 */
int kafka_topic_subsection_parse(TALLOC_CTX *ctx, void *out, void *base, CONF_ITEM *ci, conf_parser_t const *rule);

/** Look up a declared topic by name on an `fr_kafka_conf_t`
 *
 * @return the `fr_kafka_topic_t`, or NULL if no topic of that name was
 *         declared (or if no topics have been parsed yet).
 */
fr_kafka_topic_t	*kafka_topic_conf_find(fr_kafka_conf_t const *kc, char const *name);

/** Initialise librdkafka's global state (SSL / SASL / internal ref-count)
 *
 * Ref-counted: every call must be paired with `fr_kafka_free()`.  The
 * first call lazily kicks librdkafka's one-time init paths by creating
 * and destroying a throwaway producer; subsequent calls just bump the
 * refcount.  Call this from a kafka-using module's `.onload` so the
 * library's internal globals are set up deterministically at startup
 * rather than racing the first real `rd_kafka_new()` in a worker
 * thread.
 *
 * @return 0 on success, -1 on failure.
 */
int		fr_kafka_init(void);

/** Release one reference to librdkafka's global state
 *
 * Call from a module's `.unload` to pair `fr_kafka_init()`.  The last
 * release is a no-op; librdkafka internally ref-counts its own globals
 * and tears down when the last `rd_kafka_t` goes.
 */
void		fr_kafka_free(void);

/** @name Nested config arrays referenced by `KAFKA_BASE_PRODUCER_CONFIG`
 *
 * Extern so the macro's FR_CONF_SUBSECTION_GLOBAL entries can name them
 * from any TU.  Not part of the stable API - treat as implementation
 * detail of the macro.
 * @{
 */
extern conf_parser_t const kafka_metadata_config[];
extern conf_parser_t const kafka_version_config[];
extern conf_parser_t const kafka_connection_config[];
extern conf_parser_t const kafka_tls_config[];
extern conf_parser_t const kafka_sasl_config[];
extern conf_parser_t const kafka_base_producer_topics_config[];
extern conf_parser_t const kafka_consumer_group_config[];
extern conf_parser_t const kafka_base_consumer_topics_config[];
extern conf_parser_t const kafka_base_properties_config[];
extern conf_parser_t const kafka_base_topic_properties_config[];
/** @} */

/** Config entries common to producer and consumer clients
 *
 * Broker list, client identity, TLS / SASL, metadata / version /
 * connection tuning, debug / plugin knobs.  Usually composed with a
 * role-specific macro (@ref KAFKA_PRODUCER_CONFIG, or a future
 * consumer equivalent).
 */
#define KAFKA_BASE_CONFIG \
	/* Initial list of brokers. librdkafka only needs one it can reach. */ \
	{ FR_CONF_PAIR_GLOBAL("server", FR_TYPE_STRING, CONF_FLAG_REQUIRED | CONF_FLAG_MULTI, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "metadata.broker.list", .string_sep = "," }}, \
	/* Identifier sent with each request to brokers. */ \
	{ FR_CONF_PAIR_GLOBAL("client_id", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "client.id" }}, \
	/* Rack identifier for rack-aware fetch-from-follower. */ \
	{ FR_CONF_PAIR_GLOBAL("rack_id", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "client.rack" }}, \
	/* Max size of a message the broker will accept. */ \
	{ FR_CONF_PAIR_GLOBAL("request_max_size", FR_TYPE_SIZE, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "message.max.bytes" }}, \
	/* Max size of a message copied into librdkafka's send buffer. */ \
	{ FR_CONF_PAIR_GLOBAL("request_copy_max_size", FR_TYPE_SIZE, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "message.copy.max.bytes" }}, \
	/* Max size of a response from a broker. */ \
	{ FR_CONF_PAIR_GLOBAL("response_max_size", FR_TYPE_SIZE, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "receive.message.max.bytes" }}, \
	/* Compile-time features to enable (comma-separated). */ \
	{ FR_CONF_PAIR_GLOBAL("feature", FR_TYPE_STRING, CONF_FLAG_MULTI, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "builtin.features", .string_sep = "," }}, \
	/* Comma-separated list of debug contexts to enable. */ \
	{ FR_CONF_PAIR_GLOBAL("debug", FR_TYPE_STRING, CONF_FLAG_MULTI, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "debug", .string_sep = "," }}, \
	/* Semicolon-separated plugin library paths to load. */ \
	{ FR_CONF_PAIR_GLOBAL("plugin", FR_TYPE_STRING, CONF_FLAG_MULTI, kafka_config_parse, NULL), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "plugin.library.paths", .string_sep = ";" }}, \
	{ FR_CONF_SUBSECTION_GLOBAL("metadata", 0, kafka_metadata_config) }, \
	{ FR_CONF_SUBSECTION_GLOBAL("version", 0, kafka_version_config) }, \
	{ FR_CONF_SUBSECTION_GLOBAL("connection", 0, kafka_connection_config) }, \
	{ FR_CONF_SUBSECTION_GLOBAL("tls", 0, kafka_tls_config) }, \
	{ FR_CONF_SUBSECTION_GLOBAL("sasl", 0, kafka_sasl_config) }, \
	/* Escape-hatch for librdkafka client properties we don't enumerate. \
	 * Contents are fed verbatim to rd_kafka_conf_set - no type dispatch, \
	 * the user writes librdkafka-native units (e.g. "500" for ms). */ \
	{ FR_CONF_SUBSECTION_GLOBAL("properties", 0, kafka_base_properties_config) }

/** Producer-only delta: librdkafka producer tuning + declared topics
 *
 * Compose with @ref KAFKA_BASE_CONFIG.  Callers must embed
 * `fr_kafka_conf_t` as the first member of their instance struct so
 * `FR_CONF_OFFSET` resolves against it.
 *
 * @code
 *     static conf_parser_t const module_config[] = {
 *         KAFKA_BASE_CONFIG,
 *         KAFKA_PRODUCER_CONFIG,
 *         { FR_CONF_OFFSET("my_thing", rlm_foo_t, my_thing) },
 *         CONF_PARSER_TERMINATOR
 *     };
 * @endcode
 */
#define KAFKA_PRODUCER_CONFIG \
	/* Enables the transactional producer. */ \
	{ FR_CONF_PAIR_GLOBAL("transactional_id", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "transactional.id", .empty_default = true }}, \
	/* Maximum time the transaction coordinator will wait for a status update \
	 * from the producer before proactively aborting the transaction. */ \
	{ FR_CONF_PAIR_GLOBAL("transaction_timeout", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "transaction.timeout.ms" }}, \
	/* Ensures exactly-once, in-order delivery per partition. \
	 * Requires acks=all semantics broker-side. */ \
	{ FR_CONF_PAIR_GLOBAL("idempotence", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.idempotence" }}, \
	/* Fail any error that would cause a gap in the produced message series. */ \
	{ FR_CONF_PAIR_GLOBAL("gapless_guarantee", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.gapless.guarantee" }}, \
	/* Max number of messages buffered across all topics/partitions. \
	 * Produce fails synchronously (QUEUE_FULL) once hit. */ \
	{ FR_CONF_PAIR_GLOBAL("queue_max_messages", FR_TYPE_UINT32, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queue.buffering.max.messages" }}, \
	/* Max total size of buffered messages (bytes, scaled from kbytes). */ \
	{ FR_CONF_PAIR_GLOBAL("queue_max_size", FR_TYPE_SIZE, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queue.buffering.max.kbytes", .size_scale = 1024 }}, \
	/* Linger time before a batch is sent, for producer-side batching. */ \
	{ FR_CONF_PAIR_GLOBAL("queue_max_delay", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queue.buffering.max.ms" }}, \
	/* Max number of retries per failed send. */ \
	{ FR_CONF_PAIR_GLOBAL("message_retry_max", FR_TYPE_UINT32, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "message.send.max.retries" }}, \
	/* Backoff between retries of a protocol request. */ \
	{ FR_CONF_PAIR_GLOBAL("message_retry_interval", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "retry.backoff.ms" }}, \
	/* Outstanding-request threshold at which the accumulator backpressures. */ \
	{ FR_CONF_PAIR_GLOBAL("backpressure_threshold", FR_TYPE_UINT32, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queue.buffering.backpressure.threshold" }}, \
	/* Compression codec: none, gzip, snappy, lz4, zstd. */ \
	{ FR_CONF_PAIR_GLOBAL("compression_type", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "compression.type" }}, \
	/* Max size (bytes) of all messages batched into one MessageSet. */ \
	{ FR_CONF_PAIR_GLOBAL("batch_size", FR_TYPE_SIZE, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "batch.size" }}, \
	/* Delay before reassigning sticky partitions per topic. */ \
	{ FR_CONF_PAIR_GLOBAL("sticky_partition_delay", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sticky.partitioning.linger.ms" }}, \
	/* Declared topics.  Topic-level conf is stashed on each subsection via \
	 * cf_data_add; the subcs_size is a dummy because cf_parse asserts on \
	 * it for multi subsections. */ \
	{ FR_CONF_SUBSECTION_GLOBAL("topic", 0, kafka_base_producer_topics_config) }

/** Consumer-only delta: consumer-group membership, fetch/queue tuning,
 *  declared subscription topics.
 *
 * Compose with @ref KAFKA_BASE_CONFIG.  Same embedding contract as the
 * producer macro (see @ref KAFKA_PRODUCER_CONFIG).
 *
 * @code
 *     static conf_parser_t const module_config[] = {
 *         KAFKA_BASE_CONFIG,
 *         KAFKA_CONSUMER_CONFIG,
 *         CONF_PARSER_TERMINATOR
 *     };
 * @endcode
 */
#define KAFKA_CONSUMER_CONFIG \
	/* Consumer-group membership config (id, instance_id, session_timeout, ...). */ \
	{ FR_CONF_SUBSECTION_GLOBAL("group", 0, kafka_consumer_group_config) }, \
	/* Max allowed time between calls to consume messages. */ \
	{ FR_CONF_PAIR_GLOBAL("max_poll_interval", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "max.poll.interval.ms" }}, \
	/* Whether offsets are committed automatically. */ \
	{ FR_CONF_PAIR_GLOBAL("auto_commit", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.auto.commit" }}, \
	/* Interval between auto commits. */ \
	{ FR_CONF_PAIR_GLOBAL("auto_commit_interval", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "auto.commit.interval.ms" }}, \
	/* Automatically store the offset of the last message handed to the application. */ \
	{ FR_CONF_PAIR_GLOBAL("auto_offset_store", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.auto.offset.store" }}, \
	/* Min number of messages per topic+partition librdkafka keeps locally. */ \
	{ FR_CONF_PAIR_GLOBAL("queued_messages_min", FR_TYPE_UINT64, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queued.min.messages" }}, \
	/* Max total size of pre-fetched messages in the local consumer queue. */ \
	{ FR_CONF_PAIR_GLOBAL("queued_messages_max_size", FR_TYPE_SIZE, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queued.max.messages.kbytes", .size_scale = 1024 }}, \
	/* Max time the broker may wait to fill the Fetch response. */ \
	{ FR_CONF_PAIR_GLOBAL("fetch_wait_max", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "fetch.wait.max.ms" }}, \
	/* Initial per-partition fetch size. */ \
	{ FR_CONF_PAIR_GLOBAL("fetch_message_max_size", FR_TYPE_SIZE, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "fetch.message.max.bytes" }}, \
	/* Max bytes per topic+partition in a Fetch response. */ \
	{ FR_CONF_PAIR_GLOBAL("fetch_partition_max_size", FR_TYPE_SIZE, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "max.partition.fetch.bytes" }}, \
	/* Max total data a broker may return for a single Fetch request. */ \
	{ FR_CONF_PAIR_GLOBAL("fetch_max_size", FR_TYPE_SIZE, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "fetch.max.bytes" }}, \
	/* Min bytes the broker responds with. */ \
	{ FR_CONF_PAIR_GLOBAL("fetch_min_size", FR_TYPE_SIZE, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "fetch.min.bytes" }}, \
	/* How long to wait before retrying a fetch after an error. */ \
	{ FR_CONF_PAIR_GLOBAL("fetch_error_backoff", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "fetch.error.backoff.ms" }}, \
	/* How to read messages written transactionally (read_committed / read_uncommitted). */ \
	{ FR_CONF_PAIR_GLOBAL("isolation_level", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "isolation.level" }}, \
	/* Verify CRC32 of every consumed message. */ \
	{ FR_CONF_PAIR_GLOBAL("check_crcs", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "check.crcs" }}, \
	/* Allow automatic topic creation when subscribing to an unknown topic. */ \
	{ FR_CONF_PAIR_GLOBAL("auto_create_topic", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "allow.auto.create.topics" }}, \
	/* Declared subscription topics; same layering as the producer form. */ \
	{ FR_CONF_SUBSECTION_GLOBAL("topic", 0, kafka_base_consumer_topics_config) }


#ifdef __cplusplus
}
#endif
