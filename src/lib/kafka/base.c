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
 * @file kafka/base.c
 * @brief Kafka global structures
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include <freeradius-devel/kafka/base.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/util/size.h>

/* fr_kafka_conf_ctx_t definition lives in base.h so the KAFKA_BASE_CONFIG
 * macro can construct struct literals of it from caller TUs. */

/** @name Shared helpers
 *
 * Used by both the base-level and topic-level parse/dflt paths below.
 *
 * @{
 */

/** Common parse path for a single CONF_PAIR's value
 *
 * Handles librdkafka's preferred unit conventions (ms-integer for time
 * deltas, byte-integer for sizes, string "true"/"false" for bools) and
 * the optional kctx->mapping translation.  Caller hands the resulting
 * string to either rd_kafka_conf_set or rd_kafka_topic_conf_set.
 */
static int kafka_config_parse_single(char const **out, CONF_PAIR *cp, conf_parser_t const *rule)
{
	fr_value_box_t			vb = FR_VALUE_BOX_INITIALISER_NULL(vb);
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	fr_type_t			type = rule->type;
	static _Thread_local char	buff[sizeof("18446744073709551615")];
	static _Thread_local fr_sbuff_t	sbuff;

	/*
	 *	Map string values if possible, and if there's
	 *	no match then just pass the original through.
	 *
	 *      We count this as validation...
	 */
	if (kctx->mapping) {
		fr_table_ptr_sorted_t	*mapping = kctx->mapping;
		size_t			mapping_len = *kctx->mapping_len;

		*out = fr_table_value_by_str(mapping, cf_pair_value(cp), cf_pair_value(cp));
		return 0;
	} else if (fr_type_is_string(type)) {
		*out = cf_pair_value(cp);
		return 0;
	}

	/*
	 *	Parse as a box for basic validation
	 */
	if (cf_pair_to_value_box(NULL, &vb, cp, rule) < 0) return -1;

	/*
	 *	In kafka all the time deltas are in ms
	 *	resolution, so we need to take the parsed value,
	 *	scale it, and print it back to a string.
	 */
	switch (type) {
	case FR_TYPE_TIME_DELTA:
	{
		uint64_t			delta;

		sbuff = FR_SBUFF_OUT(buff, sizeof(buff));
		delta = fr_time_delta_to_msec(vb.vb_time_delta);
		if (fr_sbuff_in_sprintf(&sbuff, "%" PRIu64, delta) < 0) {
		error:
			fr_value_box_clear(&vb);
			return -1;
		}
		*out = fr_sbuff_start(&sbuff);
	}
		break;

	case FR_TYPE_SIZE:
	{
		size_t size = vb.vb_size;

		sbuff = FR_SBUFF_OUT(buff, sizeof(buff));

		/*
		 *	Most options are in bytes, but some are in kilobytes
		 */
		if (kctx->size_scale) size /= kctx->size_scale;

		/*
		 *	Kafka doesn't want units...
		 */
		if (fr_sbuff_in_sprintf(&sbuff, "%zu", size) < 0) goto error;
		*out = fr_sbuff_start(&sbuff);
	}
		break;

	/*
	 *	Ensure bool is always mapped to the string constants
	 *	"true" or "false".
	 */
	case FR_TYPE_BOOL:
		*out = vb.vb_bool ? "true" : "false";
		break;

	default:
		*out = cf_pair_value(cp);
		break;
	}

	fr_value_box_clear(&vb);

	return 0;
}

/** Common dflt path: take a librdkafka-native value string and materialise
 *  it as a CONF_PAIR in the caller's units (time deltas as "Ns", sizes
 *  with unit suffixes, etc.).  Invoked by the base and topic dflt funcs.
 *
 * @param[out] out	Where to write the pair.
 * @param[in] parent	being populated.
 * @param[in] cs	to allocate the pair in.
 * @param[in] value	to convert.
 * @param[in] quote	to use when allocating the pair.
 * @param[in] rule	UNUSED.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
static int kafka_config_dflt_single(CONF_PAIR **out, UNUSED void *parent, CONF_SECTION *cs, char const *value,
				    fr_token_t quote, conf_parser_t const *rule)
{
	char				tmp[sizeof("18446744073709551615b")];
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	fr_type_t			type = rule->type;

	/*
	 *	Apply any mappings available, but default back
	 *      to the raw value if we don't have a match.
	 */
	if (kctx->mapping) {
		fr_table_ptr_sorted_t	*mapping = kctx->mapping;
		size_t			mapping_len = *kctx->mapping_len;

		value = fr_table_str_by_str_value(mapping, value, value);
	}
	/*
	 *	Convert time delta as an integer with ms precision
	 */
	switch (type) {
	case FR_TYPE_TIME_DELTA:
	{
		fr_sbuff_t 	value_elem = FR_SBUFF_IN(tmp, sizeof(tmp));
		fr_time_delta_t	delta;

		if (fr_time_delta_from_str(&delta, value, strlen(value), FR_TIME_RES_MSEC) < 0) {
			cf_log_perr(cs, "Failed parsing default \"%s\"", value);
			return -1;
		}

		fr_time_delta_to_str(&value_elem, delta, FR_TIME_RES_SEC, true);
		value = fr_sbuff_start(&value_elem);
	}
		break;

	case FR_TYPE_SIZE:
	{
		fr_sbuff_t 	value_elem = FR_SBUFF_IN(tmp, sizeof(tmp));
		size_t		size;

		if (fr_size_from_str(&size, &FR_SBUFF_IN_STR(value)) < 0) {
			cf_log_perr(cs, "Failed parsing default \"%s\"", value);
			return -1;
		}

		/*
		 *	Some options are in kbytes *sigh*
		 */
		if (kctx->size_scale) size *= kctx->size_scale;

		/*
		 * 	reprint the size with an appropriate unit
		 */
		if (fr_size_to_str(&value_elem, size) < 0) {
			cf_log_perr(cs, "Failed size reprint");
			return -1;
		}
		value = fr_sbuff_start(&value_elem);
	}
		break;

	default:
		break;
	}

	MEM(*out = cf_pair_alloc(cs, rule->name1, value, T_OP_EQ, T_BARE_WORD, quote));
	cf_item_mark_parsed(*out);	/* Don't re-parse this */

	return 0;
}

/** No-op parser used to reserve CONF_PAIR names inside a topic subsection
 *  that the module reads separately (via call_env), so they aren't caught
 *  by the trailing raw-passthrough catch-all and fed to librdkafka.
 */
static int kafka_noop_parse(UNUSED TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *base,
			    UNUSED CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	return 0;
}

/** @} */

/** @name Base conf (`fr_kafka_conf_t`)
 *
 * Lifecycle, lazy-init + talloc sentinel, and the FR_CONF_PAIR_GLOBAL parsers for
 * the top-level `kafka { ... }` section.
 *
 * @{
 */

/** Destructor on the talloc sentinel that owns the rd_kafka_conf_t handle
 *
 * The sentinel is just a talloced `rd_kafka_conf_t *` attached to the
 * caller's parse ctx - when talloc unwinds the instance, this fires and
 * releases the librdkafka handle.
 */
static int _kafka_conf_free(rd_kafka_conf_t **pconf)
{
	if (*pconf) rd_kafka_conf_destroy(*pconf);
	return 0;
}

/** Fetch the `fr_kafka_conf_t` currently being populated by the parser
 *
 * The parser contract is that `base` points at the caller's instance
 * struct and `fr_kafka_conf_t` is its first member, so a reinterpret
 * cast of `base` is the `fr_kafka_conf_t`.
 *
 * Also lazy-initialises the underlying librdkafka conf the first time
 * we see it, attaching a talloc sentinel under the parse ctx so the
 * handle is released when the caller's instance tree unwinds.
 */
static fr_kafka_conf_t *kafka_conf_get(TALLOC_CTX *ctx, void *base)
{
	fr_kafka_conf_t	*kc = base;

	if (!kc) return NULL;
	if (!kc->conf) {
		rd_kafka_conf_t	**s;

		MEM(kc->conf = rd_kafka_conf_new());

		/*
		 *	Attach a sentinel under the parse ctx so teardown
		 *	of the caller's instance data automatically releases
		 *	the librdkafka handle.
		 */
		MEM(s = talloc(ctx, rd_kafka_conf_t *));
		*s = kc->conf;
		talloc_set_destructor(s, _kafka_conf_free);
	}
	return kc;
}

/** Translate config items directly to settings in a kafka config struct
 *
 * @param[in] ctx	to allocate fr_kafka_conf_t in.
 * @param[out] out	Unused.
 * @param[in] base	Unused.
 * @param[in] ci	To parse.
 * @param[in] rule	describing how to parse the item.
 * @return
 *	- 0 on success.
 *      - -1 on failure
 */
int kafka_config_parse(TALLOC_CTX *ctx, UNUSED void *out, void *base,
		       CONF_ITEM *ci, conf_parser_t const *rule)
{
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	CONF_ITEM			*parent = cf_parent(ci);
	CONF_SECTION			*cs = cf_item_to_section(parent);
	CONF_PAIR			*cp = cf_item_to_pair(ci);

	fr_kafka_conf_t 		*kc;
	char const			*value;

	kc = kafka_conf_get(ctx, base);
	fr_assert_msg(kc, "kafka base struct missing - caller must embed fr_kafka_conf_t as first member");

	/*
	 *	Multi rules require us to concat the values together before handing them off
	 */
	if (fr_rule_multi(rule)) {
		unsigned int	i;
		CONF_PAIR	*cp_p;
		size_t		count;
		char const	**array;
		fr_sbuff_t	*agg;
		fr_slen_t	slen;

		FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 256, SIZE_MAX);

		count = cf_pair_count(cs,  rule->name1);
		if (count <= 1) goto do_single;

		MEM(array = talloc_array(ctx, char const *, count));
		for (cp_p = cp, i = 0;
		     cp_p;
		     cp_p = cf_pair_find_next(cs, cp_p, rule->name1), i++) {
			if (kafka_config_parse_single(&array[i], cp_p, rule) < 0) return -1;
			cf_item_mark_parsed(cp_p);
		}

		slen = fr_sbuff_array_concat(agg, array, kctx->string_sep);
		talloc_free(array);
		if (slen < 0) return -1;

		value = fr_sbuff_start(agg);
	} else {
	do_single:
		if (kafka_config_parse_single(&value, cp, rule) < 0) return -1;
	}

	{
		char errstr[512];

		if (rd_kafka_conf_set(kc->conf, kctx->property,
				      value, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
			cf_log_perr(cp, "%s", errstr);
			return -1;
		}
	}

	return 0;
}

/** Return the default value from the kafka client library
 *
 * @param[out] out	Where to write the pair.
 * @param[in] parent	being populated.
 * @param[in] cs	to allocate the pair in.
 * @param[in] quote	to use when allocating the pair.
 * @param[in] rule	UNUSED.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int kafka_config_dflt(CONF_PAIR **out, void *parent, CONF_SECTION *cs, fr_token_t quote, conf_parser_t const *rule)
{
	char				buff[1024];
	size_t				buff_len = sizeof(buff);
	char const			*value;

	fr_kafka_conf_t 		*kc;
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	rd_kafka_conf_res_t 		ret;

	kc = kafka_conf_get(cs, parent);
	fr_assert_msg(kc, "kafka base struct missing during default generation");

	if ((ret = rd_kafka_conf_get(kc->conf, kctx->property, buff, &buff_len)) != RD_KAFKA_CONF_OK) {
		if (ret == RD_KAFKA_CONF_UNKNOWN) {
			if (kctx->empty_default) return 0;

			cf_log_debug(cs, "No default available for \"%s\" - \"%s\"", rule->name1, kctx->property);
			return 0;	/* Not an error */
		}

		cf_log_err(cs, "Failed retrieving kafka property \"%s\"", kctx->property);
		return -1;
	}
#if 0
	cf_log_debug(cs, "Retrieved dflt \"%s\" for \"%s\" - \"%s\"", buff, rule->name1, kctx->property);
#endif
	value = buff;

	/*
	 *	If it's multi we need to break the string apart on the string separator
	 *	and potentially unescape the separator.
	 */
	if (fr_rule_multi(rule)) {
		fr_sbuff_t 			value_in = FR_SBUFF_IN(value, buff_len);
		char				tmp[256];
		fr_sbuff_t 			value_elem = FR_SBUFF_OUT(tmp, sizeof(tmp));
		/*
		 *	FR_SBUFF_TERM() uses sizeof() on its argument, which
		 *	produces the wrong length for a runtime pointer.  Build
		 *	the terminator list by hand so the length is correct.
		 */
		fr_sbuff_term_elem_t		tt_elem = { .str = kctx->string_sep, .len = strlen(kctx->string_sep) };
		fr_sbuff_term_t			tt = { .len = 1, .elem = &tt_elem };
		fr_sbuff_unescape_rules_t	ue_rules = {
							.name = __FUNCTION__,
							.chr = '\\'
						};
		/*
		 *	Convert escaped separators back
		 */
		ue_rules.subs[(uint8_t)kctx->string_sep[0]] = kctx->string_sep[0];

		while (fr_sbuff_out_unescape_until(&value_elem, &value_in, SIZE_MAX, &tt, &ue_rules) > 0) {
			if (kafka_config_dflt_single(out, parent, cs, fr_sbuff_start(&value_elem), quote, rule) < 0) return -1;

			/*
			 *	Skip past the string separator
			 */
			fr_sbuff_advance(&value_in, strlen(kctx->string_sep));

			/*
			 *	Reset
			 */
			fr_sbuff_set_to_start(&value_elem);
		}
		return 0;
	}

	/*
	 *	Parse a single value
	 */
	if (kafka_config_dflt_single(out, parent, cs, value, quote, rule) < 0) return -1;

	return 0;
}

/** Untyped passthrough: hand a CONF_PAIR's attr/value straight to rd_kafka_conf_set
 *
 * Used by the `CF_IDENT_ANY` entry in the base `properties { }` subsection
 * to accept arbitrary librdkafka properties that don't have a typed entry
 * in `KAFKA_BASE_CONFIG` / `KAFKA_PRODUCER_CONFIG` / `KAFKA_CONSUMER_CONFIG`.
 * No unit scaling, no bool mapping - the user writes what librdkafka
 * expects (e.g. "500" for a ms value, "1048576" for a byte count).
 */
int kafka_config_raw_parse(TALLOC_CTX *ctx, UNUSED void *out, void *base,
			   CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	CONF_PAIR		*cp = cf_item_to_pair(ci);
	fr_kafka_conf_t		*kc;
	char			errstr[512];

	kc = kafka_conf_get(ctx, base);
	fr_assert_msg(kc, "kafka base struct missing - caller must embed fr_kafka_conf_t as first member");

	if (rd_kafka_conf_set(kc->conf, cf_pair_attr(cp), cf_pair_value(cp),
			      errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
		cf_log_perr(cp, "%s", errstr);
		return -1;
	}
	return 0;
}

/** @} */

/** @name Topic conf (`fr_kafka_topic_conf_t` + `fr_kafka_topic_t`)
 *
 * Per-topic lifecycle, FR_CONF_PAIR_GLOBAL parsers for entries inside a declared
 * topic subsection, and the subsection hook that indexes each declared
 * topic onto `fr_kafka_conf_t.topics`.
 *
 * @{
 */

/** Destructor on a per-topic conf - releases the librdkafka handle. */
static int _kafka_topic_conf_free(fr_kafka_topic_conf_t *ktc)
{
	if (ktc->rdtc) rd_kafka_topic_conf_destroy(ktc->rdtc);
	return 0;
}

/** Allocate a per-topic conf parented under `ctx`
 *
 * Used by the subsection hook to build each declared topic's
 * `fr_kafka_topic_conf_t`.  The destructor releases the librdkafka
 * handle when the owning `fr_kafka_topic_t` is freed.
 */
static fr_kafka_topic_conf_t *kafka_topic_conf_alloc(TALLOC_CTX *ctx)
{
	fr_kafka_topic_conf_t	*ktc;

	MEM(ktc = talloc(ctx, fr_kafka_topic_conf_t));
	MEM(ktc->rdtc = rd_kafka_topic_conf_new());
	talloc_set_destructor(ktc, _kafka_topic_conf_free);
	return ktc;
}

/** Translate config items directly to settings in a kafka topic config struct
 *
 * `base` is the `fr_kafka_topic_conf_t` the per-topic subsection hook
 * handed down, so we write directly through it instead of re-fetching
 * via cf_data.  Falls back to cf_data lookup if a caller runs this
 * parser outside `kafka_topic_subsection_parse`.
 *
 * @param[in] ctx	UNUSED.
 * @param[out] out	UNUSED.
 * @param[in] base	topic-level conf (`fr_kafka_topic_conf_t *`).
 * @param[in] ci	To parse.
 * @param[in] rule	describing how to parse the item.
 * @return
 *	- 0 on success.
 *      - -1 on failure
 */
static int kafka_topic_config_parse(UNUSED TALLOC_CTX *ctx, UNUSED void *out, void *base,
				    CONF_ITEM *ci, conf_parser_t const *rule)
{
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	CONF_PAIR			*cp = cf_item_to_pair(ci);

	fr_kafka_topic_conf_t 		*ktc = base;
	char const			*value;

	fr_assert_msg(ktc, "kafka topic conf missing - topic parser invoked without subsection hook");
	if (kafka_config_parse_single(&value, cp, rule) < 0) return -1;

	{
		char errstr[512];

		if (rd_kafka_topic_conf_set(ktc->rdtc, kctx->property,
					    value, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
			cf_log_perr(cp, "%s", errstr);
			return -1;
		}
	}

	return 0;
}

/** Return the default value for a topic from the kafka client library
 *
 * @param[out] out	Where to write the pair.
 * @param[in] parent	being populated.
 * @param[in] cs	to allocate the pair in.
 * @param[in] quote	to use when allocating the pair.
 * @param[in] rule	UNUSED.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
static int kafka_topic_config_dflt(CONF_PAIR **out, void *parent, CONF_SECTION *cs, fr_token_t quote, conf_parser_t const *rule)
{
	char				buff[1024];
	size_t				buff_len = sizeof(buff);
	char const			*value;

	fr_kafka_topic_conf_t 		*ktc = parent;
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	rd_kafka_conf_res_t 		ret;

	fr_assert_msg(ktc, "kafka topic conf missing during default generation");

	if ((ret = rd_kafka_topic_conf_get(ktc->rdtc, kctx->property, buff, &buff_len)) != RD_KAFKA_CONF_OK) {
		if (ret == RD_KAFKA_CONF_UNKNOWN) {
			if (kctx->empty_default) return 0;

			cf_log_debug(cs, "No default available for \"%s\" - \"%s\"", rule->name1, kctx->property);
			return 0;	/* Not an error */
		}

		cf_log_err(cs, "Failed retrieving kafka property '%s'", kctx->property);
		return -1;
	}
#if 0
	cf_log_debug(cs, "Retrieved dflt \"%s\" for \"%s\" - \"%s\"", buff, rule->name1, kctx->property);
#endif
	value = buff;

	/*
	 *	Parse a single value
	 */
	if (kafka_config_dflt_single(out, parent, cs, value, quote, rule) < 0) return -1;

	return 0;
}

/** Topic-level counterpart to `kafka_config_raw_parse`
 *
 * Used inside a declared topic's `properties { }` subsection to accept
 * arbitrary `rd_kafka_topic_conf_set` properties.  `base` is the enclosing
 * topic's `fr_kafka_topic_conf_t`, handed down by the subsection hook.
 */
int kafka_topic_config_raw_parse(UNUSED TALLOC_CTX *ctx, UNUSED void *out, void *base,
				 CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	CONF_PAIR		*cp = cf_item_to_pair(ci);
	fr_kafka_topic_conf_t	*ktc = base;
	char			errstr[512];

	fr_assert_msg(ktc, "kafka topic conf missing - raw parser invoked without subsection hook");

	if (rd_kafka_topic_conf_set(ktc->rdtc, cf_pair_attr(cp), cf_pair_value(cp),
				    errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
		cf_log_perr(cp, "%s", errstr);
		return -1;
	}
	return 0;
}

/** Order-by-name comparator for the `fr_kafka_conf_t.topics` tree. */
static int8_t _kafka_topic_cmp(void const *one, void const *two)
{
	fr_kafka_topic_t const	*a = one;
	fr_kafka_topic_t const	*b = two;
	return CMP(strcmp(a->name, b->name), 0);
}

fr_kafka_topic_t *kafka_topic_conf_find(fr_kafka_conf_t const *kc, char const *name)
{
	fr_kafka_topic_t	key;

	if (!kc || !kc->topics || !name) return NULL;
	key.name = name;
	return fr_rb_find(kc->topics, &key);
}

/** Per-topic subsection hook.  Runs the inner rules against the topic's
 *  section, then inserts a record into the parent's topics tree.
 *
 * Invoked by the framework for each `<name> { ... }` inside `topic { }`.
 * `ci` is the topic's CONF_SECTION, `base` points at the caller's instance
 * struct (with `fr_kafka_conf_t` as its first member).
 */
int kafka_topic_subsection_parse(TALLOC_CTX *ctx, void *out, void *base,
				 CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	CONF_SECTION		*subcs = cf_item_to_section(ci);
	fr_kafka_conf_t		*kc;
	fr_kafka_topic_t	*topic;
	char const		*name = cf_section_name1(subcs);

	fr_assert_msg(base, "kafka base struct missing");

	kc = kafka_conf_get(ctx, base);
	if (!kc->topics) {
		MEM(kc->topics = fr_rb_inline_talloc_alloc(ctx, fr_kafka_topic_t, node, _kafka_topic_cmp, NULL));
	}

	/*
	 *	Allocate eagerly so the inner parsers can write into
	 *	topic->conf via `base` instead of round-tripping through
	 *	cf_data.
	 */
	MEM(topic = talloc_zero(kc->topics, fr_kafka_topic_t));
	topic->name = talloc_strdup(topic, name);
	topic->conf = kafka_topic_conf_alloc(topic);
	topic->cs = subcs;

	/*
	 *	Inner rules (acks, compression, properties, ...) have been
	 *	pushed on the subsection by the framework.  Run them with
	 *	topic->conf as base so they write directly into our struct.
	 */
	if (cf_section_parse(ctx, topic->conf, subcs) < 0) {
		talloc_free(topic);
		return -1;
	}

	if (!fr_rb_insert(kc->topics, topic)) {
		cf_log_err(ci, "Duplicate kafka topic '%s'", name);
		talloc_free(topic);
		return -1;
	}

	/*
	 *	If the caller wired an output target on the subsection
	 *	rule, hand back the topic pointer so it lands in their
	 *	array.  The tree on kc->topics is the primary index;
	 *	this is just a convenience for direct-access patterns.
	 */
	if (out) *((fr_kafka_topic_t **)out) = topic;

	return 0;
}
/** @} */

/** @name `conf_parser_t` arrays
 *
 * Nested subsections referenced by the `KAFKA_BASE_CONFIG` /
 * `KAFKA_PRODUCER_CONFIG` / `KAFKA_CONSUMER_CONFIG` macros in base.h.
 * Base-level surfaces first, then producer-specific, then consumer.
 *
 * @{
 */

/** `properties { ... }` escape-hatch contents
 *
 * Accepts any `key = value` pair and hands it straight to
 * `rd_kafka_conf_set`.  See `kafka_config_raw_parse`.
 */
conf_parser_t const kafka_base_properties_config[] = {
	{ .name1 = CF_IDENT_ANY, .func = kafka_config_raw_parse },
	CONF_PARSER_TERMINATOR
};

/** Per-topic `properties { ... }` escape-hatch contents
 *
 * Same idea as `kafka_base_properties_config`, but dispatches to
 * `rd_kafka_topic_conf_set` against the enclosing topic's conf.
 */
conf_parser_t const kafka_base_topic_properties_config[] = {
	{ .name1 = CF_IDENT_ANY, .func = kafka_topic_config_raw_parse },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t const kafka_sasl_oauth_config[] = {
	{ FR_CONF_PAIR_GLOBAL("oauthbearer_conf", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.oauthbearer.config", .empty_default = true }},

	{ FR_CONF_PAIR_GLOBAL("unsecure_jwt", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.sasl.oauthbearer.unsecure.jwt" }},

	CONF_PARSER_TERMINATOR
};

static conf_parser_t const kafka_sasl_kerberos_config[] = {
	/*
	 *	Service principal
	 */
	{ FR_CONF_PAIR_GLOBAL("service_name", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.kerberos.service.name" }},

	/*
	 *	Principal
	 */
	{ FR_CONF_PAIR_GLOBAL("principal", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.kerberos.principal" }},

	/*
	 *	knit cmd
	 */
	{ FR_CONF_PAIR_GLOBAL("kinit_cmd", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.kerberos.kinit.cmd" }},

	/*
	 *	keytab
	 */
	{ FR_CONF_PAIR_GLOBAL("keytab", FR_TYPE_STRING, CONF_FLAG_FILE_READABLE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.kerberos.kinit.keytab", .empty_default = true }},

	/*
	 *	How long between key refreshes
	 */
	{ FR_CONF_PAIR_GLOBAL("refresh_delay", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.kerberos.min.time.before.relogin" }},

	CONF_PARSER_TERMINATOR
};

conf_parser_t const kafka_sasl_config[] = {
	/*
	 *	SASL mechanism
	 */
	{ FR_CONF_PAIR_GLOBAL("mech", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.mechanism" }},

	/*
	 *	Static SASL username
	 */
	{ FR_CONF_PAIR_GLOBAL("username", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.username", .empty_default = true }},

	/*
	 *	Static SASL password
	 */
	{ FR_CONF_PAIR_GLOBAL("password", FR_TYPE_STRING, CONF_FLAG_SECRET, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.password", .empty_default = true }},

	{ FR_CONF_SUBSECTION_GLOBAL("kerberos", 0, kafka_sasl_kerberos_config) },

	{ FR_CONF_SUBSECTION_GLOBAL("oauth", 0, kafka_sasl_oauth_config) },

	CONF_PARSER_TERMINATOR
};

static fr_table_ptr_sorted_t kafka_check_cert_cn_table[] = {
	{ L("false"),	"none"	},
	{ L("no"),	"none"	},
	{ L("true"),	"https"	},
	{ L("yes"),	"https"	}
};
static size_t kafka_check_cert_cn_table_len = NUM_ELEMENTS(kafka_check_cert_cn_table);

conf_parser_t const kafka_tls_config[] = {
	/*
	 *	Cipher suite list in OpenSSL's format
	 */
	{ FR_CONF_PAIR_GLOBAL("cipher_list", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.cipher.suites", .empty_default = true }},

	/*
	 *	Curves list in OpenSSL's format
	 */
	{ FR_CONF_PAIR_GLOBAL("curve_list", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.curves.list", .empty_default = true }},

	/*
	 *	Curves list in OpenSSL's format
	 */
	{ FR_CONF_PAIR_GLOBAL("sigalg_list", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.sigalgs.list", .empty_default = true }},

	/*
	 *	Sets the full path to a CA certificate (used to validate
	 *	the certificate the server presents).
	 */
	{ FR_CONF_PAIR_GLOBAL("ca_file", FR_TYPE_STRING, CONF_FLAG_FILE_READABLE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.ca.location", .empty_default = true }},

	/*
	 *	Location of the CRL file.
	 */
	{ FR_CONF_PAIR_GLOBAL("crl_file", FR_TYPE_STRING, CONF_FLAG_FILE_READABLE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.crl.location", .empty_default = true }},

	/*
	 *	Sets the path to the public certificate file we present
	 *	to the servers.
	 */
	{ FR_CONF_PAIR_GLOBAL("certificate_file", FR_TYPE_STRING, CONF_FLAG_FILE_READABLE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.certificate.location", .empty_default = true }},

	/*
	 *	Sets the path to the private key for our public
	 *	certificate.
	 */
	{ FR_CONF_PAIR_GLOBAL("private_key_file", FR_TYPE_STRING, CONF_FLAG_FILE_READABLE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.key.location", .empty_default = true }},

	/*
	 *	Enable or disable certificate validation
	 */
	{ FR_CONF_PAIR_GLOBAL("require_cert", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.ssl.certificate.verification" }},

	{ FR_CONF_PAIR_GLOBAL("check_cert_cn", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.endpoint.identification.algorithm",
	  				  .mapping = kafka_check_cert_cn_table,
	  				  .mapping_len = &kafka_check_cert_cn_table_len }},
	CONF_PARSER_TERMINATOR
};

conf_parser_t const kafka_connection_config[] = {
	/*
	 *	Socket timeout
	 */
	{ FR_CONF_PAIR_GLOBAL("timeout", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.timeout.ms" }},

	/*
	 *	Close broker connections after this period.
	 */
	{ FR_CONF_PAIR_GLOBAL("idle_timeout", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "connections.max.idle.ms" }},

	/*
	 *	Maximum requests in flight (per connection).
	 */
	{ FR_CONF_PAIR_GLOBAL("max_requests_in_flight", FR_TYPE_UINT64, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "max.in.flight.requests.per.connection" }},

	/*
	 *	Socket send buffer.
	 */
	{ FR_CONF_PAIR_GLOBAL("send_buff", FR_TYPE_UINT64, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.send.buffer.bytes" }},

	/*
	 *	Socket recv buffer.
	 */
	{ FR_CONF_PAIR_GLOBAL("recv_buff", FR_TYPE_UINT64, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.receive.buffer.bytes" }},

	/*
	 *	If true, send TCP keepalives
	 */
	{ FR_CONF_PAIR_GLOBAL("keepalive", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.keepalive.enable" }},

	/*
	 *	If true, disable nagle algorithm
	 */
	{ FR_CONF_PAIR_GLOBAL("nodelay", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.nagle.disable" }},

	/*
	 *	How long the DNS resolver cache is valid for
	 */
	{ FR_CONF_PAIR_GLOBAL("resolver_cache_ttl", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "broker.address.ttl" }},

	/*
	 *	Should we use A records, AAAA records or either
	 *	when resolving broker addresses
	 */
	{ FR_CONF_PAIR_GLOBAL("resolver_addr_family", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "broker.address.family" }},

	/*
	 *	How many failures before we reconnect the connection
	 */
	{ FR_CONF_PAIR_GLOBAL("reconnection_failure_count", FR_TYPE_UINT32, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.max.fails" }},

	/*
	 *	Initial time to wait before reconnecting.
	 */
	{ FR_CONF_PAIR_GLOBAL("reconnection_delay_initial", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "reconnect.backoff.ms" }},

	/*
	 *	Max time to wait before reconnecting.
	 */
	{ FR_CONF_PAIR_GLOBAL("reconnection_delay_max", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "reconnect.backoff.max.ms" }},

	CONF_PARSER_TERMINATOR
};

conf_parser_t const kafka_version_config[] = {
	/*
	 *	Request the API version from connected brokers
	 */
	{ FR_CONF_PAIR_GLOBAL("request", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "api.version.request" }},

	/*
	 *	How long to wait for a version response.
	 */
	{ FR_CONF_PAIR_GLOBAL("timeout", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "api.version.request.timeout.ms" }},

	/*
	 *	How long to wait before retrying a version request.
	 */
	{ FR_CONF_PAIR_GLOBAL("retry_delay", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "api.version.fallback.ms" }},

	/*
	 *	Default version to use if the version request fails.
	 */
	{ FR_CONF_PAIR_GLOBAL("default", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "broker.version.fallback" }},

	CONF_PARSER_TERMINATOR
};

conf_parser_t const kafka_metadata_config[] = {
	/*
	 *	Interval between attempts to refresh metadata from brokers
	 */
	{ FR_CONF_PAIR_GLOBAL("refresh_interval", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "topic.metadata.refresh.interval.ms" }},

	/*
	 *	Interval between attempts to refresh metadata from brokers
	 */
	{ FR_CONF_PAIR_GLOBAL("max_age", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "metadata.max.age.ms" }},

	/*
	 *	 Used when a topic loses its leader
	 */
	{ FR_CONF_PAIR_GLOBAL("fast_refresh_interval", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "topic.metadata.refresh.fast.interval.ms" }},

	/*
	 *	 Used when a topic loses its leader to prevent spurious metadata changes
	 */
	{ FR_CONF_PAIR_GLOBAL("max_propagation", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "topic.metadata.propagation.max.ms" }},

	/*
	 *	Use sparse metadata requests which use less bandwidth maps
	 */
	{ FR_CONF_PAIR_GLOBAL("refresh_sparse", FR_TYPE_BOOL, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "topic.metadata.refresh.sparse" }},

	/*
	 *	List of topics to ignore
	 */
	{ FR_CONF_PAIR_GLOBAL("blacklist", FR_TYPE_STRING, CONF_FLAG_MULTI, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "topic.blacklist", .string_sep = ",", .empty_default = true }},

	CONF_PARSER_TERMINATOR
};

/** @name Producer-specific topic config
 * @{
 */

static conf_parser_t const kafka_base_producer_topic_config[] = {
	/*
	 *	Payload and key templates for `kafka.produce.<topic>`
	 *	invocations.  Parsed at call_env time, but we reserve
	 *	the names here so the raw-passthrough catch-all below
	 *	doesn't try to hand them to rd_kafka_topic_conf_set.
	 */
	{ FR_CONF_PAIR_GLOBAL("value", FR_TYPE_STRING, 0, kafka_noop_parse, NULL) },
	{ FR_CONF_PAIR_GLOBAL("key", FR_TYPE_STRING, 0, kafka_noop_parse, NULL) },

	/*
	 *	This field indicates the number of acknowledgements the leader
	 *	broker must receive from ISR brokers before responding to the request.
	 */
	{ FR_CONF_PAIR_GLOBAL("request_required_acks", FR_TYPE_INT16, 0, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "request.required.acks" }},

	/*
	 *	medium	The ack timeout of the producer request in milliseconds
	 */
	{ FR_CONF_PAIR_GLOBAL("request_timeout", FR_TYPE_TIME_DELTA, 0, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "request.timeout.ms" }},

	/*
	 *	Local message timeout
	 */
	{ FR_CONF_PAIR_GLOBAL("message_timeout", FR_TYPE_TIME_DELTA, 0, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "message.timeout.ms" }},

	/*
	 *	Partitioning strategy
	 */
	{ FR_CONF_PAIR_GLOBAL("partitioner", FR_TYPE_STRING, 0, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "partitioner" }},

	/*
	 *	compression codec to use for compressing message sets.
	 */
	{ FR_CONF_PAIR_GLOBAL("compression_type", FR_TYPE_STRING, 0, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "compression.type" }},

	/*
	 *	compression level to use
	 */
	{ FR_CONF_PAIR_GLOBAL("compression_level", FR_TYPE_INT8, 0, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "compression.level" }},

	/*
	 *	Escape hatch for rd_kafka_topic_conf_set properties not
	 *	covered above.  Same shape as the top-level properties
	 *	block but writes to the per-topic conf.
	 */
	{ FR_CONF_SUBSECTION_GLOBAL("properties", 0, kafka_base_topic_properties_config) },

	CONF_PARSER_TERMINATOR
};

/*
 * Allows topic configurations in the format:
 *
 * topic {
 *   <name> {
 *     request_required_acks = ...
 *   }
 * }
 *
 */
conf_parser_t const kafka_base_producer_topics_config[] = {
	{ FR_CONF_SUBSECTION_GLOBAL(CF_IDENT_ANY, CONF_FLAG_MULTI, kafka_base_producer_topic_config),
	  .subcs_size = sizeof(fr_kafka_topic_conf_t), .subcs_type = "fr_kafka_topic_conf_t",
	  .func = kafka_topic_subsection_parse },

	CONF_PARSER_TERMINATOR
};

/* The producer config now lives entirely in the `KAFKA_PRODUCER_CONFIG`
 * macro in base.h so callers can compose it with their own config entries.
 * See that macro for the full set of librdkafka pass-through properties. */

/** @} */

/** @name Consumer-specific topic + group config
 * @{
 */

conf_parser_t const kafka_consumer_group_config[] = {
	/*
	 *	Group consumer is a member of
	 */
	{ FR_CONF_PAIR_GLOBAL("id", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "group.id" }},

	/*
	 *	A unique identifier of the consumer instance provided by the end user
	 */
	{ FR_CONF_PAIR_GLOBAL("instance_id", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "group.instance.id" }},

	/*
	 *	Range or roundrobin
	 */
	{ FR_CONF_PAIR_GLOBAL("partition_assignment_strategy", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "partition.assignment.strategy" }},

	/*
	 *	Client group session and failure detection timeout.
	 */
	{ FR_CONF_PAIR_GLOBAL("session_timeout", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "session.timeout.ms" }},

	/*
	 *	Group session keepalive heartbeat interval.
	 */
	{ FR_CONF_PAIR_GLOBAL("heartbeat_interval", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "heartbeat.interval.ms" }},

	/*
	 *	How often to query for the current client group coordinator
	 */
	{ FR_CONF_PAIR_GLOBAL("coordinator_query_interval", FR_TYPE_TIME_DELTA, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "coordinator.query.interval.ms" }},


	CONF_PARSER_TERMINATOR
};

conf_parser_t const kafka_base_consumer_topic_config[] = {
	/*
	 *	How many messages we process at a time
	 *
	 *	High numbers may starve the worker thread
	 */
	{ FR_CONF_PAIR_GLOBAL("max_messages_per_cycle", FR_TYPE_UINT32, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "consume.callback.max.messages" }},

	/*
	 *	Action to take when there is no initial offset
	 *	in offset store or the desired offset is out of range.
	 */
	{ FR_CONF_PAIR_GLOBAL("auto_offset_reset", FR_TYPE_STRING, 0, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "auto.offset.reset" }},

	/*
	 *	Escape hatch for rd_kafka_topic_conf_set properties not
	 *	covered above.
	 */
	{ FR_CONF_SUBSECTION_GLOBAL("properties", 0, kafka_base_topic_properties_config) },

	CONF_PARSER_TERMINATOR
};

/*
 * Allows topic configurations in the format:
 *
 * topic {
 *   <name> {
 *     request_required_acks = ...
 *   }
 * }
 *
 */
conf_parser_t const kafka_base_consumer_topics_config[] = {
	{ FR_CONF_SUBSECTION_GLOBAL(CF_IDENT_ANY, CONF_FLAG_MULTI, kafka_base_consumer_topic_config),
	  .subcs_size = sizeof(fr_kafka_topic_conf_t), .subcs_type = "fr_kafka_topic_conf_t",
	  .func = kafka_topic_subsection_parse },

	CONF_PARSER_TERMINATOR
};

/* The consumer config now lives in the `KAFKA_CONSUMER_CONFIG` macro in
 * base.h so callers can compose it with their own entries. */

/** @} */

/** @name Library init
 *
 * librdkafka defers SSL / SASL / internal-refcount setup until the first
 * `rd_kafka_new()`.  Doing that lazily in a worker thread races the
 * server's own OpenSSL init and leaves the ordering non-deterministic,
 * so we kick it once at module load via `fr_kafka_init()`.  The counter
 * mirrors `fr_openssl_init()` in src/lib/tls/base.c.
 *
 * @{
 */
static uint32_t kafka_instance_count = 0;

static void _kafka_null_log_cb(UNUSED rd_kafka_t const *rk, UNUSED int level,
			       UNUSED char const *fac, UNUSED char const *buf)
{
	/* swallow the "no bootstrap brokers" warning from the dummy producer */
}

/** Drive librdkafka's lazy global init deterministically
 *
 * First call creates and immediately destroys a throwaway producer, which
 * walks all of librdkafka's one-shot init paths (SSL lock callbacks on
 * OpenSSL 1.0.2, SASL global init if compiled in, etc.).  Subsequent
 * calls just bump the refcount so multiple kafka-using modules can share
 * the init.
 */
int fr_kafka_init(void)
{
	rd_kafka_conf_t *conf;
	rd_kafka_t	*rk;
	char		errstr[512];

	if (kafka_instance_count > 0) {
		kafka_instance_count++;
		return 0;
	}

	conf = rd_kafka_conf_new();
	rd_kafka_conf_set_log_cb(conf, _kafka_null_log_cb);

	rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if (!rk) {
		fr_strerror_printf("Failed priming librdkafka globals: %s", errstr);
		return -1;
	}
	rd_kafka_destroy(rk);

	kafka_instance_count++;
	return 0;
}

/** Drop one ref to librdkafka's global init
 *
 * librdkafka refcounts its own globals internally; our counter just
 * pairs fr_kafka_init() calls so re-entrant module load/unload in test
 * harnesses does the right thing.
 */
void fr_kafka_free(void)
{
	if (kafka_instance_count == 0) return;
	kafka_instance_count--;
}

/** @} */
/** @} */
