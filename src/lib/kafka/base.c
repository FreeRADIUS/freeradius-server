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
 * @file kafka/base.c
 * @brief Kafka global structures
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include <freeradius-devel/kafka/base.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/size.h>

typedef struct {
	rd_kafka_conf_t		*conf;
} fr_kafka_conf_t;

typedef struct {
	rd_kafka_topic_conf_t	*conf;
} fr_kafka_topic_conf_t;

typedef struct {
	fr_table_ptr_sorted_t	*mapping;		//!< Mapping table between string constant.

	size_t			*mapping_len;		//!< Length of the mapping tables

	bool			empty_default;		//!< Don't produce messages saying the default is missing.

	size_t			size_scale;		//!< Divide/multiply FR_TYPE_SIZE by this amount.

	char const		*property;		//!< Kafka configuration property.

	char const		*string_sep;		//!< Used for multi-value configuration items.
							//!< Kafka uses ', ' or ';' seemingly at random.
} fr_kafka_conf_ctx_t;

/** Destroy a kafka configuration handle
 *
 * @param[in] kc	To destroy.
 * @return 0
 */
static int _kafka_conf_free(fr_kafka_conf_t *kc)
{
	rd_kafka_conf_destroy(kc->conf);
	return 0;
}

static inline CC_HINT(always_inline)
fr_kafka_conf_t *kafka_conf_from_cs(CONF_SECTION *cs)
{
	CONF_DATA const	*cd;
	fr_kafka_conf_t	*kc;

	cd = cf_data_find(cs, fr_kafka_conf_t, "conf");
	if (cd) {
		kc = cf_data_value(cd);
	} else {
		MEM(kc = talloc(NULL, fr_kafka_conf_t));
		MEM(kc->conf = rd_kafka_conf_new());
		talloc_set_destructor(kc, _kafka_conf_free);
		cf_data_add(cs, kc, "conf", true);
	}

	return kc;
}

/** Destroy a kafka topic configuration handle
 *
 * @param[in] ktc	To destroy.
 * @return 0
 */
static int _kafka_topic_conf_free(fr_kafka_topic_conf_t *ktc)
{
	rd_kafka_topic_conf_destroy(ktc->conf);
	return 0;
}

static inline CC_HINT(always_inline)
fr_kafka_topic_conf_t *kafka_topic_conf_from_cs(CONF_SECTION *cs)
{
	CONF_DATA const		*cd;
	fr_kafka_topic_conf_t	*ktc;

	cd = cf_data_find(cs, fr_kafka_topic_conf_t, "conf");
	if (cd) {
		ktc = cf_data_value(cd);
	} else {
		MEM(ktc = talloc(NULL, fr_kafka_topic_conf_t));
		MEM(ktc->conf = rd_kafka_topic_conf_new());
		talloc_set_destructor(ktc, _kafka_topic_conf_free);
		cf_data_add(cs, ktc, "conf", true);
	}

	return ktc;
}

/** Perform any conversions necessary to map kafka defaults to our values
 *
 * @param[out] out	Where to write the pair.
 * @param[in] cs	to allocate the pair in.
 * @param[in] value	to convert.
 * @param[in] quote	to use when allocing the pair.
 * @param[in] rule	UNUSED.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
static int kafka_config_dflt_single(CONF_PAIR **out, CONF_SECTION *cs, char const *value,
				    fr_token_t quote, CONF_PARSER const *rule)
{
	char				tmp[sizeof("18446744073709551615b")];
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	fr_type_t			type = FR_BASE_TYPE(rule->type);

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

		if (fr_size_from_str(&size, &FR_SBUFF_IN(value, strlen(value))) < 0) {
			cf_log_perr(cs, "Failed parsing default \"%s\"", value);
			return -1;
		}

		/*
		 *	Some options are in kbytes *sigh*
		 */
		if (kctx->size_scale) size *= kctx->size_scale;

		fr_size_to_str(&value_elem, size);	/* reprint the size with an appropriate unit */
		value = fr_sbuff_start(&value_elem);
	}
		break;

	default:
		break;
	}

	MEM(*out = cf_pair_alloc(cs, rule->name, value, T_OP_EQ, T_BARE_WORD, quote));
	cf_pair_mark_parsed(*out);	/* Don't re-parse this */

	return 0;
}

/** Return the default value from the kafka client library
 *
 * @param[out] out	Where to write the pair.
 * @param[in] cs	to allocate the pair in.
 * @param[in] quote	to use when allocing the pair.
 * @param[in] rule	UNUSED.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
static int kafka_config_dflt(CONF_PAIR **out, CONF_SECTION *cs, fr_token_t quote, CONF_PARSER const *rule)
{
	char				buff[1024];
	size_t				buff_len = sizeof(buff);
	char const			*value;

	fr_kafka_conf_t 		*kc;
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	rd_kafka_conf_res_t 		ret;

	kc = kafka_conf_from_cs(cs);
	fr_assert(kc);

	if ((ret = rd_kafka_conf_get(kc->conf, kctx->property, buff, &buff_len)) != RD_KAFKA_CONF_OK) {
		if (ret == RD_KAFKA_CONF_UNKNOWN) {
			if (kctx->empty_default) return 0;

			cf_log_debug(cs, "No default available for \"%s\" - \"%s\"", rule->name, kctx->property);
			return 0;	/* Not an error */
		}

		cf_log_err(cs, "Failed retrieving kafka property \"%s\"", kctx->property);
		return -1;
	}
#if 0
	cf_log_debug(cs, "Retrieved dflt \"%s\" for \"%s\" - \"%s\"", buff, rule->name, kctx->property);
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
		fr_sbuff_term_t			tt = FR_SBUFF_TERM(kctx->string_sep);
		fr_sbuff_unescape_rules_t	ue_rules = {
							.name = __FUNCTION__,
							.chr = '\\'
						};
		/*
		 *	Convert escaped separators back
		 */
		ue_rules.subs[(uint8_t)kctx->string_sep[0]] = kctx->string_sep[0];

		while (fr_sbuff_out_unescape_until(&value_elem, &value_in, SIZE_MAX, &tt, &ue_rules) > 0) {
			if (kafka_config_dflt_single(out, cs, fr_sbuff_start(&value_elem), quote, rule) < 0) return -1;

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
	if (kafka_config_dflt_single(out, cs, value, quote, rule) < 0) return -1;

	return 0;
}

/** Return the default value for a topic from the kafka client library
 *
 * @param[out] out	Where to write the pair.
 * @param[in] cs	to allocate the pair in.
 * @param[in] quote	to use when allocing the pair.
 * @param[in] rule	UNUSED.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
static int kafka_topic_config_dflt(CONF_PAIR **out, CONF_SECTION *cs, fr_token_t quote, CONF_PARSER const *rule)
{
	char				buff[1024];
	size_t				buff_len = sizeof(buff);
	char const			*value;

	fr_kafka_topic_conf_t 		*ktc;
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	rd_kafka_conf_res_t 		ret;

	ktc = kafka_topic_conf_from_cs(cs);
	fr_assert(ktc);

	if ((ret = rd_kafka_topic_conf_get(ktc->conf, kctx->property, buff, &buff_len)) != RD_KAFKA_CONF_OK) {
		if (ret == RD_KAFKA_CONF_UNKNOWN) {
			if (kctx->empty_default) return 0;

			cf_log_debug(cs, "No default available for \"%s\" - \"%s\"", rule->name, kctx->property);
			return 0;	/* Not an error */
		}

		fr_assert(ret == RD_KAFKA_CONF_UNKNOWN);
		cf_log_err(cs, "Failed retrieving kafka property '%s'", kctx->property);
		return -1;
	}
#if 0
	cf_log_debug(cs, "Retrieved dflt \"%s\" for \"%s\" - \"%s\"", buff, rule->name, kctx->property);
#endif
	value = buff;

	/*
	 *	Parse a single value
	 */
	if (kafka_config_dflt_single(out, cs, value, quote, rule) < 0) return -1;

	return 0;
}

static int kafka_config_parse_single(char const **out, CONF_PAIR *cp, CONF_PARSER const *rule)
{
	fr_value_box_t			vb;
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	fr_type_t			type = FR_BASE_TYPE(rule->type);
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

		sbuff = FR_SBUFF_IN(buff, sizeof(buff));
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

		sbuff = FR_SBUFF_IN(buff, sizeof(buff));

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
static int kafka_config_parse(TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *base,
			      CONF_ITEM *ci, CONF_PARSER const *rule)
{
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	CONF_ITEM			*parent = cf_parent(ci);
	CONF_SECTION			*cs = cf_item_to_section(parent);
	CONF_PAIR			*cp = cf_item_to_pair(ci);

	fr_kafka_conf_t 		*kc;
	char const			*value;

	kc = kafka_conf_from_cs(cf_item_to_section(parent));

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

		count = cf_pair_count(cs,  rule->name);
		if (count <= 1) goto do_single;

		MEM(array = talloc_array(ctx, char const *, count));
		for (cp_p = cp, i = 0;
		     cp_p;
		     cp_p = cf_pair_find_next(cs, cp_p, rule->name), i++) {
			if (kafka_config_parse_single(&array[i], cp_p, rule) < 0) return -1;
			cf_pair_mark_parsed(cp_p);
		}

		slen = talloc_array_concat(agg, array, kctx->string_sep);
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


/** Translate config items directly to settings in a kafka topic config struct
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
static int kafka_topic_config_parse(UNUSED TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *base,
				    CONF_ITEM *ci, CONF_PARSER const *rule)
{
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	CONF_ITEM			*parent = cf_parent(ci);
	CONF_PAIR			*cp = cf_item_to_pair(ci);

	fr_kafka_topic_conf_t 		*ktc;
	char const			*value;

	ktc = kafka_topic_conf_from_cs(cf_item_to_section(parent));
	if (kafka_config_parse_single(&value, cp, rule) < 0) return -1;

	{
		char errstr[512];

		if (rd_kafka_topic_conf_set(ktc->conf, kctx->property,
					    value, errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
			cf_log_perr(cp, "%s", errstr);
			return -1;
		}
	}

	return 0;
}

#if 0
/** Configure a new topic for production or consumption
 *
 */
static int kafka_topic_new(UNUSED TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *base,
			   CONF_ITEM *ci, CONF_PARSER const *rule)
{
	fr_kafka_conf_ctx_t const	*kctx = rule->uctx;
	CONF_ITEM			*parent = cf_parent(ci);
	CONF_PAIR			*cp = cf_item_to_pair(ci);

	fr_kafka_topic_conf_t 		*ktc;
	char const			*value;

	ktc = kafka_topic_conf_from_cs(cf_item_to_section(parent));

	rd_kafka_topic_new (rd_kafka_t *rk, const char *topic, rd_kafka_topic_conf_t *conf)
}
#endif

static CONF_PARSER const kafka_sasl_oauth_config[] = {
	{ FR_CONF_FUNC("oauthbearer_conf", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.oauthbearer.config", .empty_default = true }},

	{ FR_CONF_FUNC("unsecure_jwt", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.sasl.oauthbearer.unsecure.jwt" }},

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const kafka_sasl_kerberos_config[] = {
	/*
	 *	Service principal
	 */
	{ FR_CONF_FUNC("service_name", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.kerberos.service.name" }},

	/*
	 *	Principal
	 */
	{ FR_CONF_FUNC("principal", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.kerberos.principal" }},

	/*
	 *	knit cmd
	 */
	{ FR_CONF_FUNC("kinit_cmd", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.kerberos.kinit.cmd" }},

	/*
	 *	keytab
	 */
	{ FR_CONF_FUNC("keytab", FR_TYPE_STRING | FR_TYPE_FILE_INPUT, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.kerberos.kinit.keytab", .empty_default = true }},

	/*
	 *	How long between key refreshes
	 */
	{ FR_CONF_FUNC("refresh_delay", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.kerberos.min.time.before.relogin" }},

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const kafka_sasl_config[] = {
	/*
	 *	SASL mechanism
	 */
	{ FR_CONF_FUNC("mech", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.mechanism" }},

	/*
	 *	Static SASL username
	 */
	{ FR_CONF_FUNC("username", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sasl.username", .empty_default = true }},

	/*
	 *	Static SASL password
	 */
	{ FR_CONF_FUNC("password", FR_TYPE_STRING | FR_TYPE_SECRET, kafka_config_parse, kafka_config_dflt),
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

static CONF_PARSER const kafka_tls_config[] = {
	/*
	 *	Cipher suite list in OpenSSL's format
	 */
	{ FR_CONF_FUNC("cipher_list", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.cipher.suites", .empty_default = true }},

	/*
	 *	Curves list in OpenSSL's format
	 */
	{ FR_CONF_FUNC("curve_list", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.curves.list", .empty_default = true }},

	/*
	 *	Curves list in OpenSSL's format
	 */
	{ FR_CONF_FUNC("sigalg_list", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.sigalgs.list", .empty_default = true }},

	/*
	 *	Sets the full path to a CA certificate (used to validate
	 *	the certificate the server presents).
	 */
	{ FR_CONF_FUNC("ca_file", FR_TYPE_STRING | FR_TYPE_FILE_INPUT, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.ca.location", .empty_default = true }},

	/*
	 *	Location of the CRL file.
	 */
	{ FR_CONF_FUNC("crl_file", FR_TYPE_STRING | FR_TYPE_FILE_INPUT, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.crl.location", .empty_default = true }},

	/*
	 *	Sets the path to the public certificate file we present
	 *	to the servers.
	 */
	{ FR_CONF_FUNC("certificate_file", FR_TYPE_STRING | FR_TYPE_FILE_INPUT, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.certificate.location", .empty_default = true }},

	/*
	 *	Sets the path to the private key for our public
	 *	certificate.
	 */
	{ FR_CONF_FUNC("private_key_file", FR_TYPE_STRING | FR_TYPE_FILE_INPUT, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.key.location", .empty_default = true }},

	/*
	 *	Enable or disable certificate validation
	 */
	{ FR_CONF_FUNC("require_cert", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.ssl.certificate.verification" }},

	{ FR_CONF_FUNC("check_cert_cn", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "ssl.endpoint.identification.algorithm",
	  				  .mapping = kafka_check_cert_cn_table,
	  				  .mapping_len = &kafka_check_cert_cn_table_len }},
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const kafka_connection_config[] = {
	/*
	 *	Socket timeout
	 */
	{ FR_CONF_FUNC("timeout", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.timeout.ms" }},

	/*
	 *	Close broker connections after this period.
	 */
	{ FR_CONF_FUNC("idle_timeout", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "connections.max.idle.ms" }},

	/*
	 *	Maximum requests in flight (per connection).
	 */
	{ FR_CONF_FUNC("max_requests_in_flight", FR_TYPE_UINT64, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "max.in.flight.requests.per.connection" }},

	/*
	 *	Socket send buffer.
	 */
	{ FR_CONF_FUNC("send_buff", FR_TYPE_UINT64, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.send.buffer.bytes" }},

	/*
	 *	Socket recv buffer.
	 */
	{ FR_CONF_FUNC("recv_buff", FR_TYPE_UINT64, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.receive.buffer.bytes" }},

	/*
	 *	If true, send TCP keepalives
	 */
	{ FR_CONF_FUNC("keepalive", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.keepalive.enable" }},

	/*
	 *	If true, disable nagle algorithm
	 */
	{ FR_CONF_FUNC("nodelay", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.nagle.disable" }},

	/*
	 *	How long the DNS resolver cache is valid for
	 */
	{ FR_CONF_FUNC("resolver_cache_ttl", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "broker.address.ttl" }},

	/*
	 *	Should we use A records, AAAA records or either
	 *	when resolving broker addresses
	 */
	{ FR_CONF_FUNC("resolver_addr_family", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "broker.address.family" }},

	/*
	 *	How many failures before we reconnect the connection
	 */
	{ FR_CONF_FUNC("reconnection_failure_count", FR_TYPE_UINT32, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "socket.max.fails" }},

	/*
	 *	Initial time to wait before reconnecting.
	 */
	{ FR_CONF_FUNC("reconnection_delay_initial", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "reconnect.backoff.ms" }},

	/*
	 *	Max time to wait before reconnecting.
	 */
	{ FR_CONF_FUNC("reconnection_delay_max", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "reconnect.backoff.max.ms" }},

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const kafka_version_config[] = {
	/*
	 *	Request the API version from connected brokers
	 */
	{ FR_CONF_FUNC("request", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "api.version.request" }},

	/*
	 *	How long to wait for a version response.
	 */
	{ FR_CONF_FUNC("timeout", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "api.version.request.timeout.ms" }},

	/*
	 *	How long to wait before retrying a version request.
	 */
	{ FR_CONF_FUNC("retry_delay", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "api.version.fallback.ms" }},

	/*
	 *	Default version to use if the version request fails.
	 */
	{ FR_CONF_FUNC("default", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "broker.version.fallback" }},

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const kafka_metadata_config[] = {
	/*
	 *	Interval between attempts to refresh metadata from brokers
	 */
	{ FR_CONF_FUNC("refresh_interval", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "topic.metadata.refresh.interval.ms" }},

	/*
	 *	Interval between attempts to refresh metadata from brokers
	 */
	{ FR_CONF_FUNC("max_age", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "metadata.max.age.ms" }},

	/*
	 *	 Used when a topic loses its leader
	 */
	{ FR_CONF_FUNC("fast_refresh_interval", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "topic.metadata.refresh.fast.interval.ms" }},

	/*
	 *	 Used when a topic loses its leader to prevent spurious metadata changes
	 */
	{ FR_CONF_FUNC("max_propagation", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "topic.metadata.propagation.max.ms" }},

	/*
	 *	Use sparse metadata requests which use less bandwidth maps
	 */
	{ FR_CONF_FUNC("refresh_sparse", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "topic.metadata.refresh.sparse" }},

	/*
	 *	List of topics to ignore
	 */
	{ FR_CONF_FUNC("blacklist", FR_TYPE_STRING | FR_TYPE_MULTI, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "topic.blacklist", .string_sep = ",", .empty_default = true }},

	CONF_PARSER_TERMINATOR
};

#define BASE_CONFIG \
	{ FR_CONF_FUNC("server", FR_TYPE_STRING | FR_TYPE_REQUIRED | FR_TYPE_MULTI, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "metadata.broker.list", .string_sep = "," }}, \
	{ FR_CONF_FUNC("client_id", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "client.id" }}, \
	{ FR_CONF_FUNC("rack_id", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "client.rack" }}, \
	{ FR_CONF_FUNC("request_max_size", FR_TYPE_SIZE, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "message.max.bytes" }}, \
	{ FR_CONF_FUNC("request_copy_max_size", FR_TYPE_SIZE, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "message.copy.max.bytes" }}, \
	{ FR_CONF_FUNC("response_max_size", FR_TYPE_SIZE, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "receive.message.max.bytes" }}, \
	{ FR_CONF_FUNC("feature", FR_TYPE_STRING | FR_TYPE_MULTI, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "builtin.features", .string_sep = "," }}, \
	{ FR_CONF_FUNC("debug", FR_TYPE_STRING | FR_TYPE_MULTI, kafka_config_parse, kafka_config_dflt), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "debug", .string_sep = "," }}, \
	{ FR_CONF_FUNC("plugin", FR_TYPE_STRING | FR_TYPE_MULTI, kafka_config_parse, NULL), \
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "plugin.library.paths", .string_sep = ";" }}, \
	{ FR_CONF_SUBSECTION_GLOBAL("metadata", 0, kafka_metadata_config) }, \
	{ FR_CONF_SUBSECTION_GLOBAL("version", 0, kafka_version_config) }, \
	{ FR_CONF_SUBSECTION_GLOBAL("connection", 0, kafka_connection_config) }, \
	{ FR_CONF_SUBSECTION_GLOBAL("tls", 0, kafka_tls_config) }, \
	{ FR_CONF_SUBSECTION_GLOBAL("sasl", 0, kafka_sasl_config) }

static CONF_PARSER const kafka_consumer_group_config[] = {
	/*
	 *	Group consumer is a member of
	 */
	{ FR_CONF_FUNC("id", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "group.id" }},

	/*
	 *	A unique identifier of the consumer instance provided by the end user
	 */
	{ FR_CONF_FUNC("instance_id", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "group.instance.id" }},

	/*
	 *	Range or roundrobin
	 */
	{ FR_CONF_FUNC("partition_assignment_strategy", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "partition.assignment.strategy" }},

	/*
	 *	Client group session and failure detection timeout.
	 */
	{ FR_CONF_FUNC("session_timeout", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "session.timeout.ms" }},

	/*
	 *	Group session keepalive heartbeat interval.
	 */
	{ FR_CONF_FUNC("heartbeat_interval", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "heartbeat.interval.ms" }},

	/*
	 *	How often to query for the current client group coordinator
	 */
	{ FR_CONF_FUNC("coordinator_query_interval", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "coordinator.query.interval.ms" }},


	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const kafka_base_consumer_topic_config[] = {
	/*
	 *	How many messages we process at a time
	 *
	 *	High numbers may starve the worker thread
	 */
	{ FR_CONF_FUNC("max_messages_per_cycle", FR_TYPE_UINT32, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "consume.callback.max.messages" }},

	/*
	 *	Action to take when there is no initial offset
	 *	in offset store or the desired offset is out of range.
	 */
	{ FR_CONF_FUNC("auto_offset_reset", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "auto.offset.reset" }},

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
static CONF_PARSER const kafka_base_consumer_topics_config[] = {
	{ FR_CONF_SUBSECTION_GLOBAL(CF_IDENT_ANY, FR_TYPE_MULTI, kafka_base_consumer_topic_config) },

	CONF_PARSER_TERMINATOR
};

CONF_PARSER const kafka_base_consumer_config[] = {
	BASE_CONFIG,
	{ FR_CONF_SUBSECTION_GLOBAL("group", 0, kafka_consumer_group_config) },

	/*
	 *	Maximum allowed time between calls to consume messages.
	 */
	{ FR_CONF_FUNC("max_poll_interval", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "max.poll.interval.ms" }},

	/*
	 *	Toggle auto commit
	 */
	{ FR_CONF_FUNC("auto_commit", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable_auto.commit" }},

	/*
	 *	Auto commit interval
	 */
	{ FR_CONF_FUNC("auto_commit_interval", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "auto.commit.interval.ms" }},

	/*
	 *	Automatically store offset of last message provided to application.
	 */
	{ FR_CONF_FUNC("auto_offset_store", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.auto.offset.store" }},

	/*
	 *	Minimum number of messages per topic+partition librdkafka tries to
	 *	maintain in the local consumer queue.
	 */
	{ FR_CONF_FUNC("queued_messages_min", FR_TYPE_UINT64, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queued.min.messages" }},

	/*
	 *	Maximum size of queued pre-fetched messages in the local consumer queue.
	 */
	{ FR_CONF_FUNC("queued_messages_max_size", FR_TYPE_SIZE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queued.max.messages.kbytes", .size_scale = 1024 }},

	/*
	 *	 Maximum time the broker may wait to fill the Fetch response.
	 */
	{ FR_CONF_FUNC("fetch_wait_max", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "fetch.wait.max.ms" }},

	/*
	 *	Initial maximum number of bytes per topic+partition to request when
	 *      fetching messages from the broker.
	 */
	{ FR_CONF_FUNC("fetch_message_max_size", FR_TYPE_SIZE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "fetch.message.max.bytes" }},

	/*
	 *	Initial maximum number of bytes per topic+partition to request when
	 *	fetching messages from the broker.
	 */
	{ FR_CONF_FUNC("fetch_partition_max_size", FR_TYPE_SIZE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "max.partition.fetch.bytes" }},

	/*
	 *	Maximum amount of data the broker shall return for a Fetch request.
	 */
	{ FR_CONF_FUNC("fetch_max_size", FR_TYPE_SIZE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "fetch.max.bytes" }},

	/*
	 *	 Minimum number of bytes the broker responds with.
	 */
	{ FR_CONF_FUNC("fetch_min_size", FR_TYPE_SIZE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "fetch.min.bytes" }},

	/*
	 *	How long to postpone the next fetch request for a topic+partition
	 *	in case of a fetch error.
	 */
	{ FR_CONF_FUNC("fetch_error_backoff", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "fetch.error.backoff.ms" }},

	/*
	 *	Controls how to read messages written transactionally
	 */
	{ FR_CONF_FUNC("isolation_level", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "isolation.level" }},

	/*
	 *	Verify CRC32 of consumed messages, ensuring no on-the-wire or
	 *	on-disk corruption to the messages occurred.
	 */
	{ FR_CONF_FUNC("check_crcs", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "check.crcs" }},

	/*
	 *	Allow automatic topic creation on the broker when subscribing
	 *	to or assigning non-existent topics
	 */
	{ FR_CONF_FUNC("auto_create_topic", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "allow.auto.create.topics" }},

	{ FR_CONF_SUBSECTION_GLOBAL("topic", 0, kafka_base_consumer_topics_config) }, \

	CONF_PARSER_TERMINATOR
};

static CONF_PARSER const kafka_base_producer_topic_config[] = {
	/*
	 *	This field indicates the number of acknowledgements the leader
	 *	broker must receive from ISR brokers before responding to the request.
	 */
	{ FR_CONF_FUNC("request_required_acks", FR_TYPE_INT16, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "request.required.acks" }},

	/*
	 *	medium	The ack timeout of the producer request in milliseconds
	 */
	{ FR_CONF_FUNC("request_timeout", FR_TYPE_TIME_DELTA, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "request.timeout.ms" }},

	/*
	 *	Local message timeout
	 */
	{ FR_CONF_FUNC("message_timeout", FR_TYPE_TIME_DELTA, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "message.timeout.ms" }},

	/*
	 *	Partitioning strategy
	 */
	{ FR_CONF_FUNC("partitioner", FR_TYPE_STRING, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "partitioner" }},

	/*
	 *	compression codec to use for compressing message sets.
	 */
	{ FR_CONF_FUNC("compression_type", FR_TYPE_STRING, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "compression.type" }},

	/*
	 *	compression level to use
	 */
	{ FR_CONF_FUNC("compression_level", FR_TYPE_INT8, kafka_topic_config_parse, kafka_topic_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "compression.level" }},

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
static CONF_PARSER const kafka_base_producer_topics_config[] = {
	{ FR_CONF_SUBSECTION_GLOBAL(CF_IDENT_ANY, 0, kafka_base_producer_topic_config) },

	CONF_PARSER_TERMINATOR
};

CONF_PARSER const kafka_base_producer_config[] = {
	BASE_CONFIG,

	/*
	 *	Enables the transactional producer
	 */
	{ FR_CONF_FUNC("transactional_id", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "transactional.id", .empty_default = true }},

	/*
	 *	The maximum amount of time in milliseconds that the transaction
	 *	coordinator will wait for a transaction status update from the
	 *	producer before proactively aborting the ongoing transaction.
	 */
	{ FR_CONF_FUNC("transaction_timeout", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "transaction.timeout.ms" }},

	/*
	 *	When set to true, the producer will ensure that messages are
	 *	successfully produced exactly once and in the original produce
	 *	order.
	 */
	{ FR_CONF_FUNC("idempotence", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.idempotence" }},

	/*
	 *	When set to true, any error that could result in a gap in the
	 *	produced message series when a batch of messages fails.
	 */
	{ FR_CONF_FUNC("gapless_guarantee", FR_TYPE_BOOL, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "enable.gapless.guarantee" }},

	/*
	 *	Maximum number of messages allowed on the producer queue.
	 *	This queue is shared by all topics and partitions.
	 */
	{ FR_CONF_FUNC("queue_max_messages", FR_TYPE_UINT32, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queue.buffering.max.messages" }},

	/*
	 *	Maximum total message size sum allowed on the producer queue.
	 */
	{ FR_CONF_FUNC("queue_max_size", FR_TYPE_SIZE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queue.buffering.max.kbytes", .size_scale = 1024 }},

	/*
	 *	How long we wait to aggregate messages
	 */
	{ FR_CONF_FUNC("queue_max_delay", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queue.buffering.max.ms" }},

	/*
	 *	How many times we resend a message
	 */
	{ FR_CONF_FUNC("message_retry_max", FR_TYPE_UINT32, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "message.send.max.retries" }},

	/*
	 *	The backoff time in milliseconds before retrying a protocol request.
	 */
	{ FR_CONF_FUNC("message_retry_interval", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "retry.backoff.ms" }},

	/*
	 *	The threshold of outstanding not yet transmitted broker requests
	 *      needed to backpressure the producer's message accumulator.
	 */
	{ FR_CONF_FUNC("backpressure_threshold", FR_TYPE_UINT32, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "queue.buffering.backpressure.threshold" }},

	/*
	 *	compression codec to use for compressing message sets.
	 */
	{ FR_CONF_FUNC("compression_type", FR_TYPE_STRING, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "compression.type" }},

	/*
	 *	Maximum size (in bytes) of all messages batched in one MessageSet
	 */
	{ FR_CONF_FUNC("batch_size", FR_TYPE_SIZE, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "batch.size" }},

	/*
	 *	Delay in milliseconds to wait to assign new sticky partitions for each topic
	 */
	{ FR_CONF_FUNC("sticky_partition_delay", FR_TYPE_TIME_DELTA, kafka_config_parse, kafka_config_dflt),
	  .uctx = &(fr_kafka_conf_ctx_t){ .property = "sticky.partitioning.linger.ms" }},

	{ FR_CONF_SUBSECTION_GLOBAL("topic", FR_TYPE_MULTI, kafka_base_producer_topics_config) }, \

	CONF_PARSER_TERMINATOR
};
