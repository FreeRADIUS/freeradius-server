/*
 * Copyright (C) 2025 Network RADIUS SARL (legal@networkradius.com)
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
 * @file rlm_dpsk.c
 * @brief Dynamic PSK for WiFi
 *
 * @copyright 2025 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/util/base16.h>

#include <ctype.h>
#include <strings.h>
#include <errno.h>
#include <sys/stat.h>

#include <openssl/ssl.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/core_names.h>
#include <openssl/params.h>


/*
  Header:		02030075

  descriptor		02
  information		010a
  length		0010
  replay counter	000000000000001
  snonce		c3bb319516614aacfb44e933bf1671131fb1856e5b2721952d414ce3f5aa312b
  IV			0000000000000000000000000000000
  rsc			0000000000000000
  reserved		0000000000000000
  mic			35cddcedad0dfb6a12a2eca55c17c323
  data length		0016
  data			30140100000fac040100000fac040100000fac028c00

	30
	14		length of data
	01		...
*/

typedef struct eapol_key_frame_t {
	uint8_t		descriptor;		// message number 2
	uint16_t	information;		//
	uint16_t	length;			// always 0010, for 16 octers
	uint8_t		replay_counter[8];	// usually "1"
	uint8_t		nonce[32];		// random token
	uint8_t		iv[16];			// zeroes
	uint8_t		rsc[8];			// zeros
	uint8_t		reserved[8];		// zeroes
	uint8_t		mic[16];		// calculated data
	uint16_t	data_len;		// various other things we don't need.
} CC_HINT(__packed__) eapol_key_frame_t;

typedef struct eapol_attr_t {
	uint8_t		header[4];		// 02030075
	eapol_key_frame_t frame;
} CC_HINT(__packed__) eapol_attr_t;


typedef struct rlm_dpsk_s rlm_dpsk_t;
typedef struct dpsk_source_s dpsk_source_t;
typedef struct dpsk_adapter_conf_s dpsk_adapter_conf_t;
typedef struct dpsk_request_input_s dpsk_request_input_t;
typedef struct dpsk_auth_call_env_s dpsk_auth_call_env_t;

typedef struct {
	fr_rb_node_t		node;
	uint8_t			mac[6];
	uint8_t			pmk[32];

	uint8_t			*ssid;
	size_t			ssid_len;
	char const		*filename;
	size_t			filename_len;

	char			*identity;
	size_t			identity_len;

	char			*psk;
	size_t			psk_len;
	bool			has_vlan;
	uint16_t		vlan;
	fr_time_t		expires;

	fr_dlist_t		dlist;
	rlm_dpsk_t const	*inst;
} rlm_dpsk_cache_t;

typedef struct dpsk_file_entry_s dpsk_file_entry_t;
typedef struct dpsk_file_bucket_s dpsk_file_bucket_t;
typedef struct dpsk_file_s dpsk_file_t;

struct dpsk_file_entry_s {
	dpsk_file_entry_t	*next_by_client;
	dpsk_file_entry_t	*fallback_next;
	char			*identity;
	size_t			identity_len;
	char			*psk;
	size_t			psk_len;
	bool			has_client_mac;
	uint8_t		client_mac[6];
	bool			has_vlan;
	uint16_t		vlan;
	uint8_t		pmk[32];
};

struct dpsk_file_bucket_s {
	fr_rb_node_t		node;
	uint8_t		client_mac[6];
	dpsk_file_entry_t	*entries;
};

struct dpsk_file_s {
	dpsk_file_t		*next;
	char			*filename;
	uint8_t			*ssid;
	size_t			ssid_len;
	time_t			mtime;
	TALLOC_CTX		*data_ctx;
	dpsk_file_entry_t	*fallback_entries;
	fr_rb_tree_t		client_index;
};

typedef struct {
	fr_rb_tree_t			cache;

	pthread_mutex_t			mutex;
	fr_dlist_head_t			head;
	dpsk_file_t			*files;
} rlm_dpsk_mutable_t;

typedef enum {
	DPSK_ADAPTER_TYPE_STANDARD_ATTRS = 0,
	DPSK_ADAPTER_TYPE_NAMED_VSA_ATTRS,
	DPSK_ADAPTER_TYPE_KEY_VALUE_VSA,
} dpsk_adapter_type_t;

typedef enum {
	DPSK_REPLY_MODE_STANDARD = 0,
	DPSK_REPLY_MODE_TUNNEL_PASSWORD,
	DPSK_REPLY_MODE_AVPAIR_HEX_PMK,
	DPSK_REPLY_MODE_MS_MPPE_RECV_KEY,
} dpsk_reply_mode_t;

typedef enum {
	DPSK_VLAN_MODE_NONE = 0,
	DPSK_VLAN_MODE_TUNNEL,
} dpsk_vlan_mode_t;

typedef enum {
	DPSK_SOURCE_TYPE_ATTRIBUTES = 0,
	DPSK_SOURCE_TYPE_CSV,
	DPSK_SOURCE_TYPE_SQL,
	DPSK_SOURCE_TYPE_REST,
} dpsk_source_type_t;

typedef enum {
	DPSK_DETECT_NONE = 0,
	DPSK_DETECT_ALL_PRESENT,
	DPSK_DETECT_ANY_PRESENT,
	DPSK_DETECT_CONTAINS_PREFIX,
} dpsk_detect_type_t;

typedef enum {
	DPSK_VALUE_ENCODING_PLAIN = 0,
	DPSK_VALUE_ENCODING_RADIUS_ESCAPED,
} dpsk_value_encoding_t;

typedef struct {
	dpsk_detect_type_t	type;
	char const		**attrs;
	tmpl_t			**attrs_tmpls;
	char const		**prefixes;
} dpsk_detect_rule_t;

typedef struct {
	char const *username;
	tmpl_t	   *username_tmpl;
	char const *ssid;
	tmpl_t	   *ssid_tmpl;
	char const *called_station;
	tmpl_t	   *called_station_tmpl;
	char const *anonce;
	tmpl_t	   *anonce_tmpl;
	char const *key_msg;
	tmpl_t	   *key_msg_tmpl;
	char const *master_key;
	tmpl_t	   *master_key_tmpl;
	char const *psk;
	tmpl_t	   *psk_tmpl;
	char const *psk_identity;
	tmpl_t	   *psk_identity_tmpl;
} dpsk_standard_request_map_t;

typedef struct {
	char const		*container_attr;
	char const		*username;
	tmpl_t			*username_tmpl;
	char const		*ssid_key;
	char const		*called_station_key;
	char const		*anonce_key;
	char const		*key_msg_key;
	dpsk_value_encoding_t	value_encoding;
} dpsk_key_value_request_map_t;

typedef struct {
	dpsk_standard_request_map_t	standard;
	dpsk_standard_request_map_t	named_vsa;
	dpsk_key_value_request_map_t	key_value;
} dpsk_request_map_t;

typedef struct {
	char const *psk_attr;
	tmpl_t	   *psk_attr_tmpl;
	char const *psk_identity_attr;
	tmpl_t	   *psk_identity_attr_tmpl;
} dpsk_standard_reply_t;

typedef struct {
	char const *psk_attr;
	tmpl_t	   *psk_attr_tmpl;
} dpsk_tunnel_password_reply_t;

typedef struct {
	char const	*avpair_attr;
	tmpl_t		*avpair_attr_tmpl;
	char const	*pmk_key;
	char const	**extra_pairs;
} dpsk_avpair_hex_pmk_reply_t;

typedef struct {
	char const	*psk_attr;
	tmpl_t		*psk_attr_tmpl;
	char const	*session_timeout_attr;
	tmpl_t		*session_timeout_attr_tmpl;
	uint32_t session_timeout;
	char const	*username_attr;
	tmpl_t		*username_attr_tmpl;
	char const	*role_attr;
	tmpl_t		*role_attr_tmpl;
	char const	*reply_message_attr;
	tmpl_t		*reply_message_attr_tmpl;
} dpsk_ms_mppe_reply_t;

typedef struct {
	dpsk_vlan_mode_t	mode;
	char const		*tunnel_type_attr;
	tmpl_t			*tunnel_type_attr_tmpl;
	char const		*tunnel_medium_type_attr;
	tmpl_t			*tunnel_medium_type_attr_tmpl;
	char const		*tunnel_private_group_id_attr;
	tmpl_t			*tunnel_private_group_id_attr_tmpl;
	uint32_t		tunnel_type_value;
	uint32_t		tunnel_medium_type_value;
} dpsk_vlan_reply_t;

typedef struct {
	dpsk_reply_mode_t	mode;
	bool			mode_is_set;
	dpsk_vlan_reply_t	vlan;
	dpsk_standard_reply_t	standard;
	dpsk_tunnel_password_reply_t tunnel_password;
	dpsk_avpair_hex_pmk_reply_t avpair_hex_pmk;
	dpsk_ms_mppe_reply_t	ms_mppe_recv_key;
} dpsk_reply_policy_t;

typedef struct {
	char const *psk;
	char const *psk_identity;
	char const *pmk;
} dpsk_attr_source_t;

typedef struct {
	char const *filename;
	char const *format;
} dpsk_csv_source_t;

struct dpsk_source_s {
	char const		*name;
	dpsk_source_type_t	type;
	bool			cacheable;
	dpsk_attr_source_t	attributes;
	dpsk_csv_source_t	csv;
};

struct dpsk_adapter_conf_s {
	char const		*name;
	uint32_t		priority;
	dpsk_adapter_type_t	type;
	char const		**source_names;
	dpsk_detect_rule_t	detect;
	dpsk_request_map_t	request;
	dpsk_reply_policy_t	reply;
};

typedef struct {
	dpsk_adapter_conf_t const	*conf;
	char const			*name;
	bool (*detect)(request_t *request, dpsk_adapter_conf_t const *conf);
	int (*resolve_input)(request_t *request, dpsk_adapter_conf_t const *conf, dpsk_request_input_t *input);
	unlang_action_t (*add_reply)(unlang_result_t *p_result, request_t *request,
				     dpsk_adapter_conf_t const *conf, dpsk_auth_call_env_t *env,
				     char const *psk, size_t psk_len, char const *psk_identity,
				     bool has_vlan, uint16_t vlan, uint8_t const pmk[32], rlm_rcode_t rcode);
} dpsk_adapter_runtime_t;

struct rlm_dpsk_s {
	fr_dict_enum_value_t const	*auth_type;

	uint32_t			cache_size;
	fr_time_delta_t			cache_lifetime;
	char const			*default_adapter_name;
	char const			*default_source_name;
	dpsk_source_t			**sources;
	dpsk_adapter_conf_t		**adapters;
	dpsk_adapter_runtime_t		**adapter_order;

	rlm_dpsk_mutable_t		*mutable;
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_dpsk_dict[];
fr_dict_autoload_t rlm_dpsk_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_auth_type;

extern fr_dict_attr_autoload_t rlm_dpsk_dict_attr[];
fr_dict_attr_autoload_t rlm_dpsk_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_table_num_sorted_t const dpsk_adapter_type_table[] = {
	{ L("key_value_vsa"), DPSK_ADAPTER_TYPE_KEY_VALUE_VSA },
	{ L("named_vsa_attrs"), DPSK_ADAPTER_TYPE_NAMED_VSA_ATTRS },
	{ L("standard_attrs"), DPSK_ADAPTER_TYPE_STANDARD_ATTRS },
};
static size_t dpsk_adapter_type_table_len = NUM_ELEMENTS(dpsk_adapter_type_table);

static fr_table_num_sorted_t const dpsk_reply_mode_table[] = {
	{ L("avpair_hex_pmk"), DPSK_REPLY_MODE_AVPAIR_HEX_PMK },
	{ L("ms_mppe_recv_key"), DPSK_REPLY_MODE_MS_MPPE_RECV_KEY },
	{ L("standard"), DPSK_REPLY_MODE_STANDARD },
	{ L("tunnel_password"), DPSK_REPLY_MODE_TUNNEL_PASSWORD },
};
static size_t dpsk_reply_mode_table_len = NUM_ELEMENTS(dpsk_reply_mode_table);

static fr_table_num_sorted_t const dpsk_vlan_mode_table[] = {
	{ L("none"), DPSK_VLAN_MODE_NONE },
	{ L("tunnel"), DPSK_VLAN_MODE_TUNNEL },
};
static size_t dpsk_vlan_mode_table_len = NUM_ELEMENTS(dpsk_vlan_mode_table);

static fr_table_num_sorted_t const dpsk_source_type_table[] = {
	{ L("attributes"), DPSK_SOURCE_TYPE_ATTRIBUTES },
	{ L("csv"), DPSK_SOURCE_TYPE_CSV },
	{ L("rest"), DPSK_SOURCE_TYPE_REST },
	{ L("sql"), DPSK_SOURCE_TYPE_SQL },
};
static size_t dpsk_source_type_table_len = NUM_ELEMENTS(dpsk_source_type_table);

static fr_table_num_sorted_t const dpsk_detect_type_table[] = {
	{ L("all_present"), DPSK_DETECT_ALL_PRESENT },
	{ L("any_present"), DPSK_DETECT_ANY_PRESENT },
	{ L("contains_prefix"), DPSK_DETECT_CONTAINS_PREFIX },
	{ L("none"), DPSK_DETECT_NONE },
};
static size_t dpsk_detect_type_table_len = NUM_ELEMENTS(dpsk_detect_type_table);

static fr_table_num_sorted_t const dpsk_value_encoding_table[] = {
	{ L("plain"), DPSK_VALUE_ENCODING_PLAIN },
	{ L("radius_escaped"), DPSK_VALUE_ENCODING_RADIUS_ESCAPED },
};
static size_t dpsk_value_encoding_table_len = NUM_ELEMENTS(dpsk_value_encoding_table);

static int dpsk_parse_enum_value(CONF_ITEM *ci, char const *label,
				 fr_table_num_sorted_t const *table, size_t table_len, int *out)
{
	char const *value = cf_pair_value(cf_item_to_pair(ci));
	int parsed;

	parsed = fr_table_sorted_num_by_str(table, table_len, value, INT_MIN);
	if (parsed == INT_MIN) {
		cf_log_err(ci, "Unknown %s '%s'", label, value);
		return -1;
	}

	*out = parsed;
	return 0;
}

static int dpsk_adapter_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				   CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	dpsk_adapter_type_t *type = out;
	int value;

	if (dpsk_parse_enum_value(ci, "adapter type", dpsk_adapter_type_table, dpsk_adapter_type_table_len, &value) < 0) return -1;
	*type = value;
	return 0;
}

static int dpsk_reply_mode_parse(UNUSED TALLOC_CTX *ctx, void *out, void *parent,
				 CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	dpsk_reply_mode_t *mode = out;
	dpsk_reply_policy_t *policy = parent;
	int value;

	if (dpsk_parse_enum_value(ci, "reply mode", dpsk_reply_mode_table, dpsk_reply_mode_table_len, &value) < 0) return -1;
	*mode = value;
	if (policy) policy->mode_is_set = true;
	return 0;
}

static int dpsk_vlan_mode_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	dpsk_vlan_mode_t *mode = out;
	int value;

	if (dpsk_parse_enum_value(ci, "VLAN mode", dpsk_vlan_mode_table, dpsk_vlan_mode_table_len, &value) < 0) return -1;
	*mode = value;
	return 0;
}

static int dpsk_source_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				  CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	dpsk_source_type_t *type = out;
	int value;

	if (dpsk_parse_enum_value(ci, "source type", dpsk_source_type_table, dpsk_source_type_table_len, &value) < 0) return -1;
	*type = value;
	return 0;
}

static int dpsk_detect_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				  CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	dpsk_detect_type_t *type = out;
	int value;

	if (dpsk_parse_enum_value(ci, "detect type", dpsk_detect_type_table, dpsk_detect_type_table_len, &value) < 0) return -1;
	*type = value;
	return 0;
}

static int dpsk_value_encoding_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
				     CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	dpsk_value_encoding_t *encoding = out;
	int value;

	if (dpsk_parse_enum_value(ci, "value encoding", dpsk_value_encoding_table, dpsk_value_encoding_table_len, &value) < 0) return -1;
	*encoding = value;
	return 0;
}

static const conf_parser_t dpsk_source_attr_config[] = {
	{ FR_CONF_OFFSET("psk", dpsk_attr_source_t, psk) },
	{ FR_CONF_OFFSET("psk_identity", dpsk_attr_source_t, psk_identity) },
	{ FR_CONF_OFFSET("pmk", dpsk_attr_source_t, pmk) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_source_csv_config[] = {
	{ FR_CONF_OFFSET("filename", dpsk_csv_source_t, filename) },
	{ FR_CONF_OFFSET("format", dpsk_csv_source_t, format) },
	CONF_PARSER_TERMINATOR
};

static int dpsk_source_section_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci,
				     UNUSED conf_parser_t const *rule)
{
	CONF_SECTION	*cs = cf_item_to_section(ci);
	dpsk_source_t	*source = out;

	(void) ctx;

	if (!source || !cs) return -1;

	source->name = cf_section_name2(cs);
	return cf_section_parse(source, source, cs);
}

static const conf_parser_t dpsk_source_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("type", FR_TYPE_VOID, CONF_FLAG_NOT_EMPTY, dpsk_source_t, type), .func = dpsk_source_type_parse },
	{ FR_CONF_OFFSET("cacheable", dpsk_source_t, cacheable) },
	{ FR_CONF_OFFSET_SUBSECTION("attributes", 0, dpsk_source_t, attributes, dpsk_source_attr_config) },
	{ FR_CONF_OFFSET_SUBSECTION("csv", 0, dpsk_source_t, csv, dpsk_source_csv_config) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_detect_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("type", FR_TYPE_VOID, CONF_FLAG_NOT_EMPTY, dpsk_detect_rule_t, type), .func = dpsk_detect_type_parse },
	{ FR_CONF_OFFSET("all_present", dpsk_detect_rule_t, attrs) },
	{ FR_CONF_OFFSET("any_present", dpsk_detect_rule_t, attrs) },
	{ FR_CONF_OFFSET("contains_prefix", dpsk_detect_rule_t, prefixes) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_request_standard_config[] = {
	{ FR_CONF_OFFSET("username", dpsk_standard_request_map_t, username) },
	{ FR_CONF_OFFSET("ssid", dpsk_standard_request_map_t, ssid) },
	{ FR_CONF_OFFSET("called_station", dpsk_standard_request_map_t, called_station) },
	{ FR_CONF_OFFSET("anonce", dpsk_standard_request_map_t, anonce) },
	{ FR_CONF_OFFSET("key_msg", dpsk_standard_request_map_t, key_msg) },
	{ FR_CONF_OFFSET("master_key", dpsk_standard_request_map_t, master_key) },
	{ FR_CONF_OFFSET("psk", dpsk_standard_request_map_t, psk) },
	{ FR_CONF_OFFSET("psk_identity", dpsk_standard_request_map_t, psk_identity) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_request_key_value_config[] = {
	{ FR_CONF_OFFSET("container_attr", dpsk_key_value_request_map_t, container_attr) },
	{ FR_CONF_OFFSET("username", dpsk_key_value_request_map_t, username) },
	{ FR_CONF_OFFSET("ssid_key", dpsk_key_value_request_map_t, ssid_key) },
	{ FR_CONF_OFFSET("called_station_key", dpsk_key_value_request_map_t, called_station_key) },
	{ FR_CONF_OFFSET("anonce_key", dpsk_key_value_request_map_t, anonce_key) },
	{ FR_CONF_OFFSET("key_msg_key", dpsk_key_value_request_map_t, key_msg_key) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("value_encoding", FR_TYPE_VOID, 0, dpsk_key_value_request_map_t, value_encoding), .func = dpsk_value_encoding_parse },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_request_config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("standard", 0, dpsk_request_map_t, standard, dpsk_request_standard_config) },
	{ FR_CONF_OFFSET_SUBSECTION("named_vsa", 0, dpsk_request_map_t, named_vsa, dpsk_request_standard_config) },
	{ FR_CONF_OFFSET_SUBSECTION("key_value", 0, dpsk_request_map_t, key_value, dpsk_request_key_value_config) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_reply_standard_config[] = {
	{ FR_CONF_OFFSET("psk_attr", dpsk_standard_reply_t, psk_attr) },
	{ FR_CONF_OFFSET("psk_identity_attr", dpsk_standard_reply_t, psk_identity_attr) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_reply_tunnel_password_config[] = {
	{ FR_CONF_OFFSET("psk_attr", dpsk_tunnel_password_reply_t, psk_attr) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_reply_avpair_hex_pmk_config[] = {
	{ FR_CONF_OFFSET("avpair_attr", dpsk_avpair_hex_pmk_reply_t, avpair_attr) },
	{ FR_CONF_OFFSET("pmk_key", dpsk_avpair_hex_pmk_reply_t, pmk_key) },
	{ FR_CONF_OFFSET("extra_pairs", dpsk_avpair_hex_pmk_reply_t, extra_pairs) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_reply_ms_mppe_config[] = {
	{ FR_CONF_OFFSET("psk_attr", dpsk_ms_mppe_reply_t, psk_attr) },
	{ FR_CONF_OFFSET("session_timeout_attr", dpsk_ms_mppe_reply_t, session_timeout_attr) },
	{ FR_CONF_OFFSET("session_timeout", dpsk_ms_mppe_reply_t, session_timeout) },
	{ FR_CONF_OFFSET("username_attr", dpsk_ms_mppe_reply_t, username_attr) },
	{ FR_CONF_OFFSET("role_attr", dpsk_ms_mppe_reply_t, role_attr) },
	{ FR_CONF_OFFSET("reply_message_attr", dpsk_ms_mppe_reply_t, reply_message_attr) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_vlan_reply_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("mode", FR_TYPE_VOID, 0, dpsk_vlan_reply_t, mode), .func = dpsk_vlan_mode_parse },
	{ FR_CONF_OFFSET("tunnel_type_attr", dpsk_vlan_reply_t, tunnel_type_attr) },
	{ FR_CONF_OFFSET("tunnel_medium_type_attr", dpsk_vlan_reply_t, tunnel_medium_type_attr) },
	{ FR_CONF_OFFSET("tunnel_private_group_id_attr", dpsk_vlan_reply_t, tunnel_private_group_id_attr) },
	{ FR_CONF_OFFSET("tunnel_type_value", dpsk_vlan_reply_t, tunnel_type_value) },
	{ FR_CONF_OFFSET("tunnel_medium_type_value", dpsk_vlan_reply_t, tunnel_medium_type_value) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t dpsk_reply_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("mode", FR_TYPE_VOID, CONF_FLAG_NOT_EMPTY, dpsk_reply_policy_t, mode), .func = dpsk_reply_mode_parse },
	{ FR_CONF_OFFSET_SUBSECTION("vlan", 0, dpsk_reply_policy_t, vlan, dpsk_vlan_reply_config) },
	{ FR_CONF_OFFSET_SUBSECTION("standard", 0, dpsk_reply_policy_t, standard, dpsk_reply_standard_config) },
	{ FR_CONF_OFFSET_SUBSECTION("tunnel_password", 0, dpsk_reply_policy_t, tunnel_password, dpsk_reply_tunnel_password_config) },
	{ FR_CONF_OFFSET_SUBSECTION("avpair_hex_pmk", 0, dpsk_reply_policy_t, avpair_hex_pmk, dpsk_reply_avpair_hex_pmk_config) },
	{ FR_CONF_OFFSET_SUBSECTION("ms_mppe_recv_key", 0, dpsk_reply_policy_t, ms_mppe_recv_key, dpsk_reply_ms_mppe_config) },
	CONF_PARSER_TERMINATOR
};

static int dpsk_adapter_section_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci,
				      UNUSED conf_parser_t const *rule)
{
	CONF_SECTION		*cs = cf_item_to_section(ci);
	dpsk_adapter_conf_t	*adapter = out;

	(void) ctx;

	if (!adapter || !cs) return -1;

	adapter->name = cf_section_name2(cs);
	return cf_section_parse(adapter, adapter, cs);
}

static const conf_parser_t dpsk_adapter_config[] = {
	{ FR_CONF_OFFSET("priority", dpsk_adapter_conf_t, priority) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("type", FR_TYPE_VOID, CONF_FLAG_NOT_EMPTY, dpsk_adapter_conf_t, type), .func = dpsk_adapter_type_parse },
	{ FR_CONF_OFFSET("sources", dpsk_adapter_conf_t, source_names) },
	{ FR_CONF_OFFSET_SUBSECTION("detect", 0, dpsk_adapter_conf_t, detect, dpsk_detect_config) },
	{ FR_CONF_OFFSET_SUBSECTION("request", 0, dpsk_adapter_conf_t, request, dpsk_request_config) },
	{ FR_CONF_OFFSET_SUBSECTION("reply", 0, dpsk_adapter_conf_t, reply, dpsk_reply_config) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("cache_size", rlm_dpsk_t, cache_size) },
	{ FR_CONF_OFFSET("cache_lifetime", rlm_dpsk_t, cache_lifetime) },
	{ FR_CONF_OFFSET("default_adapter", rlm_dpsk_t, default_adapter_name) },
	{ FR_CONF_OFFSET("default_source", rlm_dpsk_t, default_source_name) },
	{ FR_CONF_SUBSECTION_ALLOC("source", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING | CONF_FLAG_MULTI,
				   rlm_dpsk_t, sources, dpsk_source_config),
		.subcs_type = "dpsk_source_t", .name2 = CF_IDENT_ANY, .func = dpsk_source_section_parse },
	{ FR_CONF_SUBSECTION_ALLOC("adapter", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING | CONF_FLAG_MULTI,
				   rlm_dpsk_t, adapters, dpsk_adapter_config),
		.subcs_type = "dpsk_adapter_conf_t", .name2 = CF_IDENT_ANY, .func = dpsk_adapter_section_parse },

	CONF_PARSER_TERMINATOR
};

typedef struct {
	tmpl_t		*anonce_tmpl;
	tmpl_t		*key_msg_tmpl;
} dpsk_autz_call_env_t;

typedef struct dpsk_auth_call_env_s {
	fr_value_box_t	ssid;
	tmpl_t		*ssid_tmpl;
	fr_value_box_t	anonce;
	tmpl_t		*anonce_tmpl;
	fr_value_box_t	key_msg;
	tmpl_t		*key_msg_tmpl;
	fr_value_box_t	username;
	fr_value_box_t	calledstation;
	fr_value_box_t	masterkey;
	tmpl_t		*masterkey_tmpl;
	fr_value_box_t	psk;
	tmpl_t		*psk_tmpl;
	fr_value_box_t	psk_identity;
	tmpl_t		*psk_dest_tmpl;
	tmpl_t		*psk_identity_dest_tmpl;
	fr_value_box_t	filename;
} dpsk_auth_call_env_t;

typedef struct {
	uint8_t akm[4];
	uint8_t pairwise[4];
	size_t kck_len;
	size_t kek_len;
	size_t tk_len;
	size_t ptk_len;
} dpsk_rsn_info_t;

typedef struct {
	dpsk_rsn_info_t rsn_info;
	uint8_t descriptor_version;
	bool use_sha256;
	bool use_hostap_pmf;
	uint8_t snonce[32];
	uint8_t packet_mic[16];
	uint8_t frame[256];
	size_t frame_len;
} dpsk_verify_ctx_t;

#ifdef WITH_TLS
static const call_env_method_t dpsk_autz_method_env = {
	.inst_size = sizeof(dpsk_autz_call_env_t),
	.inst_type = "dpsk_autz_call_env_t",
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("anonce", FR_TYPE_OCTETS, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED,
						dpsk_autz_call_env_t, anonce_tmpl), .pair.dflt = "FreeRADIUS-EV5.802_1X-Anonce",
						.pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("key_msg", FR_TYPE_OCTETS, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED,
						dpsk_autz_call_env_t, key_msg_tmpl), .pair.dflt = "FreeRADIUS-EV5.802_1X-EAPoL-Key-Msg",
						.pair.dflt_quote = T_BARE_WORD },
		CALL_ENV_TERMINATOR
	}
};

static const call_env_method_t dpsk_auth_method_env = {
	.inst_size = sizeof(dpsk_auth_call_env_t),
	.inst_type = "dpsk_auth_call_env_t",
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_PARSE_OFFSET("ssid", FR_TYPE_STRING,
					  CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE,
					  dpsk_auth_call_env_t, ssid, ssid_tmpl), .pair.dflt = "Called-Station-SSID",
					  .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_OFFSET("anonce", FR_TYPE_OCTETS,
					  CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE,
					  dpsk_auth_call_env_t, anonce, anonce_tmpl), .pair.dflt = "FreeRADIUS-EV5.802_1X-Anonce",
					  .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_OFFSET("key_msg", FR_TYPE_OCTETS,
					  CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE,
					  dpsk_auth_call_env_t, key_msg, key_msg_tmpl), .pair.dflt = "FreeRADIUS-EV5.802_1X-EAPoL-Key-Msg",
					  .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("username", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED,
				     dpsk_auth_call_env_t, username), .pair.dflt = "User-Name", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("called_station", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE,
				     dpsk_auth_call_env_t, calledstation), .pair.dflt = "Called-Station-MAC", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_OFFSET("pairwise_master_key", FR_TYPE_OCTETS, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE,
					   dpsk_auth_call_env_t, masterkey, masterkey_tmpl), .pair.dflt = "control.Pairwise-Master-Key", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_OFFSET("pre_shared_key", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE,
					   dpsk_auth_call_env_t, psk, psk_tmpl), .pair.dflt = "control.Pre-Shared-Key", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("psk_identity", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE,
				     dpsk_auth_call_env_t, psk_identity), .pair.dflt = "control.PSK-Identity", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("pre_shared_key_attr", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED,
						dpsk_auth_call_env_t, psk_dest_tmpl), .pair.dflt = "reply.Pre-Shared-Key", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("psk_identity_attr", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED,
					   dpsk_auth_call_env_t, psk_identity_dest_tmpl), .pair.dflt = "reply.PSK-Identity", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("filename", FR_TYPE_STRING, CALL_ENV_FLAG_NONE, dpsk_auth_call_env_t, filename) },
		CALL_ENV_TERMINATOR
	}
};


static bool dpsk_list_contains_prefix(fr_pair_list_t const *list, char const *prefix)
{
	fr_pair_t const *vp;
	size_t prefix_len = strlen(prefix);

	for (vp = fr_pair_list_head(list);
	     vp;
	     vp = fr_pair_list_next(list, vp)) {
		if (fr_type_is_structural(vp->vp_type)) {
			if (dpsk_list_contains_prefix(&vp->vp_group, prefix)) return true;
			continue;
		}

		if ((vp->vp_type != FR_TYPE_STRING) || !vp->vp_strvalue || (vp->vp_length < prefix_len)) continue;
		if (strncmp(vp->vp_strvalue, prefix, prefix_len) == 0) return true;
	}

	return false;
}

static fr_pair_t *dpsk_find_pair_by_tmpl(request_t *request, tmpl_t *vpt);
static int dpsk_resolve_attr_pair_tmpl(request_t *request, tmpl_t *vpt,
				       fr_value_box_t *dst, fr_value_box_t const **active);
static fr_pair_t *dpsk_find_pair_by_da_recursive(fr_pair_list_t const *list, fr_dict_attr_t const *da);
typedef struct dpsk_request_input_s dpsk_request_input_t;
static dpsk_adapter_runtime_t const *dpsk_select_adapter(rlm_dpsk_t const *inst, request_t *request);

/*
 *	mod_authorize() - authorize user if we can authenticate
 *	it later. Add Auth-Type attribute if present in module
 *	configuration (usually Auth-Type must be "DPSK")
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_dpsk_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_dpsk_t);
	dpsk_adapter_runtime_t const	*adapter;

	(void) p_result;
	(void) mctx->env_data;
	adapter = dpsk_select_adapter(inst, request);
	if (!adapter) RETURN_UNLANG_NOOP;

	if (!inst->auth_type) {
		WARN("No 'authenticate %s {...}' section or 'Auth-Type = %s' set.  Cannot setup DPSK authentication.",
		     mctx->mi->name, mctx->mi->name);
		RETURN_UNLANG_NOOP;
	}

	RDEBUG2("Found DPSK request (%s). Setting control.Auth-Type = ::%s", adapter->name, mctx->mi->name);

	if (!module_rlm_section_type_set(request, attr_auth_type, inst->auth_type)) RETURN_UNLANG_NOOP;

	RETURN_UNLANG_UPDATED;
}

static rlm_dpsk_cache_t *dpsk_cache_find(request_t *request, rlm_dpsk_t const *inst, uint8_t *buffer, size_t buflen,
				 fr_value_box_t const *ssid, char const *filename, uint8_t const *mac)
{
	rlm_dpsk_cache_t *entry, my_entry;

	memcpy(my_entry.mac, mac, sizeof(my_entry.mac));
	memcpy(&my_entry.ssid, &ssid->vb_octets, sizeof(my_entry.ssid)); /* const issues */
	my_entry.ssid_len = ssid->vb_length;
	my_entry.filename = filename;
	my_entry.filename_len = filename ? strlen(filename) : 0;

	entry = fr_rb_find(&inst->mutable->cache, &my_entry);
	if (entry) {
		if fr_time_gt(entry->expires, fr_time()) {
			RDEBUG3("Cache entry found");
			memcpy(buffer, entry->pmk, buflen);
			return entry;
		}

		RDEBUG3("Cache entry has expired");
		fr_rb_delete(&inst->mutable->cache, entry);
	}

	return NULL;
}

static int dpsk_cache_entry_dup(request_t *request, rlm_dpsk_cache_t const *entry,
				char const **psk_identity_out, char const **psk_out, size_t *psk_len_out,
				bool *has_vlan_out, uint16_t *vlan_out)
{
	char *identity_copy;
	char *psk_copy;

	fr_assert(entry != NULL);

	MEM(identity_copy = talloc_strdup(request, entry->identity));
	MEM(psk_copy = talloc_strdup(request, entry->psk));

	*psk_identity_out = identity_copy;
	*psk_out = psk_copy;
	*psk_len_out = entry->psk_len;
	*has_vlan_out = entry->has_vlan;
	*vlan_out = entry->vlan;

	return 0;
}


static int generate_pmk(request_t *request, uint8_t *buffer, size_t buflen, fr_value_box_t const *ssid, char const *psk, size_t psk_len)
{
	fr_assert(buflen == 32);

	if (PKCS5_PBKDF2_HMAC_SHA1((const char *) psk, psk_len, (const unsigned char *) ssid->vb_strvalue,
				   ssid->vb_length, 4096, buflen, buffer) == 0) {
		RERROR("Failed calling OpenSSL to calculate the PMK");
		return -1;
	}

	return 0;
}

static uint16_t dpsk_read_be16(uint8_t const *p)
{
	return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}

static uint16_t dpsk_read_le16(uint8_t const *p)
{
	return (uint16_t) (((uint16_t) p[1] << 8) | p[0]);
}

static void dpsk_rdebug_mac(request_t *request, char const *label, uint8_t const mac[6]);
static void dpsk_rdebug_akm_suite(request_t *request, uint8_t const akm[4]);

static uint8_t dpsk_eapol_descriptor_version(uint8_t const *eapol_key_msg, size_t eapol_key_msg_len)
{
	eapol_attr_t const *eapol;

	if (eapol_key_msg_len < sizeof(eapol_attr_t)) return 0;
	eapol = (eapol_attr_t const *) eapol_key_msg;

	return (uint8_t) (dpsk_read_be16((uint8_t const *) &eapol->frame.information) & 0x7);
}

static int dpsk_eapol_first_akm_suite(uint8_t out[4], uint8_t const *eapol_key_msg, size_t eapol_key_msg_len)
{
	eapol_attr_t const *eapol;
	uint8_t const *key_data;
	size_t key_data_len, pos;

	if (eapol_key_msg_len < sizeof(eapol_attr_t)) return -1;
	eapol = (eapol_attr_t const *) eapol_key_msg;
	key_data_len = dpsk_read_be16((uint8_t const *) &eapol->frame.data_len);
	if ((sizeof(eapol_attr_t) + key_data_len) > eapol_key_msg_len) return -1;

	key_data = eapol_key_msg + sizeof(eapol_attr_t);
	for (pos = 0; (pos + 2) <= key_data_len; ) {
		uint8_t id = key_data[pos];
		uint8_t len = key_data[pos + 1];
		uint8_t const *p;
		uint16_t count;

		if ((pos + 2 + len) > key_data_len) break;
		if (id != 0x30) {
			pos += 2 + len;
			continue;
		}

		p = key_data + pos + 2;
		if (len < 14) return -1;
		if (dpsk_read_le16(p) != 1) return -1;
		p += 2;
		p += 4;
		count = dpsk_read_le16(p);
		p += 2;
		if ((size_t) (p - (key_data + pos + 2)) + ((size_t) count * 4) + 2 > len) return -1;
		p += count * 4;
		count = dpsk_read_le16(p);
		p += 2;
		if (!count) return -1;
		if ((size_t) (p - (key_data + pos + 2)) + 4 > len) return -1;
		memcpy(out, p, 4);
		return 0;
	}

	return -1;
}

static bool dpsk_akm_suite_uses_sha256(uint8_t const akm[4])
{
	if (memcmp(akm, "\x00\x0f\xac", 3) != 0) return false;

	switch (akm[3]) {
	case 4:
	case 6:
	case 9:
	case 19:
	case 20:
	case 25:
		return true;
	default:
		return false;
	}
}

static size_t dpsk_rsn_selector_to_tk_len(uint8_t const sel[4])
{
	if (memcmp(sel, "\x00\x0f\xac", 3) != 0) return 16;

	switch (sel[3]) {
	case 4:
	case 8:
	case 9:
	case 10:
		return 16;
	case 12:
	case 13:
		return 32;
	default:
		return 16;
	}
}

static void dpsk_akm_lengths(uint8_t const akm[4], size_t *kck_len, size_t *kek_len)
{
	*kck_len = 16;
	*kek_len = 16;

	if (memcmp(akm, "\x00\x0f\xac", 3) != 0) return;

	switch (akm[3]) {
	case 12:
	case 13:
		*kck_len = 24;
		*kek_len = 32;
		return;
	default:
		return;
	}
}

static int dpsk_parse_rsn_info_from_eapol(dpsk_rsn_info_t *info, uint8_t const *eapol_key_msg, size_t eapol_key_msg_len)
{
	eapol_attr_t const *eapol;
	uint8_t const *key_data;
	size_t key_data_len, pos;

	memset(info, 0, sizeof(*info));

	if (eapol_key_msg_len < sizeof(eapol_attr_t)) return -1;
	eapol = (eapol_attr_t const *) eapol_key_msg;
	key_data_len = dpsk_read_be16((uint8_t const *) &eapol->frame.data_len);
	if ((sizeof(eapol_attr_t) + key_data_len) > eapol_key_msg_len) return -1;

	key_data = eapol_key_msg + sizeof(eapol_attr_t);
	for (pos = 0; (pos + 2) <= key_data_len; ) {
		uint8_t id = key_data[pos];
		uint8_t len = key_data[pos + 1];
		uint8_t const *p;
		uint16_t count;

		if ((pos + 2 + len) > key_data_len) break;
		if (id != 0x30) {
			pos += 2 + len;
			continue;
		}

		p = key_data + pos + 2;
		if (len < 14) return -1;
		if (dpsk_read_le16(p) != 1) return -1;
		p += 2;
		p += 4;
		count = dpsk_read_le16(p);
		p += 2;
		if (!count) return -1;
		if ((size_t) (p - (key_data + pos + 2)) + ((size_t) count * 4) + 2 > len) return -1;
		memcpy(info->pairwise, p, 4);
		p += count * 4;

		count = dpsk_read_le16(p);
		p += 2;
		if (!count) return -1;
		if ((size_t) (p - (key_data + pos + 2)) + 4 > len) return -1;
		memcpy(info->akm, p, 4);

		dpsk_akm_lengths(info->akm, &info->kck_len, &info->kek_len);
		info->tk_len = dpsk_rsn_selector_to_tk_len(info->pairwise);
		info->ptk_len = info->kck_len + info->kek_len + info->tk_len;
		return 0;
	}

	return -1;
}

static int dpsk_prf_sha1(uint8_t *out, size_t out_len, uint8_t const *key, size_t key_len,
			 char const *label, uint8_t const *data, size_t data_len)
{
	unsigned int md_len;
	uint8_t md[EVP_MAX_MD_SIZE];
	uint8_t input[256];
	size_t label_len, input_len, pos = 0;
	uint8_t counter = 0;

	label_len = strlen(label);
	input_len = label_len + 1 + data_len + 1;
	if (input_len > sizeof(input)) return -1;
	memcpy(input, label, label_len);
	input[label_len] = '\0';
	memcpy(input + label_len + 1, data, data_len);

	while (pos < out_len) {
		size_t copy;
		input[input_len - 1] = counter;
		if (!HMAC(EVP_sha1(), key, key_len, input, input_len, md, &md_len)) return -1;
		copy = ((out_len - pos) < md_len) ? (out_len - pos) : md_len;
		memcpy(out + pos, md, copy);
		pos += copy;
		counter++;
	}

	return 0;
}

static int dpsk_prf_sha256(uint8_t *out, size_t out_len, uint8_t const *key, size_t key_len,
			   char const *label, uint8_t const *data, size_t data_len)
{
	unsigned int md_len;
	uint8_t md[EVP_MAX_MD_SIZE];
	uint8_t input[256];
	size_t label_len, input_len, pos = 0;
	uint16_t counter = 1;
	uint16_t out_bits = (uint16_t) (out_len * 8);

	label_len = strlen(label);
	input_len = 2 + label_len + data_len + 2;
	if (input_len > sizeof(input)) return -1;

	while (pos < out_len) {
		size_t copy;
		input[0] = counter & 0xff;
		input[1] = (counter >> 8) & 0xff;
		memcpy(input + 2, label, label_len);
		memcpy(input + 2 + label_len, data, data_len);
		input[2 + label_len + data_len] = out_bits & 0xff;
		input[2 + label_len + data_len + 1] = (out_bits >> 8) & 0xff;
		if (!HMAC(EVP_sha256(), key, key_len, input, input_len, md, &md_len)) return -1;
		copy = ((out_len - pos) < md_len) ? (out_len - pos) : md_len;
		memcpy(out + pos, md, copy);
		pos += copy;
		counter++;
	}

	return 0;
}

static int dpsk_aes_128_cmac(uint8_t const key[16], uint8_t const *data, size_t data_len, uint8_t out[16])
{
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_MAC *mac = NULL;
	EVP_MAC_CTX *ctx = NULL;
	OSSL_PARAM params[2];
	char cipher_name[] = "AES-128-CBC";
#else
	CMAC_CTX *ctx;
#endif
	size_t out_len = 0;
	int ok = -1;

#if OPENSSL_VERSION_MAJOR >= 3
	mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
	if (!mac) return -1;

	ctx = EVP_MAC_CTX_new(mac);
	if (!ctx) goto finish;

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher_name, 0);
	params[1] = OSSL_PARAM_construct_end();

	if (EVP_MAC_init(ctx, key, 16, params) != 1) goto finish;
	if (EVP_MAC_update(ctx, data, data_len) != 1) goto finish;
	if (EVP_MAC_final(ctx, out, &out_len, 16) != 1) goto finish;
#else
	ctx = CMAC_CTX_new();
	if (!ctx) return -1;
	if (CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL) != 1) goto finish;
	if (CMAC_Update(ctx, data, data_len) != 1) goto finish;
	if (CMAC_Final(ctx, out, &out_len) != 1) goto finish;
#endif
	if (out_len < 16) goto finish;
	ok = 0;

finish:
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_MAC_CTX_free(ctx);
	EVP_MAC_free(mac);
#else
	CMAC_CTX_free(ctx);
#endif
	return ok;
}

static int dpsk_derive_ptk(uint8_t *ptk, size_t ptk_len, uint8_t const *pmk, size_t pmk_len,
			   uint8_t const client_mac[6], uint8_t const authenticator_mac[6],
			   uint8_t const ap_anonce[32], uint8_t const snonce[32], bool use_sha256)
{
	uint8_t ptk_data[2 * 6 + 2 * 32];
	uint8_t const *min_mac, *max_mac;
	uint8_t const *min_nonce, *max_nonce;

	if (memcmp(client_mac, authenticator_mac, 6) <= 0) {
		min_mac = client_mac;
		max_mac = authenticator_mac;
	} else {
		min_mac = authenticator_mac;
		max_mac = client_mac;
	}

	if (memcmp(snonce, ap_anonce, 32) <= 0) {
		min_nonce = snonce;
		max_nonce = ap_anonce;
	} else {
		min_nonce = ap_anonce;
		max_nonce = snonce;
	}

	memcpy(ptk_data, min_mac, 6);
	memcpy(ptk_data + 6, max_mac, 6);
	memcpy(ptk_data + 12, min_nonce, 32);
	memcpy(ptk_data + 44, max_nonce, 32);

	if (use_sha256) return dpsk_prf_sha256(ptk, ptk_len, pmk, pmk_len, "Pairwise key expansion", ptk_data, sizeof(ptk_data));
	return dpsk_prf_sha1(ptk, ptk_len, pmk, pmk_len, "Pairwise key expansion", ptk_data, sizeof(ptk_data));
}

static int dpsk_compute_eapol_mic(uint8_t out[16], uint8_t descriptor_version,
				  bool use_hostap_pmf, size_t kck_len, uint8_t const *kck,
				  uint8_t const *frame, size_t frame_len)
{
	switch (descriptor_version) {
	case 2:
		if (!HMAC(EVP_sha1(), kck, 16, frame, frame_len, out, NULL)) return -1;
		return 0;

	case 3:
		if (use_hostap_pmf && (kck_len != 16)) return -1;
		if (dpsk_aes_128_cmac(kck, frame, frame_len, out) < 0) return -1;
		return 0;

	default:
		return 1;
	}
}

static int dpsk_prepare_verify_ctx(request_t *request, dpsk_verify_ctx_t *ctx,
				   uint8_t const *eapol_key_msg, size_t eapol_key_msg_len)
{
	eapol_attr_t const *eapol;
	eapol_attr_t *zeroed;
	uint8_t akm[4];

	memset(ctx, 0, sizeof(*ctx));

	if (eapol_key_msg_len < sizeof(eapol_attr_t)) return -1;
	if (eapol_key_msg_len > sizeof(ctx->frame)) return -1;

	ctx->descriptor_version = dpsk_eapol_descriptor_version(eapol_key_msg, eapol_key_msg_len);
	RDEBUG2("DPSK EAPOL-Key descriptor version=%u", ctx->descriptor_version);

	memset(akm, 0, sizeof(akm));
	if (dpsk_eapol_first_akm_suite(akm, eapol_key_msg, eapol_key_msg_len) == 0) {
		dpsk_rdebug_akm_suite(request, akm);
		ctx->use_sha256 = dpsk_akm_suite_uses_sha256(akm);
	} else {
		RDEBUG2("DPSK AKM suite not found in EAPOL key data");
	}
	if (!ctx->use_sha256 && (ctx->descriptor_version == 3)) ctx->use_sha256 = true;
	RDEBUG2("DPSK PTK KDF=%s", ctx->use_sha256 ? "SHA256" : "SHA1");

	if ((ctx->descriptor_version == 3) && (memcmp(akm, "\x00\x0f\xac\x06", 4) == 0)) {
		if (dpsk_parse_rsn_info_from_eapol(&ctx->rsn_info, eapol_key_msg, eapol_key_msg_len) == 0) {
			ctx->use_hostap_pmf = true;
			RDEBUG2("DPSK PMF branch=hostap-style PTK (kck=%zu kek=%zu tk=%zu total=%zu)",
				ctx->rsn_info.kck_len, ctx->rsn_info.kek_len,
				ctx->rsn_info.tk_len, ctx->rsn_info.ptk_len);
		} else {
			RDEBUG2("DPSK PMF branch parse_rsn_info_from_eapol failed, using legacy PTK path");
		}
	}

	memcpy(ctx->snonce, eapol_key_msg + 17, sizeof(ctx->snonce));

	memcpy(ctx->frame, eapol_key_msg, eapol_key_msg_len);
	ctx->frame_len = eapol_key_msg_len;
	zeroed = (eapol_attr_t *) &ctx->frame[0];
	memset(&zeroed->frame.mic[0], 0, sizeof(zeroed->frame.mic));

	eapol = (eapol_attr_t const *) eapol_key_msg;
	memcpy(ctx->packet_mic, &eapol->frame.mic[0], sizeof(ctx->packet_mic));

	return 0;
}

static int dpsk_verify_candidate(dpsk_verify_ctx_t const *verify, uint8_t const ap_anonce[32],
				 uint8_t const client_mac[6], uint8_t const authenticator_mac[6],
				 uint8_t const pmk[32], uint8_t calc_mic[16])
{
	uint8_t ptk[128];
	uint8_t const *kck;

	if (verify->use_hostap_pmf) {
		if ((verify->rsn_info.ptk_len == 0) || (verify->rsn_info.ptk_len > sizeof(ptk))) return -1;
		if (dpsk_derive_ptk(ptk, verify->rsn_info.ptk_len, pmk, 32, client_mac, authenticator_mac,
				    ap_anonce, verify->snonce, verify->use_sha256) < 0) return -1;
		kck = ptk;
	} else {
		if (dpsk_derive_ptk(ptk, 16, pmk, 32, client_mac, authenticator_mac,
				    ap_anonce, verify->snonce, verify->use_sha256) < 0) return -1;
		kck = ptk;
	}

	switch (dpsk_compute_eapol_mic(calc_mic, verify->descriptor_version, verify->use_hostap_pmf,
				       verify->rsn_info.kck_len, kck, verify->frame, verify->frame_len)) {
	case 0:
		break;
	case 1:
		return 1;
	default:
		return -1;
	}

	if (memcmp(verify->packet_mic, calc_mic, sizeof(verify->packet_mic)) == 0) return 0;
	return 1;
}

/*
 *	Verify the DPSK information.
 */
static int8_t dpsk_file_bucket_cmp(void const *one, void const *two)
{
	dpsk_file_bucket_t const *a = one;
	dpsk_file_bucket_t const *b = two;

	return CMP(memcmp(a->client_mac, b->client_mac, sizeof(a->client_mac)), 0);
}

static char *dpsk_trim_whitespace(char *value)
{
	char *end;

	while (*value && isspace((unsigned char) *value)) value++;
	if (!*value) return value;

	end = value + strlen(value) - 1;
	while ((end > value) && isspace((unsigned char) *end)) *end-- = '\0';

	return value;
}

static int dpsk_hex_nibble(char c)
{
	if ((c >= '0') && (c <= '9')) return c - '0';
	if ((c >= 'a') && (c <= 'f')) return 10 + (c - 'a');
	if ((c >= 'A') && (c <= 'F')) return 10 + (c - 'A');
	return -1;
}

static int dpsk_parse_client_mac(uint8_t out[6], char const *text)
{
	size_t i;

	if (strlen(text) != 12) return -1;

	for (i = 0; i < 6; i++) {
		int hi = dpsk_hex_nibble(text[i * 2]);
		int lo = dpsk_hex_nibble(text[i * 2 + 1]);

		if ((hi < 0) || (lo < 0)) return -1;
		out[i] = (uint8_t) ((hi << 4) | lo);
	}

	return 0;
}

static void dpsk_format_mac(char out[13], uint8_t const mac[6])
{
	snprintf(out, 13, "%02x%02x%02x%02x%02x%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void dpsk_rdebug_mac(request_t *request, char const *label, uint8_t const mac[6])
{
	char buffer[13];

	dpsk_format_mac(buffer, mac);
	RDEBUG2("%s %s", label, buffer);
}

static void dpsk_rdebug_akm_suite(request_t *request, uint8_t const akm[4])
{
	RDEBUG2("DPSK AKM suite=%02x:%02x:%02x:%02x", akm[0], akm[1], akm[2], akm[3]);
}

static int dpsk_parse_csv_fields(char *line, char **fields, size_t max_fields)
{
	char *p = line;
	size_t field = 0;

	while (true) {
		if (field >= max_fields) return -1;

		if (*p == '"') {
			char *start = ++p;
			char *out = start;

			while (*p) {
				if ((*p == '"') && (p[1] == '"')) {
					*out++ = '"';
					p += 2;
					continue;
				}
				if (*p == '"') break;
				*out++ = *p++;
			}
			if (*p != '"') return -1;
			*out = '\0';
			fields[field++] = start;
			p++;
			while (*p && isspace((unsigned char) *p)) p++;
			if (!*p) break;
			if (*p != ',') return -1;
			p++;
		} else {
			char *start = p;
			while (*p && (*p != ',')) p++;
			if (*p == ',') *p++ = '\0';
			fields[field++] = start;
			if (!*p) break;
		}
	}

	while (field < max_fields) fields[field++] = NULL;
	return 0;
}

static int dpsk_parse_vlan(char const *text, uint16_t *out)
{
	char *end = NULL;
	unsigned long value;

	if (!text || !*text) return 0;

	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno || !end || *end || (value > 4094)) return -1;

	*out = (uint16_t) value;
	return 1;
}

static void dpsk_free_file_data(dpsk_file_t *file)
{
	if (!file) return;
	TALLOC_FREE(file->data_ctx);
	file->fallback_entries = NULL;
	file->mtime = 0;
	fr_rb_inline_init(&file->client_index, dpsk_file_bucket_t, node, dpsk_file_bucket_cmp, NULL);
}

static dpsk_file_bucket_t *dpsk_find_bucket(dpsk_file_t *file, uint8_t const client_mac[6], bool create)
{
	dpsk_file_bucket_t key = { .client_mac = { 0 } };
	dpsk_file_bucket_t *bucket;

	memcpy(key.client_mac, client_mac, sizeof(key.client_mac));
	bucket = fr_rb_find(&file->client_index, &key);
	if (bucket || !create) return bucket;

	MEM(bucket = talloc_zero(file->data_ctx, dpsk_file_bucket_t));
	memcpy(bucket->client_mac, client_mac, sizeof(bucket->client_mac));
	if (!fr_rb_insert(&file->client_index, bucket)) {
		TALLOC_FREE(bucket);
		return fr_rb_find(&file->client_index, &key);
	}

	return bucket;
}

static int dpsk_load_file_entries(request_t *request, dpsk_file_t *file, fr_value_box_t const *ssid)
{
	FILE *fp;
	struct stat st;
	TALLOC_CTX *data_ctx = NULL;
	char buffer[2048];
	unsigned int lineno = 0;

	if (stat(file->filename, &st) < 0) {
		REDEBUG("Failed stat on %s - %s", file->filename, fr_syserror(errno));
		return -1;
	}

	if ((file->mtime == st.st_mtime) && file->data_ctx) return 0;

	dpsk_free_file_data(file);

	MEM(data_ctx = talloc_new(file));
	file->data_ctx = data_ctx;
	fr_rb_inline_init(&file->client_index, dpsk_file_bucket_t, node, dpsk_file_bucket_cmp, NULL);

	fp = fopen(file->filename, "r");
	if (!fp) {
		REDEBUG("Failed opening %s - %s", file->filename, fr_syserror(errno));
		TALLOC_FREE(file->data_ctx);
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), fp)) {
		char *fields[4] = { NULL, NULL, NULL, NULL };
		char *identity, *psk;
		char const *client_mac, *vlan;
		dpsk_file_entry_t *entry;
		dpsk_file_bucket_t *bucket;
		int has_vlan;
		size_t len = strlen(buffer);

		lineno++;
		while (len && ((buffer[len - 1] == '\n') || (buffer[len - 1] == '\r'))) buffer[--len] = '\0';
		if (!buffer[0] || (buffer[0] == '#')) continue;
		if (dpsk_parse_csv_fields(buffer, fields, 4) < 0) {
			REDEBUG("%s[%u] has too many fields", file->filename, lineno);
			goto fail;
		}

		identity = fields[0] ? dpsk_trim_whitespace(fields[0]) : NULL;
		psk = fields[1] ? dpsk_trim_whitespace(fields[1]) : NULL;
		client_mac = fields[2] ? dpsk_trim_whitespace(fields[2]) : "";
		vlan = fields[3] ? dpsk_trim_whitespace(fields[3]) : "";

		if (!identity || !psk || !*identity || !*psk) {
			REDEBUG("%s[%u] requires identity and psk", file->filename, lineno);
			goto fail;
		}

		MEM(entry = talloc_zero(file->data_ctx, dpsk_file_entry_t));
		MEM(entry->identity = talloc_strdup(entry, identity));
		entry->identity_len = strlen(entry->identity);
		MEM(entry->psk = talloc_strdup(entry, psk));
		entry->psk_len = strlen(entry->psk);

		if (*client_mac) {
			if (dpsk_parse_client_mac(entry->client_mac, client_mac) < 0) {
				REDEBUG("%s[%u] has invalid client MAC", file->filename, lineno);
				goto fail;
			}
			entry->has_client_mac = true;
		}

		has_vlan = dpsk_parse_vlan(vlan, &entry->vlan);
		if (has_vlan < 0) {
			REDEBUG("%s[%u] has invalid vlan", file->filename, lineno);
			goto fail;
		}
		entry->has_vlan = (has_vlan > 0);

		if (generate_pmk(request, entry->pmk, sizeof(entry->pmk), ssid, entry->psk, entry->psk_len) < 0) goto fail;

		if (entry->has_client_mac) {
			bucket = dpsk_find_bucket(file, entry->client_mac, true);
			if (!bucket) goto fail;
			entry->next_by_client = bucket->entries;
			bucket->entries = entry;
		} else {
			entry->fallback_next = file->fallback_entries;
			file->fallback_entries = entry;
		}
	}

	fclose(fp);
	file->mtime = st.st_mtime;
	return 0;

fail:
	fclose(fp);
	dpsk_free_file_data(file);
	return -1;
}

static dpsk_file_t *dpsk_get_file_for_request(request_t *request, rlm_dpsk_t const *inst, char const *filename,
				   fr_value_box_t const *ssid)
{
	dpsk_file_t *file;

	for (file = inst->mutable->files; file; file = file->next) {
		if (strcmp(file->filename, filename) != 0) continue;
		if (file->ssid_len != ssid->vb_length) continue;
		if (memcmp(file->ssid, ssid->vb_octets, file->ssid_len) != 0) continue;
		break;
	}

	if (!file) {
		MEM(file = talloc_zero(inst->mutable, dpsk_file_t));
		MEM(file->filename = talloc_strdup(file, filename));
		MEM(file->ssid = talloc_memdup(file, ssid->vb_octets, ssid->vb_length));
		file->ssid_len = ssid->vb_length;
		fr_rb_inline_init(&file->client_index, dpsk_file_bucket_t, node, dpsk_file_bucket_cmp, NULL);
		file->next = inst->mutable->files;
		inst->mutable->files = file;
	}

	if (dpsk_load_file_entries(request, file, ssid) < 0) return NULL;
	return file;
}

struct dpsk_request_input_s {
	fr_value_box_t const *ssid;
	fr_value_box_t const *anonce;
	fr_value_box_t const *key_msg;
	fr_value_box_t const *username;
	fr_value_box_t const *calledstation;
	fr_value_box_t const *masterkey;
	fr_value_box_t const *psk;
	fr_value_box_t const *psk_identity;
	char const *filename;
	fr_value_box_t resolved_username;
	fr_value_box_t resolved_ssid;
	fr_value_box_t resolved_anonce;
	fr_value_box_t resolved_key_msg;
	fr_value_box_t resolved_calledstation;
	fr_value_box_t resolved_masterkey;
	fr_value_box_t resolved_psk;
	fr_value_box_t resolved_psk_identity;
};

typedef struct {
	bool	has_ssid;
	bool	has_anonce;
	bool	has_key_msg;
	bool	has_bssid;
	char	ssid[256];
	size_t	ssid_len;
	uint8_t	anonce[32];
	uint8_t	key_msg[128];
	size_t	key_msg_len;
	uint8_t	bssid[6];
} dpsk_key_value_payload_t;

static char const *dpsk_adapter_default_name(dpsk_adapter_conf_t const *adapter)
{
	if (!adapter) return "<unknown>";
	if (adapter->name) return adapter->name;

	switch (adapter->type) {
	case DPSK_ADAPTER_TYPE_KEY_VALUE_VSA:
		return "key_value_vsa";
	case DPSK_ADAPTER_TYPE_NAMED_VSA_ATTRS:
		return "named_vsa_attrs";
	case DPSK_ADAPTER_TYPE_STANDARD_ATTRS:
		return "standard_attrs";
	}

	return "<unknown>";
}

static bool dpsk_request_standard_is_configured(dpsk_standard_request_map_t const *map)
{
	return map && (map->username || map->ssid || map->called_station || map->anonce ||
		       map->key_msg || map->master_key || map->psk || map->psk_identity);
}

static bool dpsk_request_key_value_is_configured(dpsk_key_value_request_map_t const *map)
{
	return map && map->container_attr;
}

static bool dpsk_request_policy_is_complete(dpsk_adapter_conf_t const *adapter)
{
	if (!adapter) return false;

	switch (adapter->type) {
	case DPSK_ADAPTER_TYPE_STANDARD_ATTRS:
		return adapter->request.standard.ssid &&
		       adapter->request.standard.called_station &&
		       adapter->request.standard.anonce &&
		       adapter->request.standard.key_msg;

	case DPSK_ADAPTER_TYPE_NAMED_VSA_ATTRS:
		return adapter->request.named_vsa.ssid &&
		       adapter->request.named_vsa.called_station &&
		       adapter->request.named_vsa.anonce &&
		       adapter->request.named_vsa.key_msg;

	case DPSK_ADAPTER_TYPE_KEY_VALUE_VSA:
		return adapter->request.key_value.container_attr &&
		       adapter->request.key_value.ssid_key &&
		       adapter->request.key_value.called_station_key &&
		       adapter->request.key_value.anonce_key &&
		       adapter->request.key_value.key_msg_key;
	}

	return false;
}

static bool dpsk_vlan_policy_is_complete(dpsk_vlan_reply_t const *policy)
{
	if (!policy) return false;
	if (policy->mode == DPSK_VLAN_MODE_NONE) return true;

	return policy->tunnel_type_attr &&
	       policy->tunnel_medium_type_attr &&
	       policy->tunnel_private_group_id_attr;
}

static dpsk_reply_mode_t dpsk_reply_mode_for_adapter(dpsk_adapter_conf_t const *adapter)
{
	switch (adapter->type) {
	case DPSK_ADAPTER_TYPE_STANDARD_ATTRS:
		return DPSK_REPLY_MODE_STANDARD;
	case DPSK_ADAPTER_TYPE_NAMED_VSA_ATTRS:
		return DPSK_REPLY_MODE_TUNNEL_PASSWORD;
	case DPSK_ADAPTER_TYPE_KEY_VALUE_VSA:
		return DPSK_REPLY_MODE_AVPAIR_HEX_PMK;
	}

	return DPSK_REPLY_MODE_STANDARD;
}

static dpsk_reply_mode_t dpsk_reply_mode_for_policy(dpsk_adapter_conf_t const *adapter)
{
	if (!adapter) return DPSK_REPLY_MODE_STANDARD;

	if (!adapter->reply.mode_is_set) {
		return dpsk_reply_mode_for_adapter(adapter);
	}

	return adapter->reply.mode;
}

static bool dpsk_reply_policy_is_complete(dpsk_adapter_conf_t const *adapter)
{
	bool configured = false;

	if (!adapter) return false;
	if (!dpsk_vlan_policy_is_complete(&adapter->reply.vlan)) return false;

	switch (dpsk_reply_mode_for_policy(adapter)) {
	case DPSK_REPLY_MODE_STANDARD:
		configured = adapter->reply.standard.psk_attr && adapter->reply.standard.psk_identity_attr;
		break;
	case DPSK_REPLY_MODE_TUNNEL_PASSWORD:
		configured = adapter->reply.tunnel_password.psk_attr != NULL;
		break;
	case DPSK_REPLY_MODE_AVPAIR_HEX_PMK:
		configured = adapter->reply.avpair_hex_pmk.avpair_attr != NULL;
		break;
	case DPSK_REPLY_MODE_MS_MPPE_RECV_KEY:
		configured = adapter->reply.ms_mppe_recv_key.psk_attr != NULL;
		break;
	}

	return configured;
}

static int dpsk_input_set_string(request_t *request, fr_value_box_t *dst, fr_value_box_t const **active,
				 char const *value);
static int dpsk_input_set_octets(request_t *request, fr_value_box_t *dst, fr_value_box_t const **active,
				 uint8_t const *data, size_t data_len);
static int dpsk_resolve_standard_map(request_t *request, dpsk_request_input_t *input,
				     dpsk_standard_request_map_t const *map);
static bool dpsk_detect_from_rule(request_t *request, dpsk_detect_rule_t const *rule);
static void dpsk_collect_key_value_payload(request_t *request, dpsk_key_value_request_map_t const *map,
					   dpsk_key_value_payload_t *ctx);
static bool dpsk_key_value_keys_present(request_t *request, dpsk_key_value_request_map_t const *map);
static fr_pair_t *dpsk_find_pair_by_da_recursive(fr_pair_list_t const *list, fr_dict_attr_t const *da)
{
	fr_pair_t *vp, *found;

	for (vp = fr_pair_list_head(list); vp; vp = fr_pair_list_next(list, vp)) {
		if (vp->da == da) return vp;

		if (!fr_type_is_structural(vp->vp_type)) continue;

		found = dpsk_find_pair_by_da_recursive(&vp->vp_group, da);
		if (found) return found;
	}

	return NULL;
}

static void dpsk_resolve_default_input(dpsk_request_input_t *input, dpsk_auth_call_env_t *env)
{
	memset(input, 0, sizeof(*input));
	input->ssid = &env->ssid;
	input->anonce = &env->anonce;
	input->key_msg = &env->key_msg;
	input->username = &env->username;
	input->calledstation = &env->calledstation;
	input->masterkey = &env->masterkey;
	input->psk = &env->psk;
	input->psk_identity = &env->psk_identity;
	input->filename = ((env->filename.type == FR_TYPE_STRING) &&
			   env->filename.vb_strvalue &&
			   (env->filename.vb_length > 0)) ? env->filename.vb_strvalue : NULL;
}

static dpsk_source_t *dpsk_find_source_by_name(rlm_dpsk_t const *inst, char const *name)
{
	size_t i, source_count;

	if (!inst || !inst->sources || !name || (name[0] == '\0')) return NULL;

	source_count = talloc_array_length(inst->sources);
	for (i = 0; i < source_count; i++) {
		dpsk_source_t *source = inst->sources[i];

		if (!source || !source->name) continue;
		if (strcmp(source->name, name) == 0) return source;
	}

	return NULL;
}

static char const *dpsk_csv_filename_for_source(dpsk_source_t const *source)
{
	if (!source) return NULL;
	if (!source->csv.filename || (source->csv.filename[0] == '\0')) return NULL;
	return source->csv.filename;
}

static char const *dpsk_dup_filename(request_t *request, char const *filename)
{
	char *out;

	if (!filename || (filename[0] == '\0')) return NULL;

	out = talloc_strdup(request, filename);
	if (!out) {
		RPERROR("Failed allocating DPSK csv filename");
		return NULL;
	}

	RDEBUG2("Resolved DPSK filename from CSV source -> %s", out);
	return out;
}

static char const *dpsk_resolve_filename_from_sources(request_t *request, rlm_dpsk_t const *inst,
						      dpsk_adapter_conf_t const *adapter)
{
	size_t i;
	size_t source_count;
	char const *filename;
	dpsk_source_t *source;

	if (!inst || !inst->sources) return NULL;
	RDEBUG3("DPSK filename resolution: adapter=%s default_source=%s",
		adapter ? dpsk_adapter_default_name(adapter) : "<none>",
		inst->default_source_name ? inst->default_source_name : "<none>");

	if (adapter && adapter->source_names) {
		size_t adapter_source_count = talloc_array_length(adapter->source_names);

		for (i = 0; i < adapter_source_count; i++) {
			char const *source_name = adapter->source_names[i];

			if (!source_name) continue;
			source = dpsk_find_source_by_name(inst, source_name);
			filename = dpsk_csv_filename_for_source(source);
			if (filename) return dpsk_dup_filename(request, filename);
		}
	}

	source = dpsk_find_source_by_name(inst, inst->default_source_name);
	filename = dpsk_csv_filename_for_source(source);
	if (filename) return dpsk_dup_filename(request, filename);

	source_count = talloc_array_length(inst->sources);
	for (i = 0; i < source_count; i++) {
		source = inst->sources[i];
		filename = dpsk_csv_filename_for_source(source);
		if (filename) return dpsk_dup_filename(request, filename);
	}

	return NULL;
}

static bool dpsk_detect_standard_map(request_t *request, dpsk_standard_request_map_t const *map)
{
	if (!dpsk_request_standard_is_configured(map)) return false;
	if (!map->ssid_tmpl || !map->called_station_tmpl || !map->anonce_tmpl || !map->key_msg_tmpl) return false;

	return (dpsk_find_pair_by_tmpl(request, map->ssid_tmpl) != NULL) &&
	       (dpsk_find_pair_by_tmpl(request, map->called_station_tmpl) != NULL) &&
	       (dpsk_find_pair_by_tmpl(request, map->anonce_tmpl) != NULL) &&
	       (dpsk_find_pair_by_tmpl(request, map->key_msg_tmpl) != NULL);
}

static bool dpsk_detect_key_value_map(request_t *request, dpsk_key_value_request_map_t const *map)
{
	return dpsk_key_value_keys_present(request, map);
}

static bool dpsk_detect_configured(request_t *request, dpsk_adapter_conf_t const *conf)
{
	if (!conf) return false;

	if ((conf->detect.type != DPSK_DETECT_NONE) && dpsk_detect_from_rule(request, &conf->detect)) return true;

	switch (conf->type) {
	case DPSK_ADAPTER_TYPE_STANDARD_ATTRS:
		return dpsk_detect_standard_map(request, &conf->request.standard);

	case DPSK_ADAPTER_TYPE_NAMED_VSA_ATTRS:
		return dpsk_detect_standard_map(request, &conf->request.named_vsa);

	case DPSK_ADAPTER_TYPE_KEY_VALUE_VSA:
		return dpsk_detect_key_value_map(request, &conf->request.key_value);
	}

	return false;
}

static int dpsk_resolve_key_value_map(request_t *request, dpsk_request_input_t *input,
				      dpsk_key_value_request_map_t const *map, char const *adapter_name)
{
	dpsk_key_value_payload_t ctx;
	bool resolved = false;

	if (!map || !dpsk_request_key_value_is_configured(map)) return 0;

	memset(&ctx, 0, sizeof(ctx));
	dpsk_collect_key_value_payload(request, map, &ctx);

	if (dpsk_resolve_attr_pair_tmpl(request, map->username_tmpl, &input->resolved_username, &input->username) < 0) return -1;

	if (ctx.has_ssid && dpsk_input_set_string(request, &input->resolved_ssid, &input->ssid, ctx.ssid) < 0) return -1;
	if (ctx.has_ssid) resolved = true;

	if (ctx.has_anonce &&
	    dpsk_input_set_octets(request, &input->resolved_anonce, &input->anonce, ctx.anonce, sizeof(ctx.anonce)) < 0) {
		return -1;
	}
	if (ctx.has_anonce) resolved = true;

	if (ctx.has_key_msg &&
	    dpsk_input_set_octets(request, &input->resolved_key_msg, &input->key_msg, ctx.key_msg, ctx.key_msg_len) < 0) {
		return -1;
	}
	if (ctx.has_key_msg) resolved = true;

	if (ctx.has_bssid &&
	    dpsk_input_set_octets(request, &input->resolved_calledstation, &input->calledstation, ctx.bssid, sizeof(ctx.bssid)) < 0) {
		return -1;
	}
	if (ctx.has_bssid) resolved = true;

	if (resolved) RDEBUG2("Resolved DPSK %s payload from configured key/value attributes", adapter_name);
	return resolved ? 1 : 0;
}

static int dpsk_resolve_standard_map_input(request_t *request, dpsk_request_input_t *input,
					  dpsk_standard_request_map_t const *map, char const *adapter_name)
{
	if (dpsk_resolve_standard_map(request, input, map) < 0) return -1;

	if ((input->ssid == &input->resolved_ssid) ||
	    (input->anonce == &input->resolved_anonce) ||
	    (input->key_msg == &input->resolved_key_msg) ||
	    (input->calledstation == &input->resolved_calledstation) ||
	    (input->username == &input->resolved_username)) {
		RDEBUG2("Resolved DPSK %s payload from configured attributes", adapter_name);
		return 1;
	}

	return 0;
}

static int dpsk_resolve_configured_adapter_input(request_t *request, dpsk_adapter_conf_t const *conf,
						 dpsk_request_input_t *input)
{
	if (!conf) return 0;

	switch (conf->type) {
	case DPSK_ADAPTER_TYPE_STANDARD_ATTRS:
		return dpsk_resolve_standard_map_input(request, input, &conf->request.standard,
						       dpsk_adapter_default_name(conf));

	case DPSK_ADAPTER_TYPE_NAMED_VSA_ATTRS:
		return dpsk_resolve_standard_map_input(request, input, &conf->request.named_vsa,
						       dpsk_adapter_default_name(conf));

	case DPSK_ADAPTER_TYPE_KEY_VALUE_VSA:
		return dpsk_resolve_key_value_map(request, input, &conf->request.key_value,
						  dpsk_adapter_default_name(conf));
	}

	return 0;
}

static int dpsk_input_set_string(request_t *request, fr_value_box_t *dst, fr_value_box_t const **active,
				 char const *value)
{
	if (fr_value_box_strdup(request, dst, NULL, value, false) < 0) return -1;
	*active = dst;
	return 0;
}

static int dpsk_input_set_octets(request_t *request, fr_value_box_t *dst, fr_value_box_t const **active,
				 uint8_t const *data, size_t data_len)
{
	if (fr_value_box_memdup(request, dst, NULL, data, data_len, false) < 0) return -1;
	*active = dst;
	return 0;
}

static int dpsk_input_set_box(request_t *request, fr_value_box_t *dst, fr_value_box_t const **active,
			      fr_value_box_t const *src)
{
	if (fr_value_box_copy(request, dst, src) < 0) return -1;
	*active = dst;
	return 0;
}

static ssize_t dpsk_compile_attr_tmpl(TALLOC_CTX *ctx, tmpl_t **out,
				      char const *name, fr_dict_attr_t const *list_def)
{
	tmpl_rules_t rules = {
		.attr = {
			.dict_def = dict_radius,
			.list_def = list_def,
			.allow_unknown = true,
			.allow_unresolved = false,
			.allow_foreign = true,
		},
		.literals_safe_for = FR_VALUE_BOX_SAFE_FOR_ANY,
	};

	if (!name) {
		*out = NULL;
		return 0;
	}

	return tmpl_afrom_attr_str(ctx, NULL, out, name, &rules);
}

static fr_pair_t *dpsk_find_pair_by_tmpl(request_t *request, tmpl_t *vpt)
{
	fr_pair_t *vp;
	tmpl_dcursor_ctx_t cc;
	fr_dcursor_t cursor;
	fr_dict_attr_t const *da;

	if (!vpt) return NULL;

	vp = tmpl_dcursor_init(NULL, request, &cc, &cursor, request, vpt);
	da = tmpl_attr_tail_da(vpt);
	if (!vp && da) vp = dpsk_find_pair_by_da_recursive(&request->request_pairs, da);
	tmpl_dcursor_clear(&cc);

	return vp;
}

static int dpsk_append_reply_pair_by_tmpl(request_t *request, tmpl_t *vpt, fr_pair_t **out)
{
	if (!vpt) return -1;
	return (tmpl_find_or_add_vp(out, request, vpt) < 0) ? -1 : 0;
}

static int dpsk_append_new_reply_pair_by_tmpl(request_t *request, tmpl_t *vpt, fr_pair_t **out)
{
	fr_dict_attr_t const *da;

	if (!vpt) return -1;

	da = tmpl_attr_tail_da(vpt);
	if (!da) return -1;

	MEM(fr_pair_append_by_da_parent(request->reply_ctx, out, &request->reply_pairs, da) >= 0);
	return 0;
}

static bool dpsk_detect_attrs_present(request_t *request, tmpl_t * const *attrs_tmpls, bool require_all)
{
	size_t i;
	bool found_any = false;

	if (!attrs_tmpls) return false;

	for (i = 0; attrs_tmpls[i]; i++) {
		bool found = dpsk_find_pair_by_tmpl(request, attrs_tmpls[i]) != NULL;

		if (found) found_any = true;
		if (require_all && !found) return false;
		if (!require_all && found) return true;
	}

	return require_all ? found_any : false;
}

static bool dpsk_detect_from_rule(request_t *request, dpsk_detect_rule_t const *rule)
{
	size_t i;

	if (!rule) return false;

	switch (rule->type) {
	case DPSK_DETECT_ALL_PRESENT:
		return dpsk_detect_attrs_present(request, rule->attrs_tmpls, true);

	case DPSK_DETECT_ANY_PRESENT:
		return dpsk_detect_attrs_present(request, rule->attrs_tmpls, false);

	case DPSK_DETECT_CONTAINS_PREFIX:
		if (!rule->prefixes) return false;
		for (i = 0; rule->prefixes[i]; i++) {
			if (!dpsk_list_contains_prefix(&request->request_pairs, rule->prefixes[i])) return false;
		}
		return true;

	case DPSK_DETECT_NONE:
	default:
		return false;
	}
}

static int dpsk_resolve_attr_pair_tmpl(request_t *request, tmpl_t *vpt,
				       fr_value_box_t *dst, fr_value_box_t const **active)
{
	fr_pair_t *vp;

	if (!vpt) return 0;
	vp = dpsk_find_pair_by_tmpl(request, vpt);
	if (!vp) return 0;

	return dpsk_input_set_box(request, dst, active, &vp->data);
}

static int dpsk_resolve_standard_map(request_t *request, dpsk_request_input_t *input,
				     dpsk_standard_request_map_t const *map)
{
	if (!map) return 0;

	if (dpsk_resolve_attr_pair_tmpl(request, map->username_tmpl, &input->resolved_username, &input->username) < 0) return -1;
	if (dpsk_resolve_attr_pair_tmpl(request, map->ssid_tmpl, &input->resolved_ssid, &input->ssid) < 0) return -1;
	if (dpsk_resolve_attr_pair_tmpl(request, map->called_station_tmpl, &input->resolved_calledstation, &input->calledstation) < 0) return -1;
	if (dpsk_resolve_attr_pair_tmpl(request, map->anonce_tmpl, &input->resolved_anonce, &input->anonce) < 0) return -1;
	if (dpsk_resolve_attr_pair_tmpl(request, map->key_msg_tmpl, &input->resolved_key_msg, &input->key_msg) < 0) return -1;
	if (dpsk_resolve_attr_pair_tmpl(request, map->master_key_tmpl, &input->resolved_masterkey, &input->masterkey) < 0) return -1;
	if (dpsk_resolve_attr_pair_tmpl(request, map->psk_tmpl, &input->resolved_psk, &input->psk) < 0) return -1;
	if (dpsk_resolve_attr_pair_tmpl(request, map->psk_identity_tmpl, &input->resolved_psk_identity, &input->psk_identity) < 0) return -1;

	return 0;
}

static size_t dpsk_decode_radius_escaped(uint8_t *out, size_t outlen, char const *in, size_t inlen)
{
	size_t i, j;

	for (i = 0, j = 0; (i < inlen) && (j < outlen); i++) {
		if ((in[i] == '\\') && ((i + 1) < inlen)) {
			if ((in[i + 1] >= '0') && (in[i + 1] <= '7')) {
				unsigned int value = 0;
				size_t k;

				for (k = 1; (k <= 3) && ((i + k) < inlen); k++) {
					if ((in[i + k] < '0') || (in[i + k] > '7')) break;
					value = (value * 8) + (unsigned int) (in[i + k] - '0');
					if (value > UINT8_MAX) return 0;
				}

				out[j++] = (uint8_t) value;
				i += k - 1;
				continue;
			}

			switch (in[i + 1]) {
			case 'n': out[j++] = '\n'; i++; continue;
			case 'r': out[j++] = '\r'; i++; continue;
			case 't': out[j++] = '\t'; i++; continue;
			case '\\':
			case '"': out[j++] = (uint8_t) in[i + 1]; i++; continue;
			}
		}

		out[j++] = (uint8_t) in[i];
	}

	return j;
}

static int dpsk_parse_mac_text(uint8_t out[6], char const *value, size_t value_len)
{
	char buffer[13];
	size_t i, j;

	for (i = 0, j = 0; (i < value_len) && (j < 12); i++) {
		if (isxdigit((uint8_t) value[i])) buffer[j++] = value[i];
	}
	buffer[j] = '\0';

	if (j != 12) return -1;

	for (i = 0; i < 6; i++) {
		int hi = dpsk_hex_nibble(buffer[i * 2]);
		int lo = dpsk_hex_nibble(buffer[i * 2 + 1]);

		if ((hi < 0) || (lo < 0)) return -1;
		out[i] = (uint8_t) ((hi << 4) | lo);
	}

	return 0;
}

static bool dpsk_key_value_prefix_match(char const *value, size_t value_len, char const *key,
					char const **out, size_t *out_len)
{
	size_t prefix_len;

	if (!key) return false;

	prefix_len = strlen(key);
	if (value_len <= prefix_len) return false;
	if (strncasecmp(value, key, prefix_len) != 0) return false;
	if (value[prefix_len] != '=') return false;

	*out = value + prefix_len + 1;
	*out_len = value_len - prefix_len - 1;
	return true;
}

static void dpsk_collect_key_value_payload_list(fr_pair_list_t const *list, dpsk_key_value_request_map_t const *map,
						dpsk_key_value_payload_t *ctx)
{
	fr_pair_t *vp;

	for (vp = fr_pair_list_head(list);
	     vp;
	     vp = fr_pair_list_next(list, vp)) {
		char const *payload = NULL;
		size_t payload_len = 0;
		uint8_t decoded[256];
		size_t decoded_len;

		if (fr_type_is_structural(vp->vp_type)) {
			dpsk_collect_key_value_payload_list(&vp->vp_group, map, ctx);
			continue;
		}

		if ((vp->vp_type != FR_TYPE_STRING) || !vp->vp_strvalue) continue;

		if (dpsk_key_value_prefix_match(vp->vp_strvalue, vp->vp_length, map->called_station_key,
						&payload, &payload_len)) {
			if (dpsk_parse_mac_text(ctx->bssid, payload, payload_len) == 0) ctx->has_bssid = true;
			continue;
		}

		if (dpsk_key_value_prefix_match(vp->vp_strvalue, vp->vp_length, map->ssid_key,
						&payload, &payload_len)) {
			ctx->ssid_len = payload_len;
			if (ctx->ssid_len >= sizeof(ctx->ssid)) ctx->ssid_len = sizeof(ctx->ssid) - 1;
			memcpy(ctx->ssid, payload, ctx->ssid_len);
			ctx->ssid[ctx->ssid_len] = '\0';
			ctx->has_ssid = true;
			continue;
		}

		if (dpsk_key_value_prefix_match(vp->vp_strvalue, vp->vp_length, map->anonce_key,
						&payload, &payload_len)) {
			if (map->value_encoding == DPSK_VALUE_ENCODING_RADIUS_ESCAPED) {
				decoded_len = dpsk_decode_radius_escaped(decoded, sizeof(decoded), payload, payload_len);
			} else {
				decoded_len = payload_len;
				if (decoded_len > sizeof(decoded)) decoded_len = sizeof(decoded);
				memcpy(decoded, payload, decoded_len);
			}

			if (decoded_len == sizeof(ctx->anonce)) {
				memcpy(ctx->anonce, decoded, sizeof(ctx->anonce));
				ctx->has_anonce = true;
			}
			continue;
		}

		if (dpsk_key_value_prefix_match(vp->vp_strvalue, vp->vp_length, map->key_msg_key,
						&payload, &payload_len)) {
			if (map->value_encoding == DPSK_VALUE_ENCODING_RADIUS_ESCAPED) {
				decoded_len = dpsk_decode_radius_escaped(decoded, sizeof(decoded), payload, payload_len);
			} else {
				decoded_len = payload_len;
				if (decoded_len > sizeof(decoded)) decoded_len = sizeof(decoded);
				memcpy(decoded, payload, decoded_len);
			}

			if ((decoded_len >= sizeof(eapol_attr_t)) && (decoded_len <= sizeof(ctx->key_msg))) {
				memcpy(ctx->key_msg, decoded, decoded_len);
				ctx->key_msg_len = decoded_len;
				ctx->has_key_msg = true;
			}
			continue;
		}
	}
}

static void dpsk_collect_key_value_payload(request_t *request, dpsk_key_value_request_map_t const *map,
					   dpsk_key_value_payload_t *ctx)
{
	if (!map) return;
	dpsk_collect_key_value_payload_list(&request->request_pairs, map, ctx);
}

static bool dpsk_key_value_keys_present(request_t *request, dpsk_key_value_request_map_t const *map)
{
	bool has_ssid = false;
	bool has_called_station = false;
	bool has_anonce = false;
	bool has_key_msg = false;
	char prefix[256];

	if (!map) return false;
	if (!map->ssid_key || !map->called_station_key || !map->anonce_key || !map->key_msg_key) return false;

	if (snprintf(prefix, sizeof(prefix), "%s=", map->ssid_key) >= (int)sizeof(prefix)) return false;
	has_ssid = dpsk_list_contains_prefix(&request->request_pairs, prefix);

	if (snprintf(prefix, sizeof(prefix), "%s=", map->called_station_key) >= (int)sizeof(prefix)) return false;
	has_called_station = dpsk_list_contains_prefix(&request->request_pairs, prefix);

	if (snprintf(prefix, sizeof(prefix), "%s=", map->anonce_key) >= (int)sizeof(prefix)) return false;
	has_anonce = dpsk_list_contains_prefix(&request->request_pairs, prefix);

	if (snprintf(prefix, sizeof(prefix), "%s=", map->key_msg_key) >= (int)sizeof(prefix)) return false;
	has_key_msg = dpsk_list_contains_prefix(&request->request_pairs, prefix);

	return has_ssid && has_called_station && has_anonce && has_key_msg;
}

static int dpsk_add_vlan_reply_from_policy(request_t *request, dpsk_vlan_reply_t const *policy,
					   bool has_vlan, uint16_t vlan)
{
	fr_pair_t *vp;
	char vlan_buffer[8];

	if (!has_vlan) return 0;
	if (!policy || (policy->mode == DPSK_VLAN_MODE_NONE)) return 0;

	if (dpsk_append_reply_pair_by_tmpl(request, policy->tunnel_type_attr_tmpl, &vp) < 0) return -1;
	vp->vp_uint32 = policy->tunnel_type_value ? policy->tunnel_type_value : 13;

	if (dpsk_append_reply_pair_by_tmpl(request, policy->tunnel_medium_type_attr_tmpl, &vp) < 0) return -1;
	vp->vp_uint32 = policy->tunnel_medium_type_value ? policy->tunnel_medium_type_value : 6;

	snprintf(vlan_buffer, sizeof(vlan_buffer), "%u", vlan);
	if (dpsk_append_reply_pair_by_tmpl(request, policy->tunnel_private_group_id_attr_tmpl, &vp) < 0) return -1;
	fr_pair_value_bstrndup(vp, vlan_buffer, strlen(vlan_buffer), true);
	return 0;
}

static int dpsk_set_reply_octets(fr_pair_t *vp, uint8_t const *data, size_t data_len)
{
	return fr_pair_value_memdup(vp, data, data_len, false);
}

static unlang_action_t dpsk_add_reply_from_policy(unlang_result_t *p_result, request_t *request,
						  dpsk_reply_policy_t const *policy,
						  char const *psk, size_t psk_len, char const *psk_identity,
						  bool has_vlan, uint16_t vlan, uint8_t const pmk[32],
						  rlm_rcode_t rcode)
{
	fr_pair_t *vp;
	char psk_hex[65];
	size_t i;

	switch (policy->mode) {
	case DPSK_REPLY_MODE_STANDARD:
		if (dpsk_append_reply_pair_by_tmpl(request, policy->standard.psk_attr_tmpl, &vp) < 0) RETURN_UNLANG_FAIL;
		fr_pair_value_bstrndup(vp, psk, psk_len, true);
		if (dpsk_append_reply_pair_by_tmpl(request, policy->standard.psk_identity_attr_tmpl, &vp) < 0) RETURN_UNLANG_FAIL;
		fr_pair_value_bstrndup(vp, psk_identity, strlen(psk_identity), true);
		if (dpsk_add_vlan_reply_from_policy(request, &policy->vlan, has_vlan, vlan) < 0) RETURN_UNLANG_FAIL;
		break;

	case DPSK_REPLY_MODE_TUNNEL_PASSWORD:
		if (dpsk_append_reply_pair_by_tmpl(request, policy->tunnel_password.psk_attr_tmpl, &vp) < 0) RETURN_UNLANG_FAIL;
		fr_pair_value_bstrndup(vp, psk, psk_len, true);
		if (dpsk_add_vlan_reply_from_policy(request, &policy->vlan, has_vlan, vlan) < 0) RETURN_UNLANG_FAIL;
		break;

	case DPSK_REPLY_MODE_AVPAIR_HEX_PMK:
		if (dpsk_add_vlan_reply_from_policy(request, &policy->vlan, has_vlan, vlan) < 0) RETURN_UNLANG_FAIL;
		fr_base16_encode(&FR_SBUFF_OUT(psk_hex, sizeof(psk_hex)), &FR_DBUFF_TMP(pmk, 32));
		if (dpsk_append_new_reply_pair_by_tmpl(request, policy->avpair_hex_pmk.avpair_attr_tmpl, &vp) < 0) RETURN_UNLANG_FAIL;
		fr_pair_value_aprintf(vp, "%s=%s",
				      policy->avpair_hex_pmk.pmk_key ? policy->avpair_hex_pmk.pmk_key : "psk",
				      psk_hex);
		for (i = 0; policy->avpair_hex_pmk.extra_pairs && policy->avpair_hex_pmk.extra_pairs[i]; i++) {
			if (dpsk_append_new_reply_pair_by_tmpl(request, policy->avpair_hex_pmk.avpair_attr_tmpl, &vp) < 0) RETURN_UNLANG_FAIL;
			fr_pair_value_bstrndup(vp, policy->avpair_hex_pmk.extra_pairs[i],
					       strlen(policy->avpair_hex_pmk.extra_pairs[i]), true);
		}
		memset(psk_hex, 0, sizeof(psk_hex));
		break;

	case DPSK_REPLY_MODE_MS_MPPE_RECV_KEY:
		if (dpsk_append_reply_pair_by_tmpl(request, policy->ms_mppe_recv_key.psk_attr_tmpl, &vp) < 0) RETURN_UNLANG_FAIL;
		if (dpsk_set_reply_octets(vp, pmk, 32) < 0) RETURN_UNLANG_FAIL;
		if (policy->ms_mppe_recv_key.session_timeout_attr && policy->ms_mppe_recv_key.session_timeout) {
			if (dpsk_append_reply_pair_by_tmpl(request, policy->ms_mppe_recv_key.session_timeout_attr_tmpl, &vp) < 0) {
				RETURN_UNLANG_FAIL;
			}
			vp->vp_uint32 = policy->ms_mppe_recv_key.session_timeout;
		}
		if (policy->ms_mppe_recv_key.username_attr) {
			if (dpsk_append_reply_pair_by_tmpl(request, policy->ms_mppe_recv_key.username_attr_tmpl, &vp) < 0) RETURN_UNLANG_FAIL;
			fr_pair_value_bstrndup(vp, psk_identity, strlen(psk_identity), true);
		}
		if (policy->ms_mppe_recv_key.role_attr) {
			if (dpsk_append_reply_pair_by_tmpl(request, policy->ms_mppe_recv_key.role_attr_tmpl, &vp) < 0) RETURN_UNLANG_FAIL;
			fr_pair_value_bstrndup(vp, psk_identity, strlen(psk_identity), true);
		}
		if (policy->ms_mppe_recv_key.reply_message_attr) {
			if (dpsk_append_reply_pair_by_tmpl(request, policy->ms_mppe_recv_key.reply_message_attr_tmpl, &vp) < 0) {
				RETURN_UNLANG_FAIL;
			}
			fr_pair_value_bstrndup(vp, psk_identity, strlen(psk_identity), true);
		}
		if (dpsk_add_vlan_reply_from_policy(request, &policy->vlan, has_vlan, vlan) < 0) RETURN_UNLANG_FAIL;
		break;
	}

	if (rcode == RLM_MODULE_OK) RETURN_UNLANG_OK;
	RETURN_UNLANG_UPDATED;
}

static unlang_action_t dpsk_add_configured_adapter_reply(unlang_result_t *p_result, request_t *request,
							 dpsk_adapter_conf_t const *conf,
							 UNUSED dpsk_auth_call_env_t *env,
							 char const *psk, size_t psk_len, char const *psk_identity,
							 bool has_vlan, uint16_t vlan,
							 uint8_t const pmk[32], rlm_rcode_t rcode)
{
	dpsk_reply_policy_t policy;

	if (!conf) {
		RERROR("Adapter '%s' has no configured reply policy",
		       "<unknown>");
		RETURN_UNLANG_FAIL;
	}

	if (!dpsk_reply_policy_is_complete(conf)) {
		RERROR("Adapter '%s' has no configured reply policy",
		       dpsk_adapter_default_name(conf));
		RETURN_UNLANG_FAIL;
	}

	policy = conf->reply;
	if (!policy.mode_is_set) {
		policy.mode = dpsk_reply_mode_for_adapter(conf);
	}

	return dpsk_add_reply_from_policy(p_result, request, &policy, psk, psk_len,
					  psk_identity, has_vlan, vlan, pmk, rcode);
}

static dpsk_adapter_runtime_t const dpsk_configured_adapter = {
	.name = "configured",
	.detect = dpsk_detect_configured,
	.resolve_input = dpsk_resolve_configured_adapter_input,
	.add_reply = dpsk_add_configured_adapter_reply,
};

static rlm_rcode_t dpsk_match_candidate(request_t *request, dpsk_request_input_t *input,
					dpsk_verify_ctx_t const *verify, uint8_t const client_mac[6],
					uint8_t const authenticator_mac[6], uint8_t const pmk[32],
					char const *label, char const *identity,
					bool has_client_mac, uint8_t const candidate_mac[6])
{
	uint8_t mic[16];
	char mac_buffer[13];
	int verify_rcode;

	if (has_client_mac) dpsk_format_mac(mac_buffer, candidate_mac);
	RDEBUG("%s candidate identity=%s psk=<redacted> mac=%s", label, identity, has_client_mac ? mac_buffer : "<any>");

	verify_rcode = dpsk_verify_candidate(verify, input->anonce->vb_octets, client_mac, authenticator_mac, pmk, mic);
	if (verify_rcode < 0) return RLM_MODULE_FAIL;
	if (verify_rcode == 0) return RLM_MODULE_OK;

	if (verify_rcode == 1) {
		RHEXDUMP2(verify->packet_mic, 16, "packet-mic:");
		RHEXDUMP2(mic, 16, "calc-mic  :");
	}

	return RLM_MODULE_NOOP;
}

static rlm_rcode_t dpsk_try_preloaded_file(request_t *request, rlm_dpsk_t const *inst, dpsk_request_input_t *input,
					   char const *filename, uint8_t const client_mac[6],
					   uint8_t const authenticator_mac[6], dpsk_verify_ctx_t const *verify,
					   uint8_t *pmk_out,
					   char const **psk_identity_out, char const **psk_out, size_t *psk_len_out,
					   bool *has_vlan_out, uint16_t *vlan_out)
{
	dpsk_file_t *file;
	dpsk_file_bucket_t *bucket;
	dpsk_file_entry_t *entry;
	rlm_rcode_t rcode;

	pthread_mutex_lock(&inst->mutable->mutex);
	file = dpsk_get_file_for_request(request, inst, filename, input->ssid);
	if (!file) {
		pthread_mutex_unlock(&inst->mutable->mutex);
		return RLM_MODULE_FAIL;
	}

	bucket = dpsk_find_bucket(file, client_mac, false);
	for (entry = bucket ? bucket->entries : NULL; entry; entry = entry->next_by_client) {
		rcode = dpsk_match_candidate(request, input, verify, client_mac, authenticator_mac,
					     entry->pmk, "client-bound", entry->identity,
					     true, entry->client_mac);
		if (rcode == RLM_MODULE_OK) {
			char *identity_copy, *psk_copy;

			memcpy(pmk_out, entry->pmk, 32);
			MEM(identity_copy = talloc_strdup(request, entry->identity));
			MEM(psk_copy = talloc_strdup(request, entry->psk));
			*psk_identity_out = identity_copy;
			*psk_out = psk_copy;
			*psk_len_out = entry->psk_len;
			*has_vlan_out = entry->has_vlan;
			*vlan_out = entry->vlan;
			pthread_mutex_unlock(&inst->mutable->mutex);
			return RLM_MODULE_UPDATED;
		}
		if (rcode == RLM_MODULE_FAIL) {
			pthread_mutex_unlock(&inst->mutable->mutex);
			return rcode;
		}
	}

	for (entry = file->fallback_entries; entry; entry = entry->fallback_next) {
		rcode = dpsk_match_candidate(request, input, verify, client_mac, authenticator_mac,
					     entry->pmk, "fallback", entry->identity,
					     false, NULL);
		if (rcode == RLM_MODULE_OK) {
			char *identity_copy, *psk_copy;

			memcpy(pmk_out, entry->pmk, 32);
			MEM(identity_copy = talloc_strdup(request, entry->identity));
			MEM(psk_copy = talloc_strdup(request, entry->psk));
			*psk_identity_out = identity_copy;
			*psk_out = psk_copy;
			*psk_len_out = entry->psk_len;
			*has_vlan_out = entry->has_vlan;
			*vlan_out = entry->vlan;
			pthread_mutex_unlock(&inst->mutable->mutex);
			return RLM_MODULE_UPDATED;
		}
		if (rcode == RLM_MODULE_FAIL) {
			pthread_mutex_unlock(&inst->mutable->mutex);
			return rcode;
		}
	}

	pthread_mutex_unlock(&inst->mutable->mutex);
	return RLM_MODULE_FAIL;
}



static unlang_action_t CC_HINT(nonnull) mod_authenticate(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_dpsk_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_dpsk_t);
	dpsk_auth_call_env_t	*env = talloc_get_type_abort(mctx->env_data, dpsk_auth_call_env_t);
	dpsk_request_input_t	input;
	rlm_dpsk_cache_t	*entry = NULL;
	int			stage = 0;
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	dpsk_adapter_runtime_t const	*adapter;
	size_t			psk_len = 0;
	dpsk_verify_ctx_t	verify;
	char const		*filename;
	char const		*psk_identity = NULL, *psk = NULL;
	uint8_t			pmk[32];
	uint8_t			s_mac[6];
	uint8_t const		*ap_mac;
	bool			has_vlan = false;
	uint16_t		vlan = 0;

	/*
	 *	Search for the information in a bunch of attributes.
	 */
	dpsk_resolve_default_input(&input, env);
	adapter = dpsk_select_adapter(inst, request);
	if (!adapter) {
		RDEBUG2("No configured dpsk adapter matched this request");
		RETURN_UNLANG_NOOP;
	}
	if (!input.filename) input.filename = dpsk_resolve_filename_from_sources(request, inst, adapter->conf);
	filename = input.filename;

	if ((input.anonce->vb_length != 32) ||
	    (input.key_msg->vb_length < sizeof(eapol_attr_t)) ||
	    (input.key_msg->vb_length > sizeof(verify.frame)) ||
	    (input.calledstation->vb_length != 6)) {
		if (adapter->resolve_input(request, adapter->conf, &input) < 0) {
			RERROR("Failed resolving %s DPSK payload", adapter->name);
			RETURN_UNLANG_FAIL;
		}
	}
	if (input.anonce->vb_length != 32) {
		RWARN("%s has incorrect length (%zu, not 32)", env->anonce_tmpl->name, input.anonce->vb_length);
		RETURN_UNLANG_NOOP;
	}

	if (input.key_msg->vb_length < sizeof(eapol_attr_t)) {
		RWARN("%s has incorrect length (%zu < %zu)", env->key_msg_tmpl->name, input.key_msg->vb_length, sizeof(eapol_attr_t));
		RETURN_UNLANG_NOOP;
	}

	if (input.key_msg->vb_length > sizeof(verify.frame)) {
		RWARN("%s has incorrect length (%zu > %zu)", env->key_msg_tmpl->name, input.key_msg->vb_length, sizeof(verify.frame));
		RETURN_UNLANG_NOOP;
	}

	/*
	 *	At this point, the request has the relevant DPSK
	 *	attributes.  The module now should return FAIL for
	 *	missing / invalid attributes, or REJECT for
	 *	authentication failure.
	 *
	 *	If the entry is found in a VP or a cache, the module
	 *	returns OK.  This means that the caller should not
	 *	save &control:Pre-Shared-Key somewhere.
	 *
	 *	If the module found a matching entry in the file, it
	 *	returns UPDATED to indicate that the caller should
	 *	update the database with the PSK which was found.
	 */

#ifdef __COVERITY__
	/*
	 * Coverity doesn't see that fr_base16_decode will populate s_mac
	 */
	memset(s_mac, 0, 6);
#endif
	/*
	 *	Get supplicant MAC address from the User-Name
	 */
	if (fr_base16_decode(NULL, &FR_DBUFF_TMP(s_mac, sizeof(s_mac)),
		       &FR_SBUFF_IN(input.username->vb_strvalue, input.username->vb_length), false) != 6) {
		RERROR("User-Name is not a recognizable hex MAC address");
		RETURN_UNLANG_FAIL;
	}

	if (input.calledstation->vb_length != 6) {
		RERROR("Called-Station-MAC is not a recognizable MAC address");
		RETURN_UNLANG_FAIL;
	}

	ap_mac = input.calledstation->vb_octets;
	dpsk_rdebug_mac(request, "DPSK authenticator MAC=", ap_mac);
	if (dpsk_prepare_verify_ctx(request, &verify, input.key_msg->vb_octets, input.key_msg->vb_length) < 0) {
		RERROR("Failed parsing EAPOL key data");
		RETURN_UNLANG_FAIL;
	}
	RDEBUG2("DPSK use_sha256=%s use_hostap_pmf=%s", verify.use_sha256 ? "true" : "false",
		verify.use_hostap_pmf ? "true" : "false");

	/*
	 *	If we're caching, then check the cache first, before
	 *	trying the file.  This check allows us to avoid the
	 *	PMK calculation in many situations, as that can be
	 *	expensive.
	 */
	if (inst->cache_size) {
		pthread_mutex_lock(&inst->mutable->mutex);
		entry = dpsk_cache_find(request, inst, pmk, sizeof(pmk), input.ssid, filename, s_mac);
		if (entry) {
			if (dpsk_cache_entry_dup(request, entry, &psk_identity, &psk, &psk_len, &has_vlan, &vlan) < 0) {
				pthread_mutex_unlock(&inst->mutable->mutex);
				RETURN_UNLANG_FAIL;
			}
			pthread_mutex_unlock(&inst->mutable->mutex);
			goto make_digest;
		}
		pthread_mutex_unlock(&inst->mutable->mutex);
	}

	/*
	 *	No cache, or no cache entry.  Look for an external PMK
	 *	taken from a database.
	 */
stage1:
	stage = 1;

	if (input.masterkey->type == FR_TYPE_OCTETS) {
		if (input.masterkey->vb_length != sizeof(pmk)) {
			RWARN("%s has incorrect length (%zu != %zu) - ignoring it", env->masterkey_tmpl->name,
			      input.masterkey->vb_length, sizeof(pmk));
		} else {
			RDEBUG2("Using %s", env->masterkey_tmpl->name);
			memcpy(pmk, input.masterkey->vb_octets, sizeof(pmk));
			goto make_digest;
		}
	}

	/*
	 *	No external PMK.  Try an external PSK.
	 */
	if (input.psk->type == FR_TYPE_STRING) {
		RDEBUG3("Trying %s", env->psk_tmpl->name);
		if (generate_pmk(request, pmk, sizeof(pmk), input.ssid, input.psk->vb_strvalue, input.psk->vb_length) < 0) {
			RETURN_UNLANG_FAIL;
		}

		if (input.psk_identity->type == FR_TYPE_STRING) {
			psk_identity = input.psk_identity->vb_strvalue;
		} else {
			psk_identity = input.username->vb_strvalue;
		}

		psk = input.psk->vb_strvalue;
		psk_len = input.psk->vb_length;

		goto make_digest;
	}

	/*
	 *	No external PSK was found.  If there's no file, then
	 *	we can't do anything else.
	 */
stage2:
	stage = 2;

	if (!filename) {
		RERROR("No %s was found, and no 'filename' was configured", env->psk_tmpl->name);
		RETURN_UNLANG_FAIL;
	}

	rcode = dpsk_try_preloaded_file(request, inst, &input, filename, s_mac, ap_mac, &verify, pmk,
					&psk_identity, &psk, &psk_len, &has_vlan, &vlan);
	if (rcode != RLM_MODULE_UPDATED) RETURN_UNLANG_FAIL;
	goto matched;
make_digest:
	rcode = dpsk_match_candidate(request, &input, &verify, s_mac, ap_mac, pmk, "selected",
				     psk_identity ? psk_identity : "<unknown>", false, NULL);
	if (rcode != RLM_MODULE_OK) {
		psk_identity = NULL;
		psk = NULL;
		psk_len = 0;

		if (stage == 0) {
			fr_assert(entry != NULL);
			pthread_mutex_lock(&inst->mutable->mutex);
			fr_rb_delete(&inst->mutable->cache, entry);
			pthread_mutex_unlock(&inst->mutable->mutex);
			entry = NULL;
			goto stage1;
		}

		if (stage == 1) {
			if (env->psk.type == FR_TYPE_STRING) RWARN("%s did not match", env->psk_tmpl->name);

			if (filename) {
				RDEBUG("Checking file %s for PSK and MAC", filename);
				goto stage2;
			}

			RWARN("No 'filename' was configured.");
			RETURN_UNLANG_REJECT;
		}

		if (rcode == RLM_MODULE_FAIL) RETURN_UNLANG_FAIL;
		RETURN_UNLANG_FAIL;
	}

matched:

	/*
	 *	Extend the lifetime of the cache entry, or add the
	 *	cache entry if necessary.  We only add / update the
	 *	cache entry if the PSK was not found in a VP.
	 *
	 *	If the caller gave us only a PMK, then don't cache anything.
	 */
	if (inst->cache_size && psk && psk_identity) {
		rlm_dpsk_cache_t my_entry;
		pthread_mutex_lock(&inst->mutable->mutex);

		/*
		 *	We've found an entry. Just update it.
		 */
		if (entry) goto update_entry;

		/*
		 *	No cached entry, or the PSK in the cached
		 *	entry didn't match.  We need to create one.
		 */
		memcpy(my_entry.mac, s_mac, sizeof(my_entry.mac));
		memcpy(&my_entry.ssid, &input.ssid->vb_octets, sizeof(my_entry.ssid)); /* const ptr issues */
		my_entry.ssid_len = input.ssid->vb_length;
		my_entry.filename = filename;
		my_entry.filename_len = filename ? strlen(filename) : 0;

		entry = fr_rb_find(&inst->mutable->cache, &my_entry);
		if (!entry) {
			/*
			 *	Maybe there are oo many entries in the
			 *	cache.  If so, delete the oldest one.
			 */
			if (fr_rb_num_elements(&inst->mutable->cache) > inst->cache_size) {
				entry = fr_dlist_head(&inst->mutable->head);
				fr_rb_delete(&inst->mutable->cache, entry); /* locks and unlinks the entry */
			}

			MEM(entry = talloc_zero(&inst->mutable->cache, rlm_dpsk_cache_t));

			memcpy(entry->mac, s_mac, sizeof(entry->mac));
			memcpy(entry->pmk, pmk, sizeof(entry->pmk));

			entry->inst = inst;

			/*
			 *	Save the SSID, PSK, and PSK identity in the cache entry.
			 */
			MEM(entry->ssid = talloc_memdup(entry, input.ssid->vb_octets, input.ssid->vb_length));
			entry->ssid_len = input.ssid->vb_length;
			if (filename) {
				entry->filename_len = strlen(filename);
				MEM(entry->filename = talloc_strdup(entry, filename));
			}

			MEM(entry->psk = talloc_strdup(entry, psk));
			entry->psk_len = psk_len;
			entry->has_vlan = has_vlan;
			entry->vlan = vlan;

			entry->identity_len = strlen(psk_identity);
			MEM(entry->identity = talloc_strdup(entry, psk_identity));

			/*
			 *	Cache it.
			 */
			if (!fr_rb_insert(&inst->mutable->cache, entry)) {
				TALLOC_FREE(entry);
				pthread_mutex_unlock(&inst->mutable->mutex);
				goto update_attributes;
			}
			RDEBUG3("Cache entry saved");
		}

	update_entry:
		entry->has_vlan = has_vlan;
		entry->vlan = vlan;
		entry->expires = fr_time_add(fr_time(), inst->cache_lifetime);
		if (fr_dlist_entry_in_list(&entry->dlist)) fr_dlist_remove(&inst->mutable->head, entry);
		fr_dlist_insert_tail(&inst->mutable->head, entry);
		pthread_mutex_unlock(&inst->mutable->mutex);

	}

update_attributes:
	fr_assert(psk != NULL);
	fr_assert(psk_identity != NULL);

	return adapter->add_reply(p_result, request, adapter->conf, env, psk, psk_len, psk_identity,
				  has_vlan, vlan, pmk, rcode);
}

static xlat_arg_parser_t const dpsk_pmk_xlat_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** xlat to generate the PMK from SSID and Pre-Shared-Key
 *
 * Example:
 @verbatim
 %dpsk.pmk(Calling-Station-SSID, Pre-Shared-Key)
 @endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t dpsk_pmk_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
			       request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t	*ssid, *psk, *vb;
	uint8_t		buffer[32];

	XLAT_ARGS(in, &ssid, &psk);

	if (PKCS5_PBKDF2_HMAC_SHA1(psk->vb_strvalue, psk->vb_length,
				   (const unsigned char *) ssid->vb_strvalue, ssid->vb_length,
				   4096, sizeof(buffer), buffer) == 0) {
		RERROR("Failed calling OpenSSL to calculate the PMK");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_OCTETS, NULL));
	fr_value_box_memdup(vb, vb, NULL, buffer, sizeof(buffer), true);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static int mod_load(void)
{
	xlat_t	*xlat;
	if (unlikely((xlat = xlat_func_register(NULL, "dpsk.pmk", dpsk_pmk_xlat, FR_TYPE_OCTETS)) == NULL)) return -1;
	xlat_func_args_set(xlat, dpsk_pmk_xlat_arg);

	return 0;
}

static void mod_unload(void)
{
	xlat_func_unregister("dpsk.pmk");
}

static void dpsk_adapter_priority_set_default(dpsk_adapter_conf_t *adapter)
{
	if (adapter->priority) return;

	switch (adapter->type) {
	case DPSK_ADAPTER_TYPE_KEY_VALUE_VSA:
		adapter->priority = 20;
		return;
	case DPSK_ADAPTER_TYPE_NAMED_VSA_ATTRS:
		adapter->priority = 30;
		return;
	case DPSK_ADAPTER_TYPE_STANDARD_ATTRS:
		adapter->priority = 100;
		return;
	}
}

static int dpsk_request_policy_validate(module_inst_ctx_t const *mctx, dpsk_adapter_conf_t const *adapter)
{
	if (dpsk_request_policy_is_complete(adapter)) return 0;

	cf_log_err(mctx->mi->conf,
		   "dpsk adapter '%s' must define a complete request policy for its adapter type",
		   dpsk_adapter_default_name(adapter));
	return -1;
}

static int dpsk_reply_policy_validate(module_inst_ctx_t const *mctx, dpsk_adapter_conf_t const *adapter)
{
	if (dpsk_reply_policy_is_complete(adapter)) return 0;

	cf_log_err(mctx->mi->conf,
		   "dpsk adapter '%s' must define a complete reply policy for its adapter type",
		   dpsk_adapter_default_name(adapter));
	return -1;
}

static dpsk_adapter_runtime_t const *dpsk_runtime_template_for_conf(dpsk_adapter_conf_t const *conf)
{
	if (!conf) return NULL;
	return &dpsk_configured_adapter;
}

static int dpsk_compile_request_attr(TALLOC_CTX *ctx, tmpl_t **out, char const *name)
{
	if (!name) {
		*out = NULL;
		return 0;
	}

	if (dpsk_compile_attr_tmpl(ctx, out, name, request_attr_request) <= 0) return -1;
	return 0;
}

static int dpsk_compile_reply_attr(TALLOC_CTX *ctx, tmpl_t **out, char const *name)
{
	if (!name) {
		*out = NULL;
		return 0;
	}

	if (dpsk_compile_attr_tmpl(ctx, out, name, request_attr_reply) <= 0) return -1;
	return 0;
}

static int dpsk_compile_standard_request_map_tmpls(TALLOC_CTX *ctx, dpsk_standard_request_map_t *map)
{
	if (!map) return 0;

	if (dpsk_compile_request_attr(ctx, &map->username_tmpl, map->username) < 0) return -1;
	if (dpsk_compile_request_attr(ctx, &map->ssid_tmpl, map->ssid) < 0) return -1;
	if (dpsk_compile_request_attr(ctx, &map->called_station_tmpl, map->called_station) < 0) return -1;
	if (dpsk_compile_request_attr(ctx, &map->anonce_tmpl, map->anonce) < 0) return -1;
	if (dpsk_compile_request_attr(ctx, &map->key_msg_tmpl, map->key_msg) < 0) return -1;
	if (dpsk_compile_request_attr(ctx, &map->master_key_tmpl, map->master_key) < 0) return -1;
	if (dpsk_compile_request_attr(ctx, &map->psk_tmpl, map->psk) < 0) return -1;
	if (dpsk_compile_request_attr(ctx, &map->psk_identity_tmpl, map->psk_identity) < 0) return -1;

	return 0;
}

static int dpsk_compile_reply_policy_tmpls(TALLOC_CTX *ctx, dpsk_reply_policy_t *policy)
{
	if (!policy) return 0;

	if (dpsk_compile_reply_attr(ctx, &policy->vlan.tunnel_type_attr_tmpl, policy->vlan.tunnel_type_attr) < 0) return -1;
	if (dpsk_compile_reply_attr(ctx, &policy->vlan.tunnel_medium_type_attr_tmpl, policy->vlan.tunnel_medium_type_attr) < 0) return -1;
	if (dpsk_compile_reply_attr(ctx, &policy->vlan.tunnel_private_group_id_attr_tmpl, policy->vlan.tunnel_private_group_id_attr) < 0) return -1;

	if (dpsk_compile_reply_attr(ctx, &policy->standard.psk_attr_tmpl, policy->standard.psk_attr) < 0) return -1;
	if (dpsk_compile_reply_attr(ctx, &policy->standard.psk_identity_attr_tmpl, policy->standard.psk_identity_attr) < 0) return -1;

	if (dpsk_compile_reply_attr(ctx, &policy->tunnel_password.psk_attr_tmpl, policy->tunnel_password.psk_attr) < 0) return -1;

	if (dpsk_compile_reply_attr(ctx, &policy->avpair_hex_pmk.avpair_attr_tmpl, policy->avpair_hex_pmk.avpair_attr) < 0) return -1;

	if (dpsk_compile_reply_attr(ctx, &policy->ms_mppe_recv_key.psk_attr_tmpl, policy->ms_mppe_recv_key.psk_attr) < 0) return -1;
	if (dpsk_compile_reply_attr(ctx, &policy->ms_mppe_recv_key.session_timeout_attr_tmpl, policy->ms_mppe_recv_key.session_timeout_attr) < 0) return -1;
	if (dpsk_compile_reply_attr(ctx, &policy->ms_mppe_recv_key.username_attr_tmpl, policy->ms_mppe_recv_key.username_attr) < 0) return -1;
	if (dpsk_compile_reply_attr(ctx, &policy->ms_mppe_recv_key.role_attr_tmpl, policy->ms_mppe_recv_key.role_attr) < 0) return -1;
	if (dpsk_compile_reply_attr(ctx, &policy->ms_mppe_recv_key.reply_message_attr_tmpl, policy->ms_mppe_recv_key.reply_message_attr) < 0) return -1;

	return 0;
}

static int dpsk_compile_detect_rule_tmpls(TALLOC_CTX *ctx, dpsk_detect_rule_t *rule)
{
	size_t i, count;

	if (!rule) return 0;
	if (!rule->attrs) return 0;

	count = talloc_array_length(rule->attrs);
	if (!count) return 0;

	MEM(rule->attrs_tmpls = talloc_zero_array(ctx, tmpl_t *, count));

	for (i = 0; i < (count - 1); i++) {
		if (!rule->attrs[i]) break;
		if (dpsk_compile_request_attr(ctx, &rule->attrs_tmpls[i], rule->attrs[i]) < 0) return -1;
	}

	return 0;
}

static int dpsk_compile_adapter_tmpls(module_inst_ctx_t const *mctx, dpsk_adapter_conf_t *adapter)
{
	if (dpsk_compile_detect_rule_tmpls(adapter, &adapter->detect) < 0) goto error;

	switch (adapter->type) {
	case DPSK_ADAPTER_TYPE_STANDARD_ATTRS:
		if (dpsk_compile_standard_request_map_tmpls(adapter, &adapter->request.standard) < 0) goto error;
		break;

	case DPSK_ADAPTER_TYPE_NAMED_VSA_ATTRS:
		if (dpsk_compile_standard_request_map_tmpls(adapter, &adapter->request.named_vsa) < 0) goto error;
		break;

	case DPSK_ADAPTER_TYPE_KEY_VALUE_VSA:
		if (dpsk_compile_request_attr(adapter, &adapter->request.key_value.username_tmpl,
					      adapter->request.key_value.username) < 0) goto error;
		break;
	}

	if (dpsk_compile_reply_policy_tmpls(adapter, &adapter->reply) < 0) goto error;

	return 0;

error:
	cf_log_err(mctx->mi->conf, "Failed compiling attribute template(s) for dpsk adapter '%s'",
		   dpsk_adapter_default_name(adapter));
	return -1;
}

static int dpsk_adapter_runtime_cmp(dpsk_adapter_runtime_t const *a, dpsk_adapter_runtime_t const *b)
{
	if (a->conf->priority < b->conf->priority) return -1;
	if (a->conf->priority > b->conf->priority) return +1;
	return 0;
}

static int dpsk_bind_adapter_order(module_inst_ctx_t const *mctx, rlm_dpsk_t *inst)
{
	size_t i, count = 0, insert;

	if (!inst->adapters) return 0;

	count = talloc_array_length(inst->adapters);
	if (!count) return 0;

	MEM(inst->adapter_order = talloc_zero_array(inst, dpsk_adapter_runtime_t *, count + 1));

	for (i = 0; i < count; i++) {
		dpsk_adapter_conf_t *conf = inst->adapters[i];
		dpsk_adapter_runtime_t const *tmpl;
		dpsk_adapter_runtime_t *runtime;

		tmpl = dpsk_runtime_template_for_conf(conf);
		if (!tmpl) {
			cf_log_err(mctx->mi->conf, "No runtime implementation is available yet for dpsk adapter '%s'",
				   dpsk_adapter_default_name(conf));
			return -1;
		}

		runtime = talloc_zero(inst->adapter_order, dpsk_adapter_runtime_t);
		*runtime = *tmpl;
		runtime->conf = conf;

		for (insert = i; insert > 0; insert--) {
			if (dpsk_adapter_runtime_cmp(inst->adapter_order[insert - 1], runtime) <= 0) break;
			inst->adapter_order[insert] = inst->adapter_order[insert - 1];
		}
		inst->adapter_order[insert] = runtime;
	}

	return 0;
}

static dpsk_adapter_runtime_t const *dpsk_select_adapter(rlm_dpsk_t const *inst, request_t *request)
{
	size_t i, count;

	if (!inst || !inst->adapter_order) return NULL;

	count = talloc_array_length(inst->adapter_order);
	if (!count) return NULL;

	for (i = 0; i < (count - 1); i++) {
		dpsk_adapter_runtime_t const *adapter = inst->adapter_order[i];

		if (!adapter) continue;
		if (adapter->detect(request, adapter->conf)) return adapter;
	}

	return NULL;
}

static int dpsk_config_validate(module_inst_ctx_t const *mctx, rlm_dpsk_t *inst)
{
	size_t i;
	bool have_default_adapter = false;
	bool have_default_source = false;

	if (inst->sources) {
		size_t source_count = talloc_array_length(inst->sources);

		for (i = 0; i < source_count; i++) {
			dpsk_source_t *source = inst->sources[i];

			if (inst->default_source_name && source->name &&
			    (strcmp(inst->default_source_name, source->name) == 0)) {
				have_default_source = true;
			}
		}
	}

	if (inst->adapters) {
		size_t adapter_count = talloc_array_length(inst->adapters);

		if (!adapter_count) {
			cf_log_err(mctx->mi->conf, "At least one dpsk adapter section must be defined");
			return -1;
		}

		for (i = 0; i < adapter_count; i++) {
			dpsk_adapter_conf_t *adapter = inst->adapters[i];
			char const *adapter_name = dpsk_adapter_default_name(adapter);

			dpsk_adapter_priority_set_default(adapter);
			if (dpsk_request_policy_validate(mctx, adapter) < 0) return -1;
			if (dpsk_reply_policy_validate(mctx, adapter) < 0) return -1;
			if (inst->default_adapter_name && (strcmp(inst->default_adapter_name, adapter_name) == 0)) have_default_adapter = true;

			switch (adapter->type) {
			case DPSK_ADAPTER_TYPE_STANDARD_ATTRS:
				break;

			case DPSK_ADAPTER_TYPE_NAMED_VSA_ATTRS:
				break;

			case DPSK_ADAPTER_TYPE_KEY_VALUE_VSA:
				break;
			}
		}
	} else {
		cf_log_err(mctx->mi->conf, "At least one dpsk adapter section must be defined");
		return -1;
	}

	if (inst->default_source_name && !have_default_source) {
		cf_log_err(mctx->mi->conf, "default_source '%s' was not defined in any source section", inst->default_source_name);
		return -1;
	}

	if (inst->default_adapter_name && !have_default_adapter) {
		cf_log_err(mctx->mi->conf, "default_adapter '%s' was not defined in any adapter section", inst->default_adapter_name);
		return -1;
	}

	return 0;
}

static int8_t cache_entry_cmp(void const *one, void const *two)
{
	rlm_dpsk_cache_t const *a = (rlm_dpsk_cache_t const *) one;
	rlm_dpsk_cache_t const *b = (rlm_dpsk_cache_t const *) two;
	int rcode;

	rcode = memcmp(a->mac, b->mac, sizeof(a->mac));
	if (rcode != 0) return rcode;

	if (a->filename_len < b->filename_len) return -1;
	if (a->filename_len > b->filename_len) return +1;
	if (a->filename_len > 0) {
		rcode = memcmp(a->filename, b->filename, a->filename_len);
		if (rcode != 0) return rcode;
	}

	if (a->ssid_len < b->ssid_len) return -1;
	if (a->ssid_len > b->ssid_len) return +1;

	return CMP(memcmp(a->ssid, b->ssid, a->ssid_len), 0);
}

static void cache_entry_free(void *data)
{
	rlm_dpsk_cache_t *entry = (rlm_dpsk_cache_t *) data;

	pthread_mutex_lock(&entry->inst->mutable->mutex);
	fr_dlist_entry_unlink(&entry->dlist);
	pthread_mutex_unlock(&entry->inst->mutable->mutex);

	talloc_free(entry);
}

static int mod_detach(const module_detach_ctx_t *mctx)
{
	rlm_dpsk_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_dpsk_t);

	if (!inst->mutable) return 0;

	pthread_mutex_destroy(&inst->mutable->mutex);
	talloc_free(inst->mutable);

	return 0;
}
#endif

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
#ifdef WITH_TLS
	rlm_dpsk_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_dpsk_t);
	pthread_mutexattr_t mutex_attr;
	size_t i;

	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, mctx->mi->name, -1);
	if (!inst->auth_type) {
		WARN("Failed to find 'authenticate %s {...}' section.  DPSK will likely not work",
		     mctx->mi->name);
	}

	if (inst->sources) {
		for (i = 0; i < talloc_array_length(inst->sources); i++) {
			if (!inst->sources[i]) break;
		}
	}

	if (dpsk_config_validate(mctx, inst) < 0) return -1;
	if (inst->adapters) {
		size_t adapter_count = talloc_array_length(inst->adapters);

		for (i = 0; i < adapter_count; i++) {
			if (dpsk_compile_adapter_tmpls(mctx, inst->adapters[i]) < 0) return -1;
		}
	}
	if (dpsk_bind_adapter_order(mctx, inst) < 0) return -1;

	/*
	 *	We can still use a cache if we're getting PSKs from a
	 *	database.  The PMK calculation can take time, so
	 *	caching the PMK still saves us time.
	 */
	if (!inst->cache_size) return 0;

	FR_INTEGER_BOUND_CHECK("cache_size", inst->cache_size, <=, ((uint32_t) 1) << 16);

	FR_TIME_DELTA_BOUND_CHECK("cache_lifetime", inst->cache_lifetime, <=, fr_time_delta_from_sec(7 * 86400));
	FR_TIME_DELTA_BOUND_CHECK("cache_lifetime", inst->cache_lifetime, >=, fr_time_delta_from_sec(3600));

	inst->mutable = talloc_zero(NULL, rlm_dpsk_mutable_t);

	fr_rb_inline_init(&inst->mutable->cache, rlm_dpsk_cache_t, node, cache_entry_cmp, cache_entry_free);

	fr_dlist_init(&inst->mutable->head, rlm_dpsk_cache_t, dlist);

	if (pthread_mutexattr_init(&mutex_attr) < 0) {
		cf_log_err(mctx->mi->conf, "Failed creating mutex attributes");
		return -1;
	}
	if (pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE) < 0) {
		pthread_mutexattr_destroy(&mutex_attr);
		cf_log_err(mctx->mi->conf, "Failed configuring recursive mutex");
		return -1;
	}
	if (pthread_mutex_init(&inst->mutable->mutex, &mutex_attr) < 0) {
		pthread_mutexattr_destroy(&mutex_attr);
		cf_log_err(mctx->mi->conf, "Failed creating mutex");
		return -1;
	}
	pthread_mutexattr_destroy(&mutex_attr);

	return 0;
#else
	cf_log_err(mctx->mi->conf, "rlm_dpsk requires OpenSSL");
	return 0;
#endif
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
extern module_rlm_t rlm_dpsk;
module_rlm_t rlm_dpsk = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "dpsk",
		.inst_size	= sizeof(rlm_dpsk_t),
		.instantiate	= mod_instantiate,
		.config		= module_config,
#ifdef WITH_TLS
		.detach		= mod_detach,
		.onload		= mod_load,
		.unload		= mod_unload,
#endif
	},
#ifdef WITH_TLS
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("recv", CF_IDENT_ANY), .method = mod_authorize, .method_env = &dpsk_autz_method_env },
			{ .section = SECTION_NAME("authenticate", CF_IDENT_ANY), .method = mod_authenticate, .method_env = &dpsk_auth_method_env },

			MODULE_BINDING_TERMINATOR
		}
	}
#endif
};
