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
 * @file rlm_dpsk.c
 * @brief Dynamic PSK for WiFi
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/dlist.h>
#include <freeradius-devel/rad_assert.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif

#include <ctype.h>

#define PW_FREERADIUS_8021X_ANONCE		(1)
#define PW_FREERADIUS_8021X_EAPOL_KEY_MSG	(2)

#define VENDORPEC_FREERADIUS_EVS5 ((((uint32_t) 245) << 24) | VENDORPEC_FREERADIUS)

#define VENDORPEC_RUCKUS	(25053)
#define PW_RUCKUS_BSSID		(14)
#define PW_RUCKUS_DPSK_PARAMS	(153)

//#define PW_RUCKUS_DPSK_CIPHER	(PW_RUCKUS_DPSK_PARAMS | (2 << 8))
#define PW_RUCKUS_DPSK_ANONCE	(PW_RUCKUS_DPSK_PARAMS | (3 << 8))
#define PW_RUCKUS_DPSK_EAPOL_KEY_FRAME	(PW_RUCKUS_DPSK_PARAMS | (4 << 8))


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
//	uint8_t		data[];
} CC_HINT(__packed__) eapol_key_frame_t;

typedef struct eapol_attr_t {
	uint8_t		header[4];		// 02030075
	eapol_key_frame_t frame;
} CC_HINT(__packed__) eapol_attr_t;

#ifdef HAVE_PTHREAD_H
#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

typedef struct rlm_dpsk_s rlm_dpsk_t;
typedef struct dpsk_adapter_s dpsk_adapter_t;

typedef enum {
	DPSK_REQUEST_ADAPTER_STANDARD_ATTRS = 0,
	DPSK_REQUEST_ADAPTER_NAMED_VSA_ATTRS,
	DPSK_REQUEST_ADAPTER_KEY_VALUE_VSA
} dpsk_request_adapter_type_t;

typedef enum {
	DPSK_REPLY_MODE_STANDARD = 0,
	DPSK_REPLY_MODE_TUNNEL_PASSWORD,
	DPSK_REPLY_MODE_AVPAIR_HEX_PMK,
	DPSK_REPLY_MODE_MS_MPPE_RECV_KEY
} dpsk_reply_mode_t;

typedef struct {
	uint8_t			mac[6];
	uint8_t			pmk[32];

	uint8_t			*ssid;
	size_t			ssid_len;

	char			*identity;
	size_t			identity_len;

	char			*psk;
	size_t			psk_len;
	bool			has_vlan;
	uint16_t		vlan;
	time_t			expires;

	fr_dlist_t		dlist;
	rlm_dpsk_t		*inst;
} rlm_dpsk_cache_t;

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

struct dpsk_adapter_s {
	char const		*name;
	CONF_SECTION		*cs;
	char const		*request_type_name;
	char const		*request_username_name;
	char const		*request_ssid_name;
	char const		*request_called_station_name;
	char const		*request_anonce_name;
	char const		*request_key_msg_name;
	char const		*request_container_name;
	char const		*request_ssid_key;
	char const		*request_called_station_key;
	char const		*request_anonce_key;
	char const		*request_key_msg_key;
	char const		*request_value_encoding_name;
	dpsk_request_adapter_type_t request_type;
	char const		*reply_mode_name;
	char const		*reply_psk_attr_name;
	char const		*reply_psk_identity_attr_name;
	char const		*reply_avpair_attr_name;
	char const		*reply_pmk_key;
	char const		*reply_extra_pairs;
	dpsk_reply_mode_t	reply_mode;
	DICT_ATTR const		*request_container;
	DICT_ATTR const		*username;
	DICT_ATTR const		*called_station;
	DICT_ATTR const		*ssid;
	DICT_ATTR const		*anonce;
	DICT_ATTR const		*frame;
};

struct rlm_dpsk_s {
	char const		*xlat_name;
	bool			ruckus;
	bool			dynamic;

	rbtree_t		*cache;

	uint32_t		cache_size;
	uint32_t		cache_lifetime;

	char const		*filename;
	char const		*request_type_name;
	char const		*request_username_name;
	char const		*request_ssid_name;
	char const		*request_called_station_name;
	char const		*request_anonce_name;
	char const		*request_key_msg_name;
	char const		*request_container_name;
	char const		*request_ssid_key;
	char const		*request_called_station_key;
	char const		*request_anonce_key;
	char const		*request_key_msg_key;
	char const		*request_value_encoding_name;
	char const		*reply_mode_name;
	char const		*reply_psk_attr_name;
	char const		*reply_psk_identity_attr_name;
	char const		*reply_avpair_attr_name;
	char const		*reply_pmk_key;
	char const		*reply_extra_pairs;
	dpsk_adapter_t		**adapters;
	size_t			num_adapters;
	dpsk_adapter_t		*default_adapter;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		mutex;
#endif
	fr_dlist_t		head;
	CONF_SECTION		*cs;
};

static const CONF_PARSER request_config[] = {
	{ "type", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_type_name), NULL },
	{ "username", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_username_name), NULL },
	{ "ssid", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_ssid_name), NULL },
	{ "called_station", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_called_station_name), NULL },
	{ "anonce", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_anonce_name), NULL },
	{ "key_msg", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_key_msg_name), NULL },
	{ "container_attr", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_container_name), NULL },
	{ "ssid_key", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_ssid_key), NULL },
	{ "called_station_key", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_called_station_key), NULL },
	{ "anonce_key", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_anonce_key), NULL },
	{ "key_msg_key", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_key_msg_key), NULL },
	{ "value_encoding", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, request_value_encoding_name), NULL },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER reply_config[] = {
	{ "mode", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, reply_mode_name), NULL },
	{ "psk_attr", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, reply_psk_attr_name), NULL },
	{ "psk_identity_attr", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, reply_psk_identity_attr_name), NULL },
	{ "avpair_attr", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, reply_avpair_attr_name), NULL },
	{ "pmk_key", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, reply_pmk_key), NULL },
	{ "extra_pairs", FR_CONF_OFFSET(PW_TYPE_STRING, dpsk_adapter_t, reply_extra_pairs), NULL },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER legacy_request_config[] = {
	{ "type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_type_name), NULL },
	{ "username", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_username_name), NULL },
	{ "ssid", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_ssid_name), NULL },
	{ "called_station", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_called_station_name), NULL },
	{ "anonce", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_anonce_name), NULL },
	{ "key_msg", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_key_msg_name), NULL },
	{ "container_attr", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_container_name), NULL },
	{ "ssid_key", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_ssid_key), NULL },
	{ "called_station_key", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_called_station_key), NULL },
	{ "anonce_key", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_anonce_key), NULL },
	{ "key_msg_key", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_key_msg_key), NULL },
	{ "value_encoding", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, request_value_encoding_name), NULL },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER legacy_reply_config[] = {
	{ "mode", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, reply_mode_name), NULL },
	{ "psk_attr", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, reply_psk_attr_name), NULL },
	{ "psk_identity_attr", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, reply_psk_identity_attr_name), NULL },
	{ "avpair_attr", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, reply_avpair_attr_name), NULL },
	{ "pmk_key", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, reply_pmk_key), NULL },
	{ "extra_pairs", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dpsk_t, reply_extra_pairs), NULL },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER adapter_config[] = {
	{ "request", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) request_config },
	{ "reply", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) reply_config },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER module_config[] = {
	{ "ruckus", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_dpsk_t, ruckus), "no" },

	{ "cache_size", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_dpsk_t, cache_size), "0" },
	{ "cache_lifetime", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_dpsk_t, cache_lifetime), "0" },

	{ "filename", FR_CONF_OFFSET(PW_TYPE_STRING,  rlm_dpsk_t, filename), NULL },
	{ "request", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) legacy_request_config },
	{ "reply", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) legacy_reply_config },

	CONF_PARSER_TERMINATOR
};


static inline CC_HINT(nonnull) rlm_dpsk_cache_t *fr_dlist_head(fr_dlist_t const *head)
{
	if (head->prev == head) return NULL;

	return (rlm_dpsk_cache_t *) (((uintptr_t) head->next) - offsetof(rlm_dpsk_cache_t, dlist));
}

static void rdebug_hex(REQUEST *request, char const *prefix, uint8_t const *data, int len)
{
	int i;
	char buffer[2048];	/* large enough for largest len */

	/*
	 *	Leave a trailing space, we don't really care about that.
	 */
	for (i = 0; i < len; i++) {
		snprintf(buffer + i * 2, sizeof(buffer) - i * 2, "%02x", data[i]);
	}

	RDEBUG("%s %s", prefix, buffer);
}
#define RDEBUG_HEX if (rad_debug_lvl >= 3) rdebug_hex

#define REQUEST_DATA_DPSK_ADAPTER 0

static VALUE_PAIR *dpsk_key_value_find(REQUEST *request, DICT_ATTR const *da, char const *key);

static int dpsk_request_config_defaults(rlm_dpsk_t const *inst, dpsk_adapter_t *adapter)
{
	if (!adapter->request_type_name) {
		adapter->request_type_name = inst->ruckus ? "named_vsa_attrs" : "standard_attrs";
	}

	if (!adapter->request_username_name) adapter->request_username_name = "User-Name";
	if (!adapter->request_ssid_name) {
		adapter->request_ssid_name = inst->ruckus ? "Ruckus-SSID" : "Called-Station-SSID";
	}
	if (!adapter->request_called_station_name) {
		adapter->request_called_station_name = inst->ruckus ? "Ruckus-BSSID" : "Called-Station-MAC";
	}
	if (!adapter->request_anonce_name) {
		adapter->request_anonce_name = inst->ruckus ? "Ruckus-DPSK-Anonce" : "FreeRADIUS-802.1X-Anonce";
	}
	if (!adapter->request_key_msg_name) {
		adapter->request_key_msg_name = inst->ruckus ? "Ruckus-DPSK-EAPoL-Key-Frame" : "FreeRADIUS-802.1X-EAPoL-Key-Msg";
	}
	if (!adapter->request_value_encoding_name) adapter->request_value_encoding_name = "radius_escaped";

	if (strcmp(adapter->request_type_name, "standard_attrs") == 0) {
		adapter->request_type = DPSK_REQUEST_ADAPTER_STANDARD_ATTRS;
		return 0;
	}

	if (strcmp(adapter->request_type_name, "named_vsa_attrs") == 0) {
		adapter->request_type = DPSK_REQUEST_ADAPTER_NAMED_VSA_ATTRS;
		return 0;
	}

	if (strcmp(adapter->request_type_name, "key_value_vsa") == 0) {
		if (!adapter->request_container_name) adapter->request_container_name = "Cisco-AVPair";
		if (!adapter->request_ssid_key) adapter->request_ssid_key = "cisco-wlan-ssid";
		if (!adapter->request_called_station_key) adapter->request_called_station_key = "cisco-bssid";
		if (!adapter->request_anonce_key) adapter->request_anonce_key = "cisco-anonce";
		if (!adapter->request_key_msg_key) adapter->request_key_msg_key = "cisco-8021x-data";
		adapter->request_type = DPSK_REQUEST_ADAPTER_KEY_VALUE_VSA;
		return 0;
	}

	return -1;
}

static int dpsk_request_config_resolve(rlm_dpsk_t const *inst, CONF_SECTION *conf, dpsk_adapter_t *adapter)
{
	if (dpsk_request_config_defaults(inst, adapter) < 0) {
		cf_log_err_cs(conf, "Unknown request.type = '%s'", adapter->request_type_name);
		return -1;
	}

	adapter->username = dict_attrbyname(adapter->request_username_name);
	if (!adapter->username) {
		cf_log_err_cs(conf, "Failed to resolve request attributes from configuration");
		return -1;
	}

	if (adapter->request_type == DPSK_REQUEST_ADAPTER_KEY_VALUE_VSA) {
		adapter->request_container = dict_attrbyname(adapter->request_container_name);
		if (!adapter->request_container ||
		    !adapter->request_ssid_key ||
		    !adapter->request_called_station_key ||
		    !adapter->request_anonce_key ||
		    !adapter->request_key_msg_key) {
			cf_log_err_cs(conf, "Failed to resolve key/value request configuration");
			return -1;
		}
		adapter->called_station = NULL;
		adapter->ssid = NULL;
		adapter->anonce = NULL;
		adapter->frame = NULL;
		return 0;
	}

	adapter->called_station = dict_attrbyname(adapter->request_called_station_name);
	adapter->ssid = dict_attrbyname(adapter->request_ssid_name);
	adapter->anonce = dict_attrbyname(adapter->request_anonce_name);
	adapter->frame = dict_attrbyname(adapter->request_key_msg_name);

	if (!adapter->called_station || !adapter->ssid || !adapter->anonce || !adapter->frame) {
		cf_log_err_cs(conf, "Failed to resolve request attributes from configuration");
		return -1;
	}

	return 0;
}

static int dpsk_reply_config_defaults(CONF_SECTION *conf, dpsk_adapter_t *adapter)
{
	if (!adapter->reply_mode_name) adapter->reply_mode_name = "standard";

	if (strcmp(adapter->reply_mode_name, "standard") == 0) {
		adapter->reply_mode = DPSK_REPLY_MODE_STANDARD;
		if (!adapter->reply_psk_attr_name) adapter->reply_psk_attr_name = "Pre-Shared-Key";
		if (!adapter->reply_psk_identity_attr_name) adapter->reply_psk_identity_attr_name = "PSK-Identity";
		return 0;
	}

	if (strcmp(adapter->reply_mode_name, "tunnel_password") == 0) {
		adapter->reply_mode = DPSK_REPLY_MODE_TUNNEL_PASSWORD;
		if (!adapter->reply_psk_attr_name) adapter->reply_psk_attr_name = "Tunnel-Password";
		return 0;
	}

	if (strcmp(adapter->reply_mode_name, "avpair_hex_pmk") == 0) {
		adapter->reply_mode = DPSK_REPLY_MODE_AVPAIR_HEX_PMK;
		if (!adapter->reply_avpair_attr_name) adapter->reply_avpair_attr_name = "Cisco-AVPair";
		if (!adapter->reply_pmk_key) adapter->reply_pmk_key = "psk";
		if (!adapter->reply_extra_pairs) adapter->reply_extra_pairs = "psk-mode=hex";
		return 0;
	}

	if (strcmp(adapter->reply_mode_name, "ms_mppe_recv_key") == 0) {
		adapter->reply_mode = DPSK_REPLY_MODE_MS_MPPE_RECV_KEY;
		if (!adapter->reply_psk_attr_name) adapter->reply_psk_attr_name = "MS-MPPE-Recv-Key";
		return 0;
	}

	cf_log_err_cs(conf, "Unknown reply.mode = '%s'", adapter->reply_mode_name);
	return -1;
}

static int dpsk_configure_adapter(rlm_dpsk_t const *inst, CONF_SECTION *conf, dpsk_adapter_t *adapter)
{
	if (dpsk_request_config_resolve(inst, conf, adapter) < 0) return -1;
	if (dpsk_reply_config_defaults(conf, adapter) < 0) return -1;
	return 0;
}

static void dpsk_copy_legacy_adapter(rlm_dpsk_t const *inst, dpsk_adapter_t *adapter)
{
	adapter->request_type_name = inst->request_type_name;
	adapter->request_username_name = inst->request_username_name;
	adapter->request_ssid_name = inst->request_ssid_name;
	adapter->request_called_station_name = inst->request_called_station_name;
	adapter->request_anonce_name = inst->request_anonce_name;
	adapter->request_key_msg_name = inst->request_key_msg_name;
	adapter->request_container_name = inst->request_container_name;
	adapter->request_ssid_key = inst->request_ssid_key;
	adapter->request_called_station_key = inst->request_called_station_key;
	adapter->request_anonce_key = inst->request_anonce_key;
	adapter->request_key_msg_key = inst->request_key_msg_key;
	adapter->request_value_encoding_name = inst->request_value_encoding_name;
	adapter->reply_mode_name = inst->reply_mode_name;
	adapter->reply_psk_attr_name = inst->reply_psk_attr_name;
	adapter->reply_psk_identity_attr_name = inst->reply_psk_identity_attr_name;
	adapter->reply_avpair_attr_name = inst->reply_avpair_attr_name;
	adapter->reply_pmk_key = inst->reply_pmk_key;
	adapter->reply_extra_pairs = inst->reply_extra_pairs;
}

static int dpsk_register_adapter(rlm_dpsk_t *inst, dpsk_adapter_t *adapter)
{
	dpsk_adapter_t **adapters;

	adapters = talloc_realloc(inst, inst->adapters, dpsk_adapter_t *, inst->num_adapters + 1);
	if (!adapters) return -1;

	inst->adapters = adapters;
	inst->adapters[inst->num_adapters++] = adapter;
	if (!inst->default_adapter) inst->default_adapter = adapter;
	return 0;
}

static bool dpsk_adapter_matches(REQUEST *request, dpsk_adapter_t const *adapter)
{
	VALUE_PAIR *vp;

	if (adapter->request_type == DPSK_REQUEST_ADAPTER_KEY_VALUE_VSA) {
		vp = dpsk_key_value_find(request, adapter->request_container, adapter->request_anonce_key);
		if (!vp) vp = dpsk_key_value_find(request, adapter->request_container, adapter->request_key_msg_key);
		return vp != NULL;
	}

	if (fr_pair_find_by_da(request->packet->vps, adapter->anonce, TAG_ANY)) return true;
	if (fr_pair_find_by_da(request->packet->vps, adapter->frame, TAG_ANY)) return true;
	return false;
}

static dpsk_adapter_t *dpsk_select_adapter(rlm_dpsk_t *inst, REQUEST *request)
{
	size_t i;

	for (i = 0; i < inst->num_adapters; i++) {
		if (dpsk_adapter_matches(request, inst->adapters[i])) return inst->adapters[i];
	}

	return NULL;
}

static int dpsk_decode_escaped(uint8_t *out, size_t outlen, char const *in, size_t inlen)
{
	size_t i, j;

	for (i = 0, j = 0; (i < inlen) && (j < outlen); i++) {
		if (in[i] != '\\') {
			out[j++] = (uint8_t) in[i];
			continue;
		}

		if ((i + 1) >= inlen) return -1;

		if ((in[i + 1] >= '0') && (in[i + 1] <= '7')) {
			unsigned int value = 0;
			int consumed = 0;

			while (((i + 1 + consumed) < inlen) && (consumed < 3) &&
			       (in[i + 1 + consumed] >= '0') && (in[i + 1 + consumed] <= '7')) {
				value = (value * 8) + (unsigned int) (in[i + 1 + consumed] - '0');
				consumed++;
			}
			if (value > UINT8_MAX) return -1;
			out[j++] = (uint8_t) value;
			i += consumed;
			continue;
		}

		out[j++] = (uint8_t) in[i + 1];
		i++;
	}

	return (int) j;
}

static int dpsk_mac_from_string(uint8_t mac[static 6], char const *value, size_t value_len)
{
	char buffer[32];
	size_t i, j;

	for (i = 0, j = 0; (i < value_len) && (j < (sizeof(buffer) - 1)); i++) {
		if (isxdigit((uint8_t) value[i])) buffer[j++] = value[i];
	}
	buffer[j] = '\0';

	if (j != 12) return -1;
	if (fr_hex2bin(mac, 6, buffer, j) != 6) return -1;

	return 0;
}

static VALUE_PAIR *dpsk_key_value_find(REQUEST *request, DICT_ATTR const *da, char const *key)
{
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	size_t key_len = strlen(key);

	for (vp = fr_cursor_init(&cursor, &request->packet->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da != da) continue;
		if (vp->vp_length <= key_len) continue;
		if (memcmp(vp->vp_strvalue, key, key_len) != 0) continue;
		if (vp->vp_strvalue[key_len] != '=') continue;
		return vp;
	}

	return NULL;
}

static int dpsk_add_reply_pair(REQUEST *request, char const *attr, char const *value)
{
	return (fr_pair_make(request->reply, &request->reply->vps, attr, value, T_OP_ADD) != NULL) ? 0 : -1;
}

static int dpsk_parse_vlan(char const *text, uint16_t *out)
{
	char *end = NULL;
	unsigned long vlan;

	if (!text || !*text) return 0;
	if (!isdigit((uint8_t) text[0])) return -1;

	vlan = strtoul(text, &end, 10);
	if (!end || *end) return -1;
	if ((vlan < 1) || (vlan > 4094)) return -1;

	*out = (uint16_t) vlan;
	return 1;
}

static rlm_rcode_t dpsk_add_vlan_reply(REQUEST *request, bool has_vlan, uint16_t vlan)
{
	char vlan_buffer[8];

	if (!has_vlan) return RLM_MODULE_OK;

	snprintf(vlan_buffer, sizeof(vlan_buffer), "%u", vlan);
	if (dpsk_add_reply_pair(request, "Tunnel-Type", "VLAN") < 0) return RLM_MODULE_FAIL;
	if (dpsk_add_reply_pair(request, "Tunnel-Medium-Type", "IEEE-802") < 0) return RLM_MODULE_FAIL;
	if (dpsk_add_reply_pair(request, "Tunnel-Private-Group-Id", vlan_buffer) < 0) return RLM_MODULE_FAIL;

	return RLM_MODULE_OK;
}

static rlm_rcode_t dpsk_emit_reply(REQUEST *request, dpsk_adapter_t const *adapter,
				   uint8_t const pmk[static 32], char const *psk,
				   size_t psk_len, char const *psk_identity,
				   bool has_vlan, uint16_t vlan)
{
	char buffer[2 + (32 * 2) + 1];
	char pair[256];
	char *extra, *token, *saveptr = NULL;
	rlm_rcode_t rcode = RLM_MODULE_FAIL;

	switch (adapter->reply_mode) {
	case DPSK_REPLY_MODE_STANDARD:
		if (dpsk_add_reply_pair(request, adapter->reply_psk_attr_name, psk) < 0) return RLM_MODULE_FAIL;
		if (dpsk_add_reply_pair(request, adapter->reply_psk_identity_attr_name, psk_identity) < 0) return RLM_MODULE_FAIL;
		rcode = RLM_MODULE_OK;
		break;

	case DPSK_REPLY_MODE_TUNNEL_PASSWORD:
		if (dpsk_add_reply_pair(request, adapter->reply_psk_attr_name, psk) < 0) return RLM_MODULE_FAIL;
		rcode = RLM_MODULE_OK;
		break;

	case DPSK_REPLY_MODE_AVPAIR_HEX_PMK:
		strcpy(buffer, "0x");
		fr_bin2hex(buffer + 2, pmk, 32);
		snprintf(pair, sizeof(pair), "%s=%s", adapter->reply_pmk_key, buffer + 2);
		if (dpsk_add_reply_pair(request, adapter->reply_avpair_attr_name, pair) < 0) return RLM_MODULE_FAIL;
		if (!adapter->reply_extra_pairs || !*adapter->reply_extra_pairs) {
			rcode = RLM_MODULE_OK;
			break;
		}

		extra = talloc_typed_strdup(request, adapter->reply_extra_pairs);
		if (!extra) return RLM_MODULE_FAIL;
		for (token = strtok_r(extra, ",", &saveptr);
		     token;
		     token = strtok_r(NULL, ",", &saveptr)) {
			while (isspace((uint8_t) *token)) token++;
			if (!*token) continue;
			if (dpsk_add_reply_pair(request, adapter->reply_avpair_attr_name, token) < 0) {
				talloc_free(extra);
				return RLM_MODULE_FAIL;
			}
		}
		talloc_free(extra);
		rcode = RLM_MODULE_OK;
		break;

	case DPSK_REPLY_MODE_MS_MPPE_RECV_KEY:
		strcpy(buffer, "0x");
		fr_bin2hex(buffer + 2, pmk, 32);
		if (dpsk_add_reply_pair(request, adapter->reply_psk_attr_name, buffer) < 0) return RLM_MODULE_FAIL;
		rcode = RLM_MODULE_OK;
		break;
	}

	(void) psk_len;
	if (rcode != RLM_MODULE_OK) return rcode;
	return dpsk_add_vlan_reply(request, has_vlan, vlan);
}

#if 0
/*
 *	Find the Ruckus attributes, and convert to FreeRADIUS ones.
 *
 *	Also check the WPA2 cipher.  We need AES + HMAC-SHA1.
 */
static bool normalize(rlm_dpsk_t *inst, REQUEST *request)
{
	VALUE_PAIR *bssid, *cipher, *anonce, *key_msg, *vp;

	if (!inst->ruckus) return false;

	bssid = fr_pair_find_by_num(request->packet->vps, PW_RUCKUS_BSSID, VENDORPEC_RUCKUS, TAG_ANY);
	if (!bssid) return false;

	cipher = fr_pair_find_by_num(request->packet->vps, PW_RUCKUS_DPSK_CIPHER, VENDORPEC_RUCKUS, TAG_ANY);
	if (!cipher) return false;

	if (cipher->vp_byte != 4) {
		RDEBUG("Found Ruckus-DPSK-Cipher != 4, which means that we cannot do DPSK");
		return false;
	}

	anonce = fr_pair_find_by_num(request->packet->vps, PW_RUCKUS_DPSK_ANONCE, VENDORPEC_RUCKUS, TAG_ANY);
	if (!anonce) return false;

	key_msg = fr_pair_find_by_num(request->packet->vps, PW_RUCKUS_DPSK_EAPOL_KEY_FRAME, VENDORPEC_RUCKUS, TAG_ANY);
	if (!key_msg) return false;

	MEM(vp = fr_pair_afrom_da(request->packet, anonce->da));
	fr_pair_value_memcpy(vp, anonce->vp_octets, anonce->vp_length);
	fr_pair_add(&request->packet->vps, vp);

	MEM(vp = fr_pair_afrom_da(request->packet, key_msg->da));
	fr_pair_value_memcpy(vp, key_msg->vp_octets, key_msg->vp_length);
	fr_pair_add(&request->packet->vps, vp);

	return false;
}
#endif

/*
 *	mod_authorize() - authorize user if we can authenticate
 *	it later. Add Auth-Type attribute if present in module
 *	configuration (usually Auth-Type must be "DPSK")
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void * instance, REQUEST *request)
{
	rlm_dpsk_t *inst = instance;
	dpsk_adapter_t *adapter;

	adapter = dpsk_select_adapter(inst, request);
	if (!adapter) return RLM_MODULE_NOOP;

	if (request_data_add(request, inst, REQUEST_DATA_DPSK_ADAPTER, adapter, false) < 0) {
		return RLM_MODULE_FAIL;
	}

	if (fr_pair_find_by_num(request->config, PW_AUTH_TYPE, 0, TAG_ANY)) {
		RWDEBUG2("Auth-Type already set.  Not setting to %s", inst->xlat_name);
		return RLM_MODULE_NOOP;
	}

	RDEBUG2("Found DPSK request via adapter '%s'.  Setting 'Auth-Type  = %s'",
		adapter->name, inst->xlat_name);

	/*
	 *	Set Auth-Type to DPSK.  The authentication code
	 *	will verify the request against the selected adapter.
	 */
	if (!pair_make_config("Auth-Type", inst->xlat_name, T_OP_EQ)) {
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

static rlm_dpsk_cache_t *dpsk_cache_find(REQUEST *request, rlm_dpsk_t const *inst, uint8_t *buffer, size_t buflen,
					 uint8_t const *ssid, size_t ssid_len, uint8_t const *mac)
{
	rlm_dpsk_cache_t *entry, my_entry;

	memcpy(my_entry.mac, mac, sizeof(my_entry.mac));
	memcpy(&my_entry.ssid, &ssid, sizeof(my_entry.ssid)); /* const issues */
	my_entry.ssid_len = ssid_len;

	entry = rbtree_finddata(inst->cache, &my_entry);
	if (entry) {
		if (entry->expires > request->timestamp) {
			RDEBUG3("Cache entry found");
			memcpy(buffer, entry->pmk, buflen);
			return entry;
		}

		RDEBUG3("Cache entry has expired");
		rbtree_deletebydata(inst->cache, entry);
	}

	return NULL;
}


static int generate_pmk(REQUEST *request, uint8_t *buffer, size_t buflen, uint8_t const *ssid, size_t ssid_len,
			char const *psk, size_t psk_len)
{
	fr_assert(buflen == 32);

	if (PKCS5_PBKDF2_HMAC_SHA1((const char *) psk, psk_len, (const unsigned char *) ssid, ssid_len, 4096, buflen, buffer) == 0) {
		RDEBUG("Failed calling OpenSSL to calculate the PMK");
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
		{
			unsigned int md_len = 0;
			uint8_t md[EVP_MAX_MD_SIZE];

			if (!HMAC(EVP_sha1(), kck, 16, frame, frame_len, md, &md_len)) return -1;
			if (md_len < sizeof(out[0]) * 16) return -1;
			memcpy(out, md, 16);
		}
		return 0;

	case 3:
		if (use_hostap_pmf && (kck_len != 16)) return -1;
		if (dpsk_aes_128_cmac(kck, frame, frame_len, out) < 0) return -1;
		return 0;

	default:
		return 1;
	}
}

static int dpsk_prepare_verify_ctx(REQUEST *request, dpsk_verify_ctx_t *ctx,
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
		RDEBUG2("DPSK AKM suite=%02x-%02x-%02x-%02x", akm[0], akm[1], akm[2], akm[3]);
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

	(void) request;
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
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_dpsk_t *inst = instance;
	dpsk_adapter_t *adapter;
	VALUE_PAIR *anonce, *key_msg, *vp, *vp_psk = NULL, *vp_id = NULL, *vp_ssid = NULL;
	rlm_dpsk_cache_t *entry = NULL;
	int lineno = 0;
	int stage = 0;
	int verify_rc;
	rlm_rcode_t rcode = RLM_MODULE_OK;
	size_t len, psk_len = 0;
	FILE *fp = NULL;
	char const *filename = inst->filename;
	char const *psk_identity = NULL, *psk = NULL;
	uint8_t const *ap_anonce, *ap_mac;
	uint8_t pmk[32];
	uint8_t s_mac[6], calc_mic[16];
	uint8_t anonce_buffer[32], key_msg_buffer[256], called_station_buffer[6];
	char ssid_buffer[256];
	uint8_t const *ssid_data = NULL;
	size_t ssid_len = 0, key_msg_len = 0;
	char token_identity[256];
	char token_psk[256];
	char const *vp_value;
	size_t vp_value_len;
	char filename_buffer[1024];
	bool has_vlan = false;
	uint16_t vlan = 0;
	dpsk_verify_ctx_t verify;

	adapter = request_data_reference(request, inst, REQUEST_DATA_DPSK_ADAPTER);
	if (!adapter) adapter = dpsk_select_adapter(inst, request);
	if (!adapter) return RLM_MODULE_NOOP;

	/*
	 *	Search for the information in a bunch of attributes.
	 */
	if (adapter->request_type == DPSK_REQUEST_ADAPTER_KEY_VALUE_VSA) {
		vp = dpsk_key_value_find(request, adapter->request_container, adapter->request_anonce_key);
		if (!vp) {
			RDEBUG("No %s in the request", adapter->request_anonce_key);
			return RLM_MODULE_NOOP;
		}
		vp_value = vp->vp_strvalue + strlen(adapter->request_anonce_key) + 1;
		vp_value_len = vp->vp_length - strlen(adapter->request_anonce_key) - 1;
		if (dpsk_decode_escaped(anonce_buffer, sizeof(anonce_buffer), vp_value, vp_value_len) != 32) {
			RDEBUG("%s has incorrect decoded length", adapter->request_anonce_key);
			return RLM_MODULE_NOOP;
		}

		vp = dpsk_key_value_find(request, adapter->request_container, adapter->request_key_msg_key);
		if (!vp) {
			RDEBUG("No %s in the request", adapter->request_key_msg_key);
			return RLM_MODULE_NOOP;
		}
		vp_value = vp->vp_strvalue + strlen(adapter->request_key_msg_key) + 1;
		vp_value_len = vp->vp_length - strlen(adapter->request_key_msg_key) - 1;
		key_msg_len = dpsk_decode_escaped(key_msg_buffer, sizeof(key_msg_buffer), vp_value, vp_value_len);
		if ((int) key_msg_len < 0) {
			RDEBUG("%s failed decoding", adapter->request_key_msg_key);
			return RLM_MODULE_NOOP;
		}
		if (key_msg_len < sizeof(eapol_attr_t)) {
			RDEBUG("%s has incorrect length (%zu < %zu)", adapter->request_key_msg_key, key_msg_len, sizeof(eapol_attr_t));
			return RLM_MODULE_NOOP;
		}

		vp = dpsk_key_value_find(request, adapter->request_container, adapter->request_ssid_key);
		if (!vp) {
			RDEBUG("No %s in the request", adapter->request_ssid_key);
			return RLM_MODULE_NOOP;
		}
		vp_value = vp->vp_strvalue + strlen(adapter->request_ssid_key) + 1;
		vp_value_len = vp->vp_length - strlen(adapter->request_ssid_key) - 1;
		if (vp_value_len >= sizeof(ssid_buffer)) {
			RDEBUG("%s is too long", adapter->request_ssid_key);
			return RLM_MODULE_NOOP;
		}
		memcpy(ssid_buffer, vp_value, vp_value_len);
		ssid_buffer[vp_value_len] = '\0';
		ssid_data = (uint8_t const *) ssid_buffer;
		ssid_len = vp_value_len;

		anonce = NULL;
		key_msg = NULL;
		vp_ssid = NULL;
	} else {
		anonce = fr_pair_find_by_da(request->packet->vps, adapter->anonce, TAG_ANY);
		if (!anonce) {
			RDEBUG("No %s in the request", adapter->anonce->name);
			return RLM_MODULE_NOOP;
		}

		if (anonce->vp_length != 32) {
			RDEBUG("%s has incorrect length (%zu, not 32)", adapter->anonce->name, anonce->vp_length);
			return RLM_MODULE_NOOP;
		}

		key_msg = fr_pair_find_by_da(request->packet->vps, adapter->frame, TAG_ANY);
		if (!key_msg) {
			RDEBUG("No %s in the request", adapter->frame->name);
			return RLM_MODULE_NOOP;
		}

		if (key_msg->vp_length < sizeof(eapol_attr_t)) {
			RDEBUG("%s has incorrect length (%zu < %zu)", adapter->frame->name, key_msg->vp_length, sizeof(eapol_attr_t));
			return RLM_MODULE_NOOP;
		}

		if (key_msg->vp_length > sizeof(key_msg_buffer)) {
			RDEBUG("%s has incorrect length (%zu > %zu)", adapter->frame->name, key_msg->vp_length, sizeof(key_msg_buffer));
			return RLM_MODULE_NOOP;
		}

		vp_ssid = fr_pair_find_by_da(request->packet->vps, adapter->ssid, TAG_ANY);
		if (!vp_ssid) {
			RDEBUG("No %s in the request", adapter->ssid->name);
			return RLM_MODULE_NOOP;
		}

		ssid_data = vp_ssid->vp_octets;
		ssid_len = vp_ssid->vp_length;
		key_msg_len = key_msg->vp_length;
	}

	/*
	 *	At this point, the request has the relevant DPSK
	 *	attributes.  The module now should return FAIL for
	 *	missing / invalid attributes, or REJECT for
	 *	authentication failure.
	 */
	vp = fr_pair_find_by_da(request->packet->vps, adapter->username, TAG_ANY);
	if (!vp) {
		RDEBUG("Missing &%s", adapter->username->name);
		return RLM_MODULE_FAIL;
	}

	len = fr_hex2bin(s_mac, sizeof(s_mac), vp->vp_strvalue, vp->vp_length);
	if (len != 6) {
		RDEBUG("&User-Name is not a recognizable hex MAC address");
		return RLM_MODULE_FAIL;
	}

	if (adapter->request_type == DPSK_REQUEST_ADAPTER_KEY_VALUE_VSA) {
		vp = dpsk_key_value_find(request, adapter->request_container, adapter->request_called_station_key);
		if (!vp) {
			RDEBUG("Missing %s", adapter->request_called_station_key);
			return RLM_MODULE_FAIL;
		}
		vp_value = vp->vp_strvalue + strlen(adapter->request_called_station_key) + 1;
		vp_value_len = vp->vp_length - strlen(adapter->request_called_station_key) - 1;
		if (dpsk_mac_from_string(called_station_buffer, vp_value, vp_value_len) < 0) {
			RDEBUG("%s is not a recognizable MAC address", adapter->request_called_station_key);
			return RLM_MODULE_FAIL;
		}
		ap_mac = called_station_buffer;
	} else {
		vp = fr_pair_find_by_da(request->packet->vps, adapter->called_station, TAG_ANY);
		if (!vp) {
			RDEBUG("Missing &%s", adapter->called_station->name);
			return RLM_MODULE_FAIL;
		}

		if (vp->length != 6) {
			RDEBUG("&%s is not a recognizable MAC address", adapter->called_station->name);
			return RLM_MODULE_FAIL;
		}

		ap_mac = vp->vp_octets;
	}

	ap_anonce = (adapter->request_type == DPSK_REQUEST_ADAPTER_KEY_VALUE_VSA) ? anonce_buffer : anonce->vp_octets;
	if (dpsk_prepare_verify_ctx(request, &verify,
				    (adapter->request_type == DPSK_REQUEST_ADAPTER_KEY_VALUE_VSA) ? key_msg_buffer : key_msg->vp_octets,
				    key_msg_len) < 0) {
		RDEBUG("Failed preparing DPSK verifier state");
		return RLM_MODULE_FAIL;
	}

	if (inst->cache) {
		entry = dpsk_cache_find(request, inst, pmk, sizeof(pmk), ssid_data, ssid_len, s_mac);
		if (entry) {
			psk_identity = entry->identity;
			psk = entry->psk;
			psk_len = entry->psk_len;
			has_vlan = entry->has_vlan;
			vlan = entry->vlan;
			goto make_digest;
		}
	}

stage1:
	stage = 1;

	vp = fr_pair_find_by_num(request->config, PW_PAIRWISE_MASTER_KEY, 0, TAG_ANY);
	if (vp && (vp->vp_length != sizeof(pmk))) {
		RDEBUG("&control:Pairwise-Master-Key has incorrect length (%zu != %zu) - ignoring it", vp->vp_length, sizeof(pmk));
		vp = NULL;
	}

	if (vp) {
		RDEBUG("Using &control:Pairwise-Master-Key");
		memcpy(pmk, vp->vp_octets, sizeof(pmk));
		goto make_digest;
	}

	vp_psk = fr_pair_find_by_num(request->config, PW_PRE_SHARED_KEY, 0, TAG_ANY);
	if (vp_psk) {
		RDEBUG("Trying &control:Pre-Shared-Key");
		if (generate_pmk(request, pmk, sizeof(pmk), ssid_data, ssid_len, vp_psk->vp_strvalue, vp_psk->vp_length) < 0) {
			fr_assert(!fp);
			return RLM_MODULE_FAIL;
		}

		vp_id = fr_pair_find_by_num(request->config, PW_PSK_IDENTITY, 0, TAG_ANY);
		if (vp_id) {
			psk_identity = vp_id->vp_strvalue;
		} else {
			vp = fr_pair_find_by_da(request->packet->vps, adapter->username, TAG_ANY);
			if (!vp) return RLM_MODULE_REJECT;
			psk_identity = vp->vp_strvalue;
		}

		psk = vp_psk->vp_strvalue;
		psk_len = vp_psk->vp_length;
		goto make_digest;
	}

stage2:
	stage = 2;

	if (!inst->filename) {
		RDEBUG("No &control:Pre-Shared-Key was found, and no 'filename' was configured");
		return RLM_MODULE_FAIL;
	}

	if (inst->filename) {
		FR_TOKEN token;
		char const *q;
		char token_mac[256];
		char token_vlan[256];
		char buffer[1024];

		if (inst->dynamic) {
			if (radius_xlat(filename_buffer, sizeof(filename_buffer),
					request, inst->filename, NULL, NULL) < 0) {
				return RLM_MODULE_FAIL;
			}

			filename = filename_buffer;

			if (!cf_file_check(inst->cs, filename, true)) {
				RDEBUG("Cannot open %s", filename);
				return RLM_MODULE_FAIL;
			}

		} else {
			fr_assert(filename == inst->filename);
		}

		RDEBUG3("Looking for PSK in file %s", filename);

		fp = fopen(filename, "r");
		if (!fp) {
			REDEBUG("Failed opening %s - %s", filename, fr_syserror(errno));
			return RLM_MODULE_FAIL;
		}

stage2a:
		q = fgets(buffer, sizeof(buffer), fp);
		lineno++;
		if (!q) {
			RDEBUG("Failed to find matching PSK or MAC in %s", filename);
		fail_file:
			fclose(fp);
			return RLM_MODULE_FAIL;
		}

		token = getstring(&q, token_identity, sizeof(token_identity), true);
		if (token == T_INVALID) {
			RDEBUG("%s[%d] Failed parsing identity", filename, lineno);
			goto fail_file;
		}

		if (*q != ',') {
			RDEBUG("%s[%d] Failed to find ',' after identity", filename, lineno);
			goto fail_file;
		}
		q++;

		token = getstring(&q, token_psk, sizeof(token_psk), true);
		if (token == T_INVALID) {
			RDEBUG("%s[%d] Failed parsing PSK", filename, lineno);
			goto fail_file;
		}

		token_mac[0] = '\0';
		token_vlan[0] = '\0';
		has_vlan = false;
		vlan = 0;
		if (*q == ',') {
			q++;

			token = getstring(&q, token_mac, sizeof(token_mac), true);
			if (token == T_INVALID) {
				RDEBUG("%s[%d] Failed parsing MAC", filename, lineno);
				goto fail_file;
			}

			if (*q == ',') {
				int parsed_vlan;

				q++;
				token = getstring(&q, token_vlan, sizeof(token_vlan), true);
				if (token == T_INVALID) {
					RDEBUG("%s[%d] Failed parsing VLAN", filename, lineno);
					goto fail_file;
				}

				parsed_vlan = dpsk_parse_vlan(token_vlan, &vlan);
				if (parsed_vlan < 0) {
					RDEBUG("%s[%d] Failed parsing VLAN", filename, lineno);
					goto fail_file;
				}
				has_vlan = (parsed_vlan > 0);
			}

			if (token_mac[0]) {
				if ((strlen(token_mac) != 12) ||
				    (fr_hex2bin((uint8_t *) token_mac, 6, token_mac, 12) != 6)) {
					RDEBUG("%s[%d] Failed parsing MAC", filename, lineno);
					goto fail_file;
				}

				if (memcmp(s_mac, token_mac, 6) != 0) {
					goto stage2a;
				}

				RDEBUG3("Found matching MAC");
				stage = 3;
			}
		}

		psk = token_psk;
		psk_len = strlen(token_psk);
		psk_identity = token_identity;

		RDEBUG3("%s[%d] Trying PSK %s", filename, lineno, token_psk);
		if (generate_pmk(request, pmk, sizeof(pmk), ssid_data, ssid_len, psk, psk_len) < 0) {
			goto fail_file;
		}
	}

make_digest:
	verify_rc = dpsk_verify_candidate(&verify, ap_anonce, s_mac, ap_mac, pmk, calc_mic);
	if (verify_rc < 0) {
		RDEBUG("Failed calculating DPSK MIC");
		return RLM_MODULE_FAIL;
	}

	if (verify_rc > 0) {
		RDEBUG3("Stage %d", stage);
		RDEBUG_HEX(request, "calculated mic:", calc_mic, sizeof(calc_mic));
		RDEBUG_HEX(request, "packet mic    :", verify.packet_mic, sizeof(verify.packet_mic));

		psk_identity = NULL;
		psk = NULL;
		psk_len = 0;
		has_vlan = false;
		vlan = 0;

		if (stage == 0) {
			fr_assert(entry != NULL);
			rbtree_deletebydata(inst->cache, entry);
			entry = NULL;
			goto stage1;
		}

		if (stage == 1) {
			if (vp_psk) RDEBUG("&control:Pre-Shared-Key did not match");

			if (inst->filename) {
				RDEBUG("Checking file %s for PSK and MAC", inst->filename);
				goto stage2;
			}

			RDEBUG("No 'filename' was configured.");
			return RLM_MODULE_REJECT;
		}

		fr_assert(fp);
		if (stage == 2) goto stage2a;

		fclose(fp);
		fr_assert(stage == 3);
		RDEBUG("Found matching MAC in %s, but the PSK does not match", inst->filename);
		return RLM_MODULE_FAIL;
	}

	if (fp) {
		fr_assert(psk == token_psk);
		fr_assert(psk_identity == token_identity);
		fclose(fp);
	}

	if (inst->cache && psk && psk_identity) {
		rlm_dpsk_cache_t my_entry;

		if (entry) goto update_entry;

		memcpy(my_entry.mac, s_mac, sizeof(my_entry.mac));
		memcpy(&my_entry.ssid, &ssid_data, sizeof(my_entry.ssid));
		my_entry.ssid_len = ssid_len;

		entry = rbtree_finddata(inst->cache, &my_entry);
		if (!entry) {
			if (rbtree_num_elements(inst->cache) > inst->cache_size) {
				PTHREAD_MUTEX_LOCK(&inst->mutex);
				entry = fr_dlist_head(&inst->head);
				PTHREAD_MUTEX_UNLOCK(&inst->mutex);
				rbtree_deletebydata(inst->cache, entry);
			}

			MEM(entry = talloc_zero(inst->cache, rlm_dpsk_cache_t));

			memcpy(entry->mac, s_mac, sizeof(entry->mac));
			memcpy(entry->pmk, pmk, sizeof(entry->pmk));

			fr_dlist_entry_init(&entry->dlist);
			entry->inst = inst;

			MEM(entry->ssid = talloc_memdup(entry, ssid_data, ssid_len));
			entry->ssid_len = ssid_len;

			MEM(entry->psk = talloc_memdup(entry, psk, psk_len + 1));
			entry->psk_len = psk_len;

			entry->identity_len = strlen(psk_identity);
			MEM(entry->identity = talloc_memdup(entry, psk_identity, entry->identity_len + 1));
			entry->has_vlan = has_vlan;
			entry->vlan = vlan;

			if (!rbtree_insert(inst->cache, entry)) {
				TALLOC_FREE(entry);
				goto update_attributes;
			}
			RDEBUG3("Cache entry saved");
		}

	update_entry:
		PTHREAD_MUTEX_LOCK(&inst->mutex);
		entry->expires = request->timestamp + inst->cache_lifetime;
		fr_dlist_entry_unlink(&entry->dlist);
		fr_dlist_insert_tail(&inst->head, &entry->dlist);
		PTHREAD_MUTEX_UNLOCK(&inst->mutex);
	}

update_attributes:
	fr_assert(psk != NULL);
	fr_assert(psk_identity != NULL);

	if (dpsk_emit_reply(request, adapter, pmk, psk, psk_len, psk_identity, has_vlan, vlan) != RLM_MODULE_OK) {
		return RLM_MODULE_FAIL;
	}

	return rcode;
}

/*
 *	Generate the PMK from SSID and Pre-Shared-Key
 */
static ssize_t dpsk_xlat(void *instance, REQUEST *request,
			 char const *fmt, char *out, size_t outlen)
{
	rlm_dpsk_t *inst = instance;
	dpsk_adapter_t *adapter = inst->default_adapter;
	char const *p, *ssid, *psk;
	size_t ssid_len, psk_len;
	uint8_t buffer[32];
	char ssid_buffer[256];
	VALUE_PAIR *vp;

	if (!adapter) return 0;

	p = fmt;
	while (isspace((uint8_t) *p)) p++;

	if (!*p) {
		VALUE_PAIR *vp_ssid = NULL, *vp_psk;

		if (adapter->request_type == DPSK_REQUEST_ADAPTER_KEY_VALUE_VSA) {
			vp = dpsk_key_value_find(request, adapter->request_container, adapter->request_ssid_key);
			if (!vp) {
				RDEBUG("No %s in the request", adapter->request_ssid_key);
				return 0;
			}
			ssid = vp->vp_strvalue + strlen(adapter->request_ssid_key) + 1;
			ssid_len = vp->vp_length - strlen(adapter->request_ssid_key) - 1;
			if (ssid_len >= sizeof(ssid_buffer)) return 0;
			memcpy(ssid_buffer, ssid, ssid_len);
			ssid_buffer[ssid_len] = '\0';
			ssid = ssid_buffer;
		} else {
			vp_ssid = fr_pair_find_by_da(request->packet->vps, adapter->ssid, TAG_ANY);
			if (!vp_ssid) {
				RDEBUG("No %s in the request", adapter->ssid->name);
				return 0;
			}
			ssid = vp_ssid->vp_strvalue;
			ssid_len = vp_ssid->vp_length;
		}

		vp_psk = fr_pair_find_by_num(request->config, PW_PRE_SHARED_KEY, 0, TAG_ANY);
		if (!vp_psk) {
			RDEBUG("No &config:Pre-Shared-Key");
			return 0;
		}

		psk = vp_psk->vp_strvalue;
		psk_len = vp_psk->vp_length;
		goto get_pmk;
	}

	ssid = p;
	while (*p && !isspace((uint8_t) *p)) p++;
	ssid_len = p - ssid;
	if (!*p) {
		REDEBUG("Found SSID, but no PSK");
		return 0;
	}

	while (isspace((uint8_t) *p)) p++;
	psk = p;
	while (*p && !isspace((uint8_t) *p)) p++;
	psk_len = p - psk;

get_pmk:
	if (PKCS5_PBKDF2_HMAC_SHA1(psk, psk_len, (const unsigned char *) ssid, ssid_len, 4096, sizeof(buffer), buffer) == 0) {
		RDEBUG("Failed calling OpenSSL to calculate the PMK");
		return 0;
	}

	if (outlen < sizeof(buffer) * 2 + 1) {
		REDEBUG("Output buffer is too small for PMK");
		return 0;
	}

	return fr_bin2hex(out, buffer, 32);
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	char const *name;
	CONF_SECTION *adapter_cs;
	rlm_dpsk_t *inst = instance;

	name = cf_section_name2(conf);
	if (!name) name = cf_section_name1(conf);
	inst->xlat_name = name;
	xlat_register(inst->xlat_name, dpsk_xlat, NULL, inst);

	inst->dynamic = inst->filename && (strchr(inst->filename, '%') != NULL);
	inst->cs = conf;

	for (adapter_cs = cf_subsection_find_next(conf, NULL, "adapter");
	     adapter_cs != NULL;
	     adapter_cs = cf_subsection_find_next(conf, adapter_cs, "adapter")) {
		dpsk_adapter_t *adapter;

		if (!cf_section_name2(adapter_cs)) {
			cf_log_err_cs(adapter_cs, "Adapter sections must be named");
			return -1;
		}

		adapter = talloc_zero(inst, dpsk_adapter_t);
		if (!adapter) return -1;
		adapter->name = cf_section_name2(adapter_cs);
		adapter->cs = adapter_cs;

		if (cf_section_parse(adapter_cs, adapter, adapter_config) < 0) {
			return -1;
		}
		if (dpsk_configure_adapter(inst, adapter_cs, adapter) < 0) {
			return -1;
		}
		if (dpsk_register_adapter(inst, adapter) < 0) {
			cf_log_err_cs(adapter_cs, "Failed to register adapter '%s'", adapter->name);
			return -1;
		}
	}

	if (!inst->num_adapters) {
		dpsk_adapter_t *adapter;

		adapter = talloc_zero(inst, dpsk_adapter_t);
		if (!adapter) return -1;
		adapter->name = "default";
		adapter->cs = conf;
		dpsk_copy_legacy_adapter(inst, adapter);
		if (dpsk_configure_adapter(inst, conf, adapter) < 0) {
			cf_log_err_cs(conf, "Failed to resolve legacy request/reply configuration");
			return -1;
		}
		if (dpsk_register_adapter(inst, adapter) < 0) {
			cf_log_err_cs(conf, "Failed to register default adapter");
			return -1;
		}
	}

	if (inst->filename && !inst->dynamic && !cf_file_check(conf, inst->filename, true)) {
		return -1;
	}

	return 0;
}

static int cmp_cache_entry(void const *one, void const *two)
{
	rlm_dpsk_cache_t const *a = (rlm_dpsk_cache_t const *) one;
	rlm_dpsk_cache_t const *b = (rlm_dpsk_cache_t const *) two;
	int rcode;

	rcode = memcmp(a->mac, b->mac, sizeof(a->mac));
	if (rcode != 0) return rcode;

	if (a->ssid_len < b->ssid_len) return -1;
	if (a->ssid_len > b->ssid_len) return +1;

	return memcmp(a->ssid, b->ssid, a->ssid_len);
}

static void free_cache_entry(void *data)
{
	rlm_dpsk_cache_t *entry = (rlm_dpsk_cache_t *) data;

	PTHREAD_MUTEX_LOCK(&entry->inst->mutex);
	fr_dlist_entry_unlink(&entry->dlist);
	PTHREAD_MUTEX_UNLOCK(&entry->inst->mutex);

	talloc_free(entry);
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_dpsk_t *inst = instance;

	/*
	 *	We can still use a cache if we're getting PSKs from a
	 *	database.  The PMK calculation can take time, so
	 *	caching the PMK still saves us time.
	 */
	if (!inst->cache_size) return 0;

	FR_INTEGER_BOUND_CHECK("cache_size", inst->cache_size, <=, ((uint32_t) 1) << 16);

	FR_INTEGER_BOUND_CHECK("cache_lifetime", inst->cache_lifetime, <=, (7 * 86400));
	FR_INTEGER_BOUND_CHECK("cache_lifetime", inst->cache_lifetime, >=, 3600);

	inst->cache = rbtree_create(inst, cmp_cache_entry, free_cache_entry, RBTREE_FLAG_LOCK);
	if (!inst->cache) {
		cf_log_err_cs(conf, "Failed creating internal cache");
		return -1;
	}

	fr_dlist_entry_init(&inst->head);
#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&inst->mutex, NULL) < 0) {
		cf_log_err_cs(conf, "Failed creating mutex");
		return -1;
	}
#endif

	return 0;
}

static int mod_detach(void *instance)
{
	rlm_dpsk_t *inst = instance;

	if (!inst->cache_size) return 0;

	rbtree_free(inst->cache);

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&inst->mutex);
#endif

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
extern module_t rlm_dpsk;
module_t rlm_dpsk = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dpsk",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_dpsk_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_AUTHENTICATE]	= mod_authenticate,
	},
};
