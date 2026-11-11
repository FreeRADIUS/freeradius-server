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
 * @file rlm_preprocess.c
 * @brief Fixes up requests, and processes huntgroups/hints files.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>

#include	<ctype.h>

typedef struct rlm_preprocess_t {
	char const	*huntgroup_file;
	char const	*hints_file;
	PAIR_LIST	*huntgroups;
	PAIR_LIST	*hints;
	bool		with_ascend_hack;
	uint32_t	ascend_channels_per_line;
	bool		with_ntdomain_hack;
	bool		with_specialix_jetstream_hack;
	bool		with_cisco_vsa_hack;
	bool		with_cisco_easy_psk_hack;
	bool		with_alvarion_vsa_hack;
	bool		with_cablelabs_vsa_hack;
	DICT_ATTR const	*cisco_avpair_da;
	DICT_ATTR const	*tmp_string_0_da;
	DICT_ATTR const	*tmp_octets_0_da;
	DICT_ATTR const	*tmp_octets_1_da;
	DICT_ATTR const	*tmp_octets_2_da;
} rlm_preprocess_t;

static const CONF_PARSER module_config[] = {
	{ "huntgroups", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_preprocess_t, huntgroup_file), NULL },
	{ "hints", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_preprocess_t, hints_file), NULL },
	{ "with_ascend_hack", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_preprocess_t, with_ascend_hack), "no" },
	{ "ascend_channels_per_line", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_preprocess_t, ascend_channels_per_line), "23" },

	{ "with_ntdomain_hack", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_preprocess_t, with_ntdomain_hack), "no" },
	{ "with_specialix_jetstream_hack", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_preprocess_t, with_specialix_jetstream_hack), "no"  },
	{ "with_cisco_vsa_hack", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_preprocess_t, with_cisco_vsa_hack), "no" },
	{ "with_cisco_easy_psk_hack", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_preprocess_t, with_cisco_easy_psk_hack), "no" },
	{ "with_alvarion_vsa_hack", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_preprocess_t, with_alvarion_vsa_hack), "no" },
#if 0
	{ "with_cablelabs_vsa_hack", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_preprocess_t, with_cablelabs_vsa_hack), NULL },
#endif
	CONF_PARSER_TERMINATOR
};

/*
 *     See if a VALUE_PAIR list contains Fall-Through = Yes
 */
static int fall_through(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;
	tmp = fr_pair_find_by_num(vp, PW_FALL_THROUGH, 0, TAG_ANY);

	return tmp ? tmp->vp_integer : 0;
}

/*
 *	This hack changes Ascend's wierd port numberings
 *	to standard 0-??? port numbers so that the "+" works
 *	for IP address assignments.
 */
static void ascend_nasport_hack(VALUE_PAIR *nas_port, int channels_per_line)
{
	int service;
	int line;
	int channel;

	if (!nas_port) {
		return;
	}

	if (nas_port->vp_integer > 9999) {
		service = nas_port->vp_integer/10000; /* 1=digital 2=analog */
		line = (nas_port->vp_integer - (10000 * service)) / 100;
		channel = nas_port->vp_integer - ((10000 * service) + (100 * line));
		nas_port->vp_integer = (channel - 1) + ((line - 1) * channels_per_line);
	}
}

/*
 *	This hack strips out Cisco's VSA duplicities in lines
 *	(Cisco not implemented VSA's in standard way.
 *
 *	Cisco sends it's VSA attributes with the attribute name *again*
 *	in the string, like:  H323-Attribute = "h323-attribute=value".
 *	This sort of behaviour is nonsense.
 */
static void cisco_vsa_hack(REQUEST *request)
{
	int		vendorcode;
	char		*ptr;
	char		newattr[MAX_STRING_LEN];
	VALUE_PAIR	*vp;
	vp_cursor_t	cursor;
	for (vp = fr_cursor_init(&cursor, &request->packet->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		vendorcode = vp->da->vendor;
		if (!((vendorcode == 9) || (vendorcode == 6618) || (vendorcode == 35265))) {
			continue; /* not a Cisco, Quintum or Eltex VSA, continue */
		}

		if (vp->da->type != PW_TYPE_STRING) {
			continue;
		}

		/*
		 *  No weird packing.  Ignore it.
		 */
		ptr = strchr(vp->vp_strvalue, '='); /* find an '=' */
		if (!ptr) {
			continue;
		}

		/*
		 *	Cisco-AVPair's get packed as:
		 *
		 *	Cisco-AVPair = "h323-foo-bar = baz"
		 *	Cisco-AVPair = "h323-foo-bar=baz"
		 *
		 *	which makes sense only if you're a lunatic.
		 *	This code looks for the attribute named inside
		 *	of the string, and if it exists, adds it as a new
		 *	attribute.
		 */
		if (vp->da->attr == 1) {
			char const *p;

			p = vp->vp_strvalue;
			gettoken(&p, newattr, sizeof(newattr), false);

			if (dict_attrbyname(newattr) != NULL) {
				pair_make_request(newattr, ptr + 1, T_OP_EQ);
			}
		} else {	/* h322-foo-bar = "h323-foo-bar = baz" */
			/*
			 *	We strip out the duplicity from the
			 *	value field, we use only the value on
			 *	the right side of the '=' character.
			 */
			fr_pair_value_strcpy(vp, ptr + 1);
		}
	}
}


/*
 *	Don't even ask what this is doing...
 */

typedef struct cisco_easy_psk_info_t {
	uint8_t const	*ssid;
	size_t		ssid_len;
	uint8_t		bssid[6];
	uint8_t const	*anonce;
	size_t		anonce_len;
	uint8_t const	*eapol;
	size_t		eapol_len;
	size_t		eapol_fragments;
	bool		have_ssid;
	bool		have_bssid;
	bool		have_anonce;
	bool		have_eapol;
} cisco_easy_psk_info_t;

static int cisco_easy_psk_set_string(REQUEST *request, DICT_ATTR const *da,
				     uint8_t const *data, size_t len)
{
	VALUE_PAIR *vp;

	vp = fr_pair_find_by_da(request->packet->vps, da, TAG_ANY);
	if (!vp) vp = radius_pair_create(request->packet, &request->packet->vps, da->attr, da->vendor);
	if (!vp) return -1;

	fr_pair_value_bstrncpy(vp, data, len);
	return 0;
}

static int cisco_easy_psk_set_octets(REQUEST *request, DICT_ATTR const *da,
				     uint8_t const *data, size_t len)
{
	VALUE_PAIR *vp;

	vp = fr_pair_find_by_da(request->packet->vps, da, TAG_ANY);
	if (!vp) vp = radius_pair_create(request->packet, &request->packet->vps, da->attr, da->vendor);
	if (!vp) return -1;

	fr_pair_value_memcpy(vp, data, len);
	return 0;
}

static int cisco_easy_psk_parse_bssid(uint8_t out[6], uint8_t const *value, size_t len)
{
	char hex[12];
	size_t i, j;

	for (i = 0, j = 0; i < len; i++) {
		if (isxdigit(value[i])) {
			if (j >= sizeof(hex)) return -1;
			hex[j++] = value[i];
			continue;
		}

		if ((value[i] == '-') || (value[i] == ':') || (value[i] == '.') || isspace(value[i])) continue;
		return -1;
	}

	if (j != sizeof(hex)) return -1;
	if (fr_hex2bin(out, sizeof(out[0]) * 6, hex, sizeof(hex)) != 6) return -1;

	return 0;
}

static int cisco_easy_psk_extract(cisco_easy_psk_info_t *out, REQUEST *request, rlm_preprocess_t *inst)
{
	VALUE_PAIR *vp;
	vp_cursor_t cursor;
	bool saw_cisco_avpair = false;
	static uint8_t const cisco_wlan_ssid_prefix[] = "cisco-wlan-ssid=";
	static uint8_t const cisco_bssid_prefix[] = "cisco-bssid=";
	static uint8_t const cisco_anonce_prefix[] = "cisco-anonce=";
	static uint8_t const cisco_8021x_data_prefix[] = "cisco-8021x-data=";

	for (vp = fr_cursor_init(&cursor, &request->packet->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		size_t prefix_len;

		if (vp->da != inst->cisco_avpair_da) continue;
		saw_cisco_avpair = true;

		prefix_len = sizeof(cisco_wlan_ssid_prefix) - 1;
		if ((vp->vp_length > prefix_len) && (memcmp(vp->vp_octets, cisco_wlan_ssid_prefix, prefix_len) == 0)) {
			out->ssid = vp->vp_octets + prefix_len;
			out->ssid_len = vp->vp_length - prefix_len;
			out->have_ssid = (out->ssid_len > 0);
			continue;
		}

		prefix_len = sizeof(cisco_bssid_prefix) - 1;
		if ((vp->vp_length > prefix_len) && (memcmp(vp->vp_octets, cisco_bssid_prefix, prefix_len) == 0)) {
			if (cisco_easy_psk_parse_bssid(out->bssid, vp->vp_octets + prefix_len, vp->vp_length - prefix_len) < 0) {
				RDEBUG("Cisco EasyPSK BSSID is malformed");
				return -1;
			}
			out->have_bssid = true;
			continue;
		}

		prefix_len = sizeof(cisco_anonce_prefix) - 1;
		if ((vp->vp_length > prefix_len) && (memcmp(vp->vp_octets, cisco_anonce_prefix, prefix_len) == 0)) {
			out->anonce = vp->vp_octets + prefix_len;
			out->anonce_len = vp->vp_length - prefix_len;
			if (out->anonce_len != 32) {
				RDEBUG("Cisco EasyPSK ANonce has incorrect length (%zu != 32)", out->anonce_len);
				return -1;
			}
			out->have_anonce = true;
			continue;
		}

		prefix_len = sizeof(cisco_8021x_data_prefix) - 1;
		if ((vp->vp_length > prefix_len) && (memcmp(vp->vp_octets, cisco_8021x_data_prefix, prefix_len) == 0)) {
			out->eapol_fragments++;
			if (out->eapol_fragments > 1) {
				RDEBUG("Cisco EasyPSK EAPoL-Key data is fragmented; FT-PSK is not supported");
				return -1;
			}

			out->eapol = vp->vp_octets + prefix_len;
			out->eapol_len = vp->vp_length - prefix_len;
			if (out->eapol_len < 99) {
				RDEBUG("Cisco EasyPSK EAPoL-Key frame has incorrect length (%zu < 99)", out->eapol_len);
				return -1;
			}
			out->have_eapol = true;
			continue;
		}
	}

	if (!saw_cisco_avpair) return 0;
	if (!(out->have_ssid && out->have_bssid && out->have_anonce && out->have_eapol)) return 0;

	return 1;
}

static int cisco_easy_psk_apply(REQUEST *request, cisco_easy_psk_info_t const *info, rlm_preprocess_t *inst)
{
	if (cisco_easy_psk_set_string(request, inst->tmp_string_0_da, info->ssid, info->ssid_len) < 0) return -1;
	if (cisco_easy_psk_set_octets(request, inst->tmp_octets_0_da, info->bssid, sizeof(info->bssid)) < 0) return -1;
	if (cisco_easy_psk_set_octets(request, inst->tmp_octets_1_da, info->anonce, info->anonce_len) < 0) return -1;
	if (cisco_easy_psk_set_octets(request, inst->tmp_octets_2_da, info->eapol, info->eapol_len) < 0) return -1;

	return 0;
}

static rlm_rcode_t cisco_easy_psk_normalize(REQUEST *request, rlm_preprocess_t *inst)
{
	cisco_easy_psk_info_t info;
	int ret;

	memset(&info, 0, sizeof(info));

	ret = cisco_easy_psk_extract(&info, request, inst);
	if (ret == 0) return RLM_MODULE_NOOP;
	if (ret < 0) return RLM_MODULE_FAIL;

	if (cisco_easy_psk_apply(request, &info, inst) < 0) return RLM_MODULE_FAIL;

	return RLM_MODULE_UPDATED;
}

static void alvarion_vsa_hack(VALUE_PAIR *vp)
{
	int number = 1;
	vp_cursor_t cursor;

	for (vp = fr_cursor_init(&cursor, &vp);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		DICT_ATTR const *da;

		if (vp->da->vendor != 12394) {
			continue;
		}

		if (vp->da->type != PW_TYPE_STRING) {
			continue;
		}

		da = dict_attrbyvalue(number, 12394);
		if (!da) {
			continue;
		}

		vp->da = da;

		number++;
	}
}

/*
 *	Cablelabs magic, taken from:
 *
 * http://www.cablelabs.com/packetcable/downloads/specs/PKT-SP-EM-I12-05812.pdf
 *
 *	Sample data is:
 *
 *	0x0001d2d2026d30310000000000003030
 *	  3130303030000e812333000100033031
 *	  00000000000030303130303030000000
 *	  00063230313230313331303630323231
 *	  2e3633390000000081000500
 */

typedef struct cl_timezone_t {
	uint8_t		dst;
	uint8_t		sign;
	uint8_t		hh[2];
	uint8_t		mm[2];
	uint8_t		ss[2];
} cl_timezone_t;

typedef struct cl_bcid_t {
	uint32_t	timestamp;
	uint8_t		element_id[8];
	cl_timezone_t	timezone;
	uint32_t	event_counter;
} cl_bcid_t;

typedef struct cl_em_hdr_t {
	uint16_t	version;
	cl_bcid_t	bcid;
	uint16_t	message_type;
	uint16_t	element_type;
	uint8_t		element_id[8];
	cl_timezone_t	time_zone;
	uint32_t	sequence_number;
	uint8_t		event_time[18];
	uint8_t		status[4];
	uint8_t		priority;
	uint16_t	attr_count; /* of normal Cablelabs VSAs */
	uint8_t		event_object;
} cl_em_hdr_t;


static void cablelabs_vsa_hack(VALUE_PAIR **list)
{
	VALUE_PAIR *ev;

	ev = fr_pair_find_by_num(*list, 1, 4491, TAG_ANY); /* Cablelabs-Event-Message */
	if (!ev) {
		return;
	}

	/*
	 *	FIXME: write 100's of lines of code to decode
	 *	each data structure above.
	 */
}

/*
 *	Mangle username if needed, IN PLACE.
 */
static void rad_mangle(rlm_preprocess_t *inst, REQUEST *request)
{
	int		num_proxy_state;
	VALUE_PAIR	*namepair;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	*tmp;
	vp_cursor_t	cursor;

	/*
	 *	Get the username from the request
	 *	If it isn't there, then we can't mangle the request.
	 */
	request_pairs = request->packet->vps;
	namepair = fr_pair_find_by_num(request_pairs, PW_USER_NAME, 0, TAG_ANY);
	if (!namepair || (namepair->vp_length == 0)) {
		return;
	}

	if (inst->with_ntdomain_hack) {
		char *ptr;
		char newname[MAX_STRING_LEN];

		/*
		 *	Windows NT machines often authenticate themselves as
		 *	NT_DOMAIN\username. Try to be smart about this.
		 *
		 *	FIXME: should we handle this as a REALM ?
		 */
		if ((ptr = strchr(namepair->vp_strvalue, '\\')) != NULL) {
			strlcpy(newname, ptr + 1, sizeof(newname));
			/* Same size */
			fr_pair_value_strcpy(namepair, newname);
		}
	}

	if (inst->with_specialix_jetstream_hack) {
		/*
		 *	Specialix Jetstream 8500 24 port access server.
		 *	If the user name is 10 characters or longer, a "/"
		 *	and the excess characters after the 10th are
		 *	appended to the user name.
		 *
		 *	Reported by Lucas Heise <root@laonet.net>
		 */
		if ((strlen(namepair->vp_strvalue) > 10) &&
		    (namepair->vp_strvalue[10] == '/')) {
			fr_pair_value_strcpy(namepair, namepair->vp_strvalue + 11);
		}
	}

	/*
	 *	Small check: if Framed-Protocol present but Service-Type
	 *	is missing, add Service-Type = Framed-User.
	 */
	if (fr_pair_find_by_num(request_pairs, PW_FRAMED_PROTOCOL, 0, TAG_ANY) != NULL &&
	    fr_pair_find_by_num(request_pairs, PW_SERVICE_TYPE, 0, TAG_ANY) == NULL) {
		tmp = radius_pair_create(request->packet, &request->packet->vps, PW_SERVICE_TYPE, 0);
		tmp->vp_integer = PW_FRAMED_USER;
	}

	num_proxy_state = 0;
	for (tmp = fr_cursor_init(&cursor, &request->packet->vps);
	     tmp;
	     tmp = fr_cursor_next(&cursor)) {
		if (tmp->da->vendor != 0) {
			continue;
		}

		if (tmp->da->attr != PW_PROXY_STATE) {
			continue;
		}

		num_proxy_state++;
	}

	if (num_proxy_state > 10) {
		RWDEBUG("There are more than 10 Proxy-State attributes in the request");
		RWDEBUG("You have likely configured an infinite proxy loop");
	}
}

/*
 *	Compare the request with the "reply" part in the
 *	huntgroup, which normally only contains username or group.
 *	At least one of the "reply" items has to match.
 */
static int hunt_paircmp(REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check)
{
	vp_cursor_t	cursor;
	VALUE_PAIR	*check_item;
	VALUE_PAIR	*tmp;
	int		result = -1;

	if (!check) return 0;

	for (check_item = fr_cursor_init(&cursor, &check);
	     check_item && (result != 0);
	     check_item = fr_cursor_next(&cursor)) {
		/* FIXME: fr_pair_list_copy should be removed once VALUE_PAIRs are no longer in linked lists */
		tmp = fr_pair_copy(request, check_item);
		tmp->op = check_item->op;
		result = paircompare(req, request, tmp, NULL);
		fr_pair_list_free(&tmp);
	}

	return result;
}


/*
 *	Add hints to the info sent by the terminal server
 *	based on the pattern of the username, and other attributes.
 */
static int hints_setup(PAIR_LIST *hints, REQUEST *request)
{
	char const     	*name;
	VALUE_PAIR	*add;
	VALUE_PAIR	*tmp;
	PAIR_LIST	*i;
	int		updated = 0, ft;

	if (!hints || !request->packet->vps)
		return RLM_MODULE_NOOP;

	/*
	 *	Check for valid input, zero length names not permitted
	 */
	name = (tmp = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY)) ?
		tmp->vp_strvalue : NULL;
	if (!name || name[0] == 0) {
		/*
		 *	No name, nothing to do.
		 */
		return RLM_MODULE_NOOP;
	}

	for (i = hints; i; i = i->next) {
		/*
		 *	Use "paircompare", which is a little more general...
		 */
		if (((strcmp(i->name, "DEFAULT") == 0) || (strcmp(i->name, name) == 0)) &&
		    (paircompare(request, request->packet->vps, i->check, NULL) == 0)) {
			RDEBUG2("hints: Matched %s at %d", i->name, i->lineno);
			/*
			 *	Now add all attributes to the request list,
			 *	except PW_STRIP_USER_NAME and PW_FALL_THROUGH
			 *	and xlat them.
			 */
			add = fr_pair_list_copy(request->packet, i->reply);
			ft = fall_through(add);

			fr_pair_delete_by_num(&add, PW_STRIP_USER_NAME, 0, TAG_ANY);
			fr_pair_delete_by_num(&add, PW_FALL_THROUGH, 0, TAG_ANY);
			radius_pairmove(request, &request->packet->vps, add, true);

			updated = 1;
			if (!ft) {
				break;
			}
		}
	}

	if (updated == 0) {
		return RLM_MODULE_NOOP;
	}

	return RLM_MODULE_UPDATED;
}

/*
 *	See if we have access to the huntgroup.
 */
static int huntgroup_access(REQUEST *request, PAIR_LIST *huntgroups)
{
	PAIR_LIST	*i;
	int		r = RLM_MODULE_OK;
	VALUE_PAIR	*request_pairs = request->packet->vps;

	/*
	 *	We're not controlling access by huntgroups:
	 *	Allow them in.
	 */
	if (!huntgroups) {
		return RLM_MODULE_OK;
	}

	for (i = huntgroups; i; i = i->next) {
		/*
		 *	See if this entry matches.
		 */
		if (paircompare(request, request_pairs, i->check, NULL) != 0) {
			continue;
		}

		/*
		 *	Now check for access.
		 */
		r = RLM_MODULE_REJECT;
		if (hunt_paircmp(request, request_pairs, i->reply) == 0) {
			VALUE_PAIR *vp;

			/*
			 *  We've matched the huntgroup, so add it in
			 *  to the list of request pairs.
			 */
			vp = fr_pair_find_by_num(request_pairs, PW_HUNTGROUP_NAME, 0, TAG_ANY);
			if (!vp) {
				vp = radius_pair_create(request->packet, &request->packet->vps, PW_HUNTGROUP_NAME, 0);
				fr_pair_value_strcpy(vp, i->name);
			}
			r = RLM_MODULE_OK;
		}
		break;
	}

	return r;
}

/*
 *	If the NAS wasn't smart enought to add a NAS-IP-Address
 *	to the request, then add it ourselves.
 */
static int add_nas_attr(REQUEST *request)
{
	VALUE_PAIR *nas;

	switch (request->packet->src_ipaddr.af) {
	case AF_INET:
		nas = fr_pair_find_by_num(request->packet->vps, PW_NAS_IP_ADDRESS, 0, TAG_ANY);
		if (!nas) {
			nas = radius_pair_create(request->packet, &request->packet->vps, PW_NAS_IP_ADDRESS, 0);
			nas->vp_ipaddr = request->packet->src_ipaddr.ipaddr.ip4addr.s_addr;
		}
		break;

	case AF_INET6:
		nas = fr_pair_find_by_num(request->packet->vps, PW_NAS_IPV6_ADDRESS, 0, TAG_ANY);
		if (!nas) {
			nas = radius_pair_create(request->packet, &request->packet->vps, PW_NAS_IPV6_ADDRESS, 0);
			memcpy(&nas->vp_ipv6addr, &request->packet->src_ipaddr.ipaddr,
			       sizeof(request->packet->src_ipaddr.ipaddr));
		}
		break;

	default:
		ERROR("Unknown address family for packet");
		return -1;
	}

	return 0;
}


/*
 *	Initialize.
 */
static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	int ret;
	rlm_preprocess_t *inst = instance;

	/*
	 *	Read the huntgroups file.
	 */
	if (inst->huntgroup_file) {
		ret = pairlist_read(inst, inst->huntgroup_file, &(inst->huntgroups), 0);
		if (ret < 0) {
			ERROR("rlm_preprocess: Error reading %s", inst->huntgroup_file);

			return -1;
		}
	}

	/*
	 *	Read the hints file.
	 */
	if (inst->hints_file) {
		ret = pairlist_read(inst, inst->hints_file, &(inst->hints), 0);
		if (ret < 0) {
			ERROR("rlm_preprocess: Error reading %s", inst->hints_file);

			return -1;
		}
	}

	if (inst->with_cisco_easy_psk_hack) {
		inst->cisco_avpair_da = dict_attrbyname("Cisco-AVPair");
		inst->tmp_string_0_da = dict_attrbyname("Tmp-String-0");
		inst->tmp_octets_0_da = dict_attrbyname("Tmp-Octets-0");
		inst->tmp_octets_1_da = dict_attrbyname("Tmp-Octets-1");
		inst->tmp_octets_2_da = dict_attrbyname("Tmp-Octets-2");

		if (!inst->cisco_avpair_da || !inst->tmp_string_0_da || !inst->tmp_octets_0_da ||
		    !inst->tmp_octets_1_da || !inst->tmp_octets_2_da) {
			ERROR("rlm_preprocess: Failed resolving Cisco EasyPSK dictionary attributes");
			return -1;
		}
	}

	return 0;
}

/*
 *	Preprocess a request.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	int r;
	rlm_preprocess_t *inst = instance;

	VALUE_PAIR *vp;

	/*
	 *	Mangle the username, to get rid of stupid implementation
	 *	bugs.
	 */
	rad_mangle(inst, request);

	if (inst->with_ascend_hack) {
		/*
		 *	If we're using Ascend systems, hack the NAS-Port-Id
		 *	in place, to go from Ascend's weird values to something
		 *	approaching rationality.
		 */
		ascend_nasport_hack(fr_pair_find_by_num(request->packet->vps, PW_NAS_PORT, 0, TAG_ANY),
				    inst->ascend_channels_per_line);
	}

	if (inst->with_cisco_vsa_hack) {
		/*
		 *	We need to run this hack because the h323-conf-id
		 *	attribute should be used.
		 */
		cisco_vsa_hack(request);
	}

	if (inst->with_cisco_easy_psk_hack) {
		r = cisco_easy_psk_normalize(request, inst);
		if (r == RLM_MODULE_FAIL) return r;
	}

	if (inst->with_alvarion_vsa_hack) {
		/*
		 *	We need to run this hack because the Alvarion
		 *	people are crazy.
		 */
		alvarion_vsa_hack(request->packet->vps);
	}

	if (inst->with_cablelabs_vsa_hack) {
		/*
		 *	We need to run this hack because the Cablelabs
		 *	people are crazy.
		 */
		cablelabs_vsa_hack(&request->packet->vps);
	}

	/*
	 *	Add an event timestamp. Means Event-Timestamp can be used
	 *	consistently instead of one letter expansions.
	 */
	vp = fr_pair_find_by_num(request->packet->vps, PW_EVENT_TIMESTAMP, 0, TAG_ANY);
	if (!vp) {
		vp = radius_pair_create(request->packet, &request->packet->vps, PW_EVENT_TIMESTAMP, 0);
		vp->vp_date = request->packet->timestamp.tv_sec;
	}

	/*
	 *	Note that we add the Request-Src-IP-Address to the request
	 *	structure BEFORE checking huntgroup access.  This allows
	 *	the Request-Src-IP-Address to be used for huntgroup
	 *	comparisons.
	 */
	if (add_nas_attr(request) < 0) {
		return RLM_MODULE_FAIL;
	}

	hints_setup(inst->hints, request);

	/*
	 *      If there is a PW_CHAP_PASSWORD attribute but there
	 *      is PW_CHAP_CHALLENGE we need to add it so that other
	 *	modules can use it as a normal attribute.
	 */
	if (fr_pair_find_by_num(request->packet->vps, PW_CHAP_PASSWORD, 0, TAG_ANY) &&
	    fr_pair_find_by_num(request->packet->vps, PW_CHAP_CHALLENGE, 0, TAG_ANY) == NULL) {
		vp = radius_pair_create(request->packet, &request->packet->vps, PW_CHAP_CHALLENGE, 0);
		fr_pair_value_memcpy(vp, request->packet->vector, AUTH_VECTOR_LEN);
	}

	if ((r = huntgroup_access(request, inst->huntgroups)) != RLM_MODULE_OK) {
		char buf[1024];
		RIDEBUG("No huntgroup access: [%s] (%s)",
			request->username ? request->username->vp_strvalue : "<NO User-Name>",
			auth_name(buf, sizeof(buf), request, 1));

		return r;
	}

	return RLM_MODULE_OK; /* Meaning: try next authorization module */
}

/*
 *	Preprocess a request before accounting
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preaccounting(void *instance, REQUEST *request)
{
	int r;
	VALUE_PAIR *vp;
	rlm_preprocess_t *inst = instance;

	/*
	 *  Ensure that we have the SAME user name for both
	 *  authentication && accounting.
	 */
	rad_mangle(inst, request);

	if (inst->with_cisco_vsa_hack) {
		/*
		 *	We need to run this hack because the h323-conf-id
		 *	attribute should be used.
		 */
		cisco_vsa_hack(request);
	}

	if (inst->with_alvarion_vsa_hack) {
		/*
		 *	We need to run this hack because the Alvarion
		 *	people are crazy.
		 */
		alvarion_vsa_hack(request->packet->vps);
	}

	if (inst->with_cablelabs_vsa_hack) {
		/*
		 *	We need to run this hack because the Cablelabs
		 *	people are crazy.
		 */
		cablelabs_vsa_hack(&request->packet->vps);
	}

	/*
	 *  Ensure that we log the NAS IP Address in the packet.
	 */
	if (add_nas_attr(request) < 0) {
		return RLM_MODULE_FAIL;
	}

	hints_setup(inst->hints, request);

	/*
	 *	Add an event timestamp.  This means that the rest of
	 *	the server can use it, rather than various error-prone
	 *	manual calculations.
	 */
	vp = fr_pair_find_by_num(request->packet->vps, PW_EVENT_TIMESTAMP, 0, TAG_ANY);
	if (!vp) {
		VALUE_PAIR *delay;

		vp = radius_pair_create(request->packet, &request->packet->vps, PW_EVENT_TIMESTAMP, 0);
		vp->vp_date = request->packet->timestamp.tv_sec;

		delay = fr_pair_find_by_num(request->packet->vps, PW_ACCT_DELAY_TIME, 0, TAG_ANY);
		if (delay) {
			if ((delay->vp_integer >= vp->vp_date) || (delay->vp_integer == UINT32_MAX)) {
				RWARN("Ignoring invalid Acct-Delay-time of %u seconds", delay->vp_integer);
			} else {
				vp->vp_date -= delay->vp_integer;
			}
		}
	}

	if ((r = huntgroup_access(request, inst->huntgroups)) != RLM_MODULE_OK) {
		char buf[1024];
		RIDEBUG("No huntgroup access: [%s] (%s)",
			request->username ? request->username->vp_strvalue : "<NO User-Name>",
			auth_name(buf, sizeof(buf), request, 1));
		return r;
	}

	return r;
}

/* globally exported name */
extern module_t rlm_preprocess;
module_t rlm_preprocess = {
	.magic		= RLM_MODULE_INIT,
	.name		= "preprocess",
	.inst_size	= sizeof(rlm_preprocess_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preaccounting
	},
};

