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
 * @file rlm_wimax.c
 * @brief Supports various WiMax functionality.
 *
 * @copyright 2008 Alan DeKok (aland@networkradius.com)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#define LOG_PREFIX "rlm_wimax - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/missing.h>
#include <freeradius-devel/util/hex.h>

/*
 *	FIXME: Add check for this header to configure.ac
 */
#include <openssl/hmac.h>

/*
 *	FIXME: Fix the build system to create definitions from names.
 */
typedef struct {
	bool	delete_mppe_keys;
} rlm_wimax_t;

static const CONF_PARSER module_config[] = {
  { FR_CONF_OFFSET("delete_mppe_keys", FR_TYPE_BOOL, rlm_wimax_t, delete_mppe_keys), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;
static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_wimax_dict[];
fr_dict_autoload_t rlm_wimax_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_eap_emsk;
static fr_dict_attr_t const *attr_eap_msk;
static fr_dict_attr_t const *attr_wimax_mn_nai;

static fr_dict_attr_t const *attr_calling_station_id;

static fr_dict_attr_t const *attr_wimax_msk;
static fr_dict_attr_t const *attr_wimax_ip_technology;
static fr_dict_attr_t const *attr_wimax_mn_hha_mip4_key;
static fr_dict_attr_t const *attr_wimax_mn_hha_mip4_spi;
static fr_dict_attr_t const *attr_wimax_hha_ip_mip4;
static fr_dict_attr_t const *attr_wimax_hha_ip_mip6;
static fr_dict_attr_t const *attr_wimax_mn_hha_mip6_key;
static fr_dict_attr_t const *attr_wimax_mn_hha_mip6_spi;
static fr_dict_attr_t const *attr_wimax_fa_rk_key;
static fr_dict_attr_t const *attr_wimax_fa_rk_spi;
static fr_dict_attr_t const *attr_wimax_rrq_mn_ha_spi;
static fr_dict_attr_t const *attr_wimax_rrq_ha_ip;
static fr_dict_attr_t const *attr_wimax_ha_rk_key_requested;

static fr_dict_attr_t const *attr_ms_mppe_send_key;
static fr_dict_attr_t const *attr_ms_mppe_recv_key;

extern fr_dict_attr_autoload_t rlm_wimax_dict_attr[];
fr_dict_attr_autoload_t rlm_wimax_dict_attr[] = {
	{ .out = &attr_eap_emsk, .name = "EAP-EMSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_eap_msk, .name = "EAP-MSK", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },
	{ .out = &attr_wimax_mn_nai, .name = "WiMAX-MN-NAI", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_calling_station_id, .name = "Calling-Station-ID", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ .out = &attr_wimax_msk, .name = "WiMAX-MSK", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_ip_technology, .name = "WiMAX-IP-Technology", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_mn_hha_mip4_key, .name = "WiMAX-MN-hHA-MIP4-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_mn_hha_mip4_spi, .name = "WiMAX-MN-hHA-MIP4-SPI", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_hha_ip_mip4, .name = "WiMAX-hHA-IP-MIP4", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_wimax_hha_ip_mip6, .name = "WiMAX-hHA-IP-MIP6", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_radius },
	{ .out = &attr_wimax_mn_hha_mip6_key, .name = "WiMAX-MN-hHA-MIP6-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_mn_hha_mip6_spi, .name = "WiMAX-MN-hHA-MIP6-SPI", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_fa_rk_key, .name = "WiMAX-FA-RK-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_wimax_fa_rk_spi, .name = "WiMAX-FA-RK-SPI", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_rrq_mn_ha_spi, .name = "WiMAX-RRQ-MN-HA-SPI", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_wimax_rrq_ha_ip, .name = "WiMAX-RRQ-HA-IP", .type = FR_TYPE_COMBO_IP_ADDR, .dict = &dict_radius },
	{ .out = &attr_wimax_ha_rk_key_requested, .name = "WiMAX-HA-RK-Key-Requested", .type = FR_TYPE_UINT32, .dict = &dict_radius },

	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ NULL }
};

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	fr_pair_t *vp;

	/*
	 *	Fix Calling-Station-Id.  Damn you, WiMAX!
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_calling_station_id);
	if (vp && (vp->vp_length == 6)) {
		int	i;
		char	*p;
		uint8_t	buffer[6];

		memcpy(buffer, vp->vp_strvalue, 6);

		MEM(fr_pair_value_bstr_realloc(vp, &p, (5 * 3) + 2) == 0);

		/*
		 *	RFC 3580 Section 3.20 says this is the preferred
		 *	format.  Everyone *SANE* is using this format,
		 *	so we fix it here.
		 */
		for (i = 0; i < 6; i++) {
			fr_bin2hex(&FR_SBUFF_OUT(&p[i * 3], 2 + 1), &FR_DBUFF_TMP(&buffer[i], 1), SIZE_MAX);
			p[(i * 3) + 2] = '-';
		}

		DEBUG2("Fixing WiMAX binary Calling-Station-Id to %pV", &vp->data);
		RETURN_MODULE_OK;
	}

	RETURN_MODULE_NOOP;
}

/*
 *	Massage the request before recording it or proxying it
 */
static unlang_action_t CC_HINT(nonnull) mod_preacct(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	return mod_authorize(p_result, mctx, request);
}

/*
 *	Generate the keys after the user has been authenticated.
 */
static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_wimax_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_wimax_t);
	fr_pair_t		*msk, *emsk, *vp;
	fr_pair_t		*mn_nai, *ip, *fa_rk;
	HMAC_CTX		*hmac;
	unsigned int		rk1_len, rk2_len, rk_len;
	uint32_t		mip_spi;
	uint8_t			usage_data[24];
	uint8_t			mip_rk_1[EVP_MAX_MD_SIZE], mip_rk_2[EVP_MAX_MD_SIZE];
	uint8_t			mip_rk[2 * EVP_MAX_MD_SIZE];

	msk = fr_pair_find_by_da(&request->reply_pairs, attr_eap_msk);
	emsk = fr_pair_find_by_da(&request->reply_pairs, attr_eap_emsk);
	if (!msk || !emsk) {
		REDEBUG2("No EAP-MSK or EAP-EMSK.  Cannot create WiMAX keys");
		RETURN_MODULE_NOOP;
	}

	/*
	 *	If we delete the MS-MPPE-*-Key attributes, then add in
	 *	the WiMAX-MSK so that the client has a key available.
	 */
	if (inst->delete_mppe_keys) {
		pair_delete_reply(attr_ms_mppe_send_key);
		pair_delete_reply(attr_ms_mppe_recv_key);

		MEM(pair_update_reply(&vp, attr_wimax_msk) >= 0);
		fr_pair_value_memdup(vp, msk->vp_octets, msk->vp_length, false);
	}

	/*
	 *	Initialize usage data.
	 */
	memcpy(usage_data, "miprk@wimaxforum.org", 21);	/* with trailing \0 */
	usage_data[21] = 0x02;
	usage_data[22] = 0x00;
	usage_data[23] = 0x01;

	/*
	 *	MIP-RK-1 = HMAC-SSHA256(EMSK, usage-data | 0x01)
	 */
	hmac = HMAC_CTX_new();
	HMAC_Init_ex(hmac, emsk->vp_octets, emsk->vp_length, EVP_sha256(), NULL);

	HMAC_Update(hmac, &usage_data[0], sizeof(usage_data));
	HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

	/*
	 *	MIP-RK-2 = HMAC-SSHA256(EMSK, MIP-RK-1 | usage-data | 0x01)
	 */
	HMAC_Init_ex(hmac, emsk->vp_octets, emsk->vp_length, EVP_sha256(), NULL);

	HMAC_Update(hmac, (uint8_t const *) &mip_rk_1, rk1_len);
	HMAC_Update(hmac, &usage_data[0], sizeof(usage_data));
	HMAC_Final(hmac, &mip_rk_2[0], &rk2_len);

	memcpy(mip_rk, mip_rk_1, rk1_len);
	memcpy(mip_rk + rk1_len, mip_rk_2, rk2_len);
	rk_len = rk1_len + rk2_len;

	/*
	 *	MIP-SPI = HMAC-SSHA256(MIP-RK, "SPI CMIP PMIP");
	 */
	HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha256(), NULL);

	HMAC_Update(hmac, (uint8_t const *) "SPI CMIP PMIP", 12);
	HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

	/*
	 *	Take the 4 most significant octets.
	 *	If less than 256, add 256.
	 */
	mip_spi = ((mip_rk_1[0] << 24) | (mip_rk_1[1] << 16) |
		   (mip_rk_1[2] << 8) | mip_rk_1[3]);
	if (mip_spi < 256) mip_spi += 256;

	REDEBUG2("MIP-RK = 0x%pH", fr_box_octets(mip_rk, rk_len));
	REDEBUG2("MIP-SPI = %08x", ntohl(mip_spi));

	/*
	 *	FIXME: Perform SPI collision prevention
	 */

	/*
	 *	Calculate mobility keys
	 */
	mn_nai = fr_pair_find_by_da(&request->request_pairs, attr_wimax_mn_nai);
	if (!mn_nai) mn_nai = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_mn_nai);
	if (!mn_nai) {
		RWDEBUG("%s was not found in the request or in the reply", attr_wimax_mn_nai->name);
		RWDEBUG("We cannot calculate MN-HA keys");
	}

	/*
	 *	WiMAX-IP-Technology
	 */
	vp = NULL;
	if (mn_nai) vp = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_ip_technology);
	if (!vp) {
		RWDEBUG("%s not found in reply", attr_wimax_ip_technology->name);
		RWDEBUG("Not calculating MN-HA keys");
	}

	if (vp) switch (vp->vp_uint32) {
	case 2:			/* PMIP4 */
		/*
		 *	Look for WiMAX-hHA-IP-MIP4
		 */
		ip = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_hha_ip_mip4);
		if (!ip) {
			RWDEBUG("%s not found.  Cannot calculate MN-HA-PMIP4 key", attr_wimax_hha_ip_mip4->name);
			break;
		}

		/*
		 *	MN-HA-PMIP4 =
		 *	   H(MIP-RK, "PMIP4 MN HA" | HA-IPv4 | MN-NAI);
		 */
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "PMIP4 MN HA", 11);
		HMAC_Update(hmac, (uint8_t const *) &ip->vp_ipv4addr, 4);
		HMAC_Update(hmac, (uint8_t const *) &mn_nai->vp_strvalue, mn_nai->vp_length);
		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-PMIP4 into WiMAX-MN-hHA-MIP4-Key
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip4_key) >= 0);
		fr_pair_value_memdup(vp, &mip_rk_1[0], rk1_len, false);

		/*
		 *	Put MN-HA-PMIP4-SPI into WiMAX-MN-hHA-MIP4-SPI
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip4_spi) >= 0);
		vp->vp_uint32 = mip_spi + 1;
		break;

	case 3:			/* CMIP4 */
		/*
		 *	Look for WiMAX-hHA-IP-MIP4
		 */
		ip = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_hha_ip_mip4);
		if (!ip) {
			RWDEBUG("%s not found.  Cannot calculate MN-HA-CMIP4 key", attr_wimax_hha_ip_mip4->name);
			break;
		}

		/*
		 *	MN-HA-CMIP4 =
		 *	   H(MIP-RK, "CMIP4 MN HA" | HA-IPv4 | MN-NAI);
		 */
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "CMIP4 MN HA", 11);
		HMAC_Update(hmac, (uint8_t const *) &ip->vp_ipv4addr, 4);
		HMAC_Update(hmac, (uint8_t const *) &mn_nai->vp_strvalue, mn_nai->vp_length);
		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-CMIP4 into WiMAX-MN-hHA-MIP4-Key
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip4_key) >= 0);
		fr_pair_value_memdup(vp, &mip_rk_1[0], rk1_len, false);

		/*
		 *	Put MN-HA-CMIP4-SPI into WiMAX-MN-hHA-MIP4-SPI
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip4_spi) >= 0);
		vp->vp_uint32 = mip_spi;
		break;

	case 4:			/* CMIP6 */
		/*
		 *	Look for WiMAX-hHA-IP-MIP6
		 */
		ip = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_hha_ip_mip6);
		if (!ip) {
			RWDEBUG("%s not found.  Cannot calculate MN-HA-CMIP6 key", attr_wimax_hha_ip_mip6->name);
			break;
		}

		/*
		 *	MN-HA-CMIP6 =
		 *	   H(MIP-RK, "CMIP6 MN HA" | HA-IPv6 | MN-NAI);
		 */
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "CMIP6 MN HA", 11);
		HMAC_Update(hmac, (uint8_t const *) &ip->vp_ipv6addr, 16);
		HMAC_Update(hmac, (uint8_t const *) &mn_nai->vp_strvalue, mn_nai->vp_length);
		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-CMIP6 into WiMAX-MN-hHA-MIP6-Key
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip6_key) >= 0);
		fr_pair_value_memdup(vp, &mip_rk_1[0], rk1_len, false);

		/*
		 *	Put MN-HA-CMIP6-SPI into WiMAX-MN-hHA-MIP6-SPI
		 */
		MEM(pair_update_reply(&vp, attr_wimax_mn_hha_mip6_spi) >= 0);
		vp->vp_uint32 = mip_spi + 2;
		break;

	default:
		break;		/* do nothing */
	}

	/*
	 *	Generate FA-RK, if requested.
	 *
	 *	FA-RK= H(MIP-RK, "FA-RK")
	 */
	fa_rk = fr_pair_find_by_da(&request->reply_pairs, attr_wimax_fa_rk_key);
	if (fa_rk && (fa_rk->vp_length <= 1)) {
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "FA-RK", 5);

		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		fr_pair_value_memdup(fa_rk, &mip_rk_1[0], rk1_len, false);
	}

	/*
	 *	Create FA-RK-SPI, which is really SPI-CMIP4, which is
	 *	really MIP-SPI.  Clear?  Of course.  This is WiMAX.
	 */
	if (fa_rk) {
		MEM(pair_update_reply(&vp, attr_wimax_fa_rk_spi) >= 0);
		vp->vp_uint32 = mip_spi;
	}

	/*
	 *	Give additional information about requests && responses
	 *
	 *	WiMAX-RRQ-MN-HA-SPI
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_wimax_rrq_mn_ha_spi);
	if (vp) {
		REDEBUG2("Client requested MN-HA key: Should use SPI to look up key from storage");
		if (!mn_nai) {
			RWDEBUG("MN-NAI was not found!");
		}

		/*
		 *	WiMAX-RRQ-HA-IP
		 */
		if (!fr_pair_find_by_da(&request->request_pairs, attr_wimax_rrq_ha_ip)) {
			RWDEBUG("HA-IP was not found!");
		}

		/*
		 *	WiMAX-HA-RK-Key-Requested
		 */
		vp = fr_pair_find_by_da(&request->request_pairs, attr_wimax_ha_rk_key_requested);
		if (vp && (vp->vp_uint32 == 1)) {
			REDEBUG2("Client requested HA-RK: Should use IP to look it up from storage");
		}
	}

	/*
	 *	Wipe the context of all sensitive information.
	 */
	HMAC_CTX_free(hmac);

	RETURN_MODULE_UPDATED;
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
extern module_t rlm_wimax;
module_t rlm_wimax = {
	.magic		= RLM_MODULE_INIT,
	.name		= "wimax",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_wimax_t),
	.config		= module_config,
	.dict		= &dict_radius,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
