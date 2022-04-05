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
 * @copyright 2008 Alan DeKok <aland@networkradius.com>
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include "milenage.h"

#ifdef HAVE_OPENSSL_HMAC_H
#include <openssl/hmac.h>
#endif

#include <freeradius-devel/openssl3.h>

#define WIMAX_EPSAKA_RAND_SIZE	16
#define WIMAX_EPSAKA_KI_SIZE	16
#define WIMAX_EPSAKA_OPC_SIZE	16
#define WIMAX_EPSAKA_AMF_SIZE	2
#define WIMAX_EPSAKA_SQN_SIZE	6
#define WIMAX_EPSAKA_MAC_A_SIZE	8
#define WIMAX_EPSAKA_MAC_S_SIZE	8
#define WIMAX_EPSAKA_XRES_SIZE	8
#define WIMAX_EPSAKA_CK_SIZE	16
#define WIMAX_EPSAKA_IK_SIZE	16
#define WIMAX_EPSAKA_AK_SIZE	6
#define WIMAX_EPSAKA_AK_RESYNC_SIZE	6
#define WIMAX_EPSAKA_KK_SIZE	32
#define WIMAX_EPSAKA_KS_SIZE	14
#define WIMAX_EPSAKA_PLMN_SIZE	3
#define WIMAX_EPSAKA_KASME_SIZE	32
#define WIMAX_EPSAKA_AUTN_SIZE	16
#define WIMAX_EPSAKA_AUTS_SIZE  14

/*
 *	FIXME: Fix the build system to create definitions from names.
 */
typedef struct rlm_wimax_t {
	bool	delete_mppe_keys;

	DICT_ATTR const	*resync_info;
	DICT_ATTR const	*xres;
	DICT_ATTR const	*autn;
	DICT_ATTR const	*kasme;
} rlm_wimax_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "delete_mppe_keys", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_wimax_t, delete_mppe_keys), "no" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Print hex values in a readable format for debugging
 *	Example:
 *	FOO: 00 11 AA 22 00 FF
 */
static void rdebug_hex(REQUEST *request, char const *prefix, uint8_t const *data, int len)
{
	int i;
	char buffer[256];	/* large enough for largest len */

	/*
	 *	Leave a trailing space, we don't really care about that.
	 */
	for (i = 0; i < len; i++) {
		snprintf(buffer + i * 3, sizeof(buffer) - i * 3, "%02x ", data[i]);
	}

	RDEBUG("%s %s", prefix, buffer);
}
#define RDEBUG_HEX if (rad_debug_lvl) rdebug_hex

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR *vp;
	rlm_wimax_t *inst = instance;

	/*
	 *	Fix Calling-Station-Id.  Damn you, WiMAX!
	 */
	vp =  fr_pair_find_by_num(request->packet->vps, PW_CALLING_STATION_ID, 0, TAG_ANY);
	if (vp && (vp->vp_length == 6)) {
		int i;
		char *p;
		uint8_t buffer[6];

		memcpy(buffer, vp->vp_strvalue, 6);
		vp->vp_length = (5*3)+2;
		vp->vp_strvalue = p = talloc_array(vp, char, vp->vp_length + 1);
		vp->type = VT_DATA;

		/*
		 *	RFC 3580 Section 3.20 says this is the preferred
		 *	format.  Everyone *SANE* is using this format,
		 *	so we fix it here.
		 */
		for (i = 0; i < 6; i++) {
			fr_bin2hex(&p[i * 3], &buffer[i], 1);
			p[(i * 3) + 2] = '-';
		}

		p[(5*3)+2] = '\0';

		DEBUG2("rlm_wimax: Fixing WiMAX binary Calling-Station-Id to %s",
		       vp->vp_strvalue);
		return RLM_MODULE_OK;
	}

	/*
	 *	Check for attr WiMAX-Re-synchronization-Info
	 *	which contains the concatenation of RAND and AUTS
	 *
	 *	If it is present then we proceed to verify the SIM and
	 *	extract the new value of SQN
	 */
	VALUE_PAIR *resync_info, *ki, *opc, *sqn, *rand;
	int m_ret;

	/* Look for the Re-synchronization-Info attribute in the request */
	resync_info = fr_pair_find_by_da(request->packet->vps, inst->resync_info, TAG_ANY);
	if (resync_info && (resync_info->vp_length < (WIMAX_EPSAKA_RAND_SIZE + WIMAX_EPSAKA_AUTS_SIZE))) {
		RWDEBUG("Found request:WiMAX-Re-synchronization-Info with incorrect length: Ignoring it");
		resync_info = NULL;
	}

	/*
	 *	These are the private keys which should be added to the control
	 *	list after looking them up in a database by IMSI
	 *
	 *	We grab them from the control list here
	 */
	ki = fr_pair_find_by_num(request->config, PW_WIMAX_SIM_KI, 0, TAG_ANY);
	if (ki && (ki->vp_length < MILENAGE_CK_SIZE)) {
		RWDEBUG("Found config:WiMAX-SIM-Ki with incorrect length: Ignoring it");
		ki = NULL;
	}

	opc = fr_pair_find_by_num(request->config, PW_WIMAX_SIM_OPC, 0, TAG_ANY);
	if (opc && (opc->vp_length < MILENAGE_IK_SIZE)) {
		RWDEBUG("Found config:WiMAX-SIM-OPC with incorrect length: Ignoring it");
		opc = NULL;
	}

	/* If we have resync info (RAND and AUTS), Ki and OPc then we can proceed */
	if (resync_info && ki && opc) {
		uint64_t sqn_bin;
		uint8_t rand_bin[WIMAX_EPSAKA_RAND_SIZE];
		uint8_t auts_bin[WIMAX_EPSAKA_AUTS_SIZE];

		RDEBUG("Found WiMAX-Re-synchronization-Info. Proceeding with SQN resync");

		/* Split Re-synchronization-Info into seperate RAND and AUTS */

		memcpy(rand_bin, &resync_info->vp_octets[0], WIMAX_EPSAKA_RAND_SIZE);
		memcpy(auts_bin, &resync_info->vp_octets[WIMAX_EPSAKA_RAND_SIZE], WIMAX_EPSAKA_AUTS_SIZE);

		RDEBUG_HEX(request, "RAND  ", rand_bin, WIMAX_EPSAKA_RAND_SIZE);
		RDEBUG_HEX(request, "AUTS  ", auts_bin, WIMAX_EPSAKA_AUTS_SIZE);

		/*
		 *	This procedure uses the secret keys Ki and OPc to authenticate
		 *	the SIM and extract the SQN
		 */
		m_ret = milenage_auts(&sqn_bin, opc->vp_octets, ki->vp_octets, rand_bin, auts_bin);
		
		/*
		 *	If the SIM verification fails then we can't go any further as
		 *	we don't have the keys. And that probably means something bad
		 *	is happening so we bail out now
		 */
		if (m_ret < 0) {
			RDEBUG("SIM verification failed");
		  	return RLM_MODULE_REJECT;
		}

		/*
		 *	If we got this far it means have got a new SQN and RAND
		 *	so we store them in:
		 *	control:WiMAX-SIM-SQN
		 *	control:WiMAX-SIM-RAND
		 *
		 *	From there they can be grabbed by unlang and used later
		 */

		/* SQN is six bytes so we extract what we need from the 64 bit variable */
		uint8_t sqn_bin_arr[WIMAX_EPSAKA_SQN_SIZE] = {
			(sqn_bin & 0x0000FF0000000000ull) >> 40,
			(sqn_bin & 0x000000FF00000000ull) >> 32,
			(sqn_bin & 0x00000000FF000000ull) >> 24,
			(sqn_bin & 0x0000000000FF0000ull) >> 16,
			(sqn_bin & 0x000000000000FF00ull) >>  8,
			(sqn_bin & 0x00000000000000FFull) >>  0
		};

		/* Add SQN to control:WiMAX-SIM-SQN */
		sqn = fr_pair_find_by_num(request->config, PW_WIMAX_SIM_SQN, 0, TAG_ANY);
		if (sqn && (sqn->vp_length < WIMAX_EPSAKA_SQN_SIZE)) {
			RWDEBUG("Found config:WiMAX-SIM-SQN with incorrect length: Ignoring it");
			sqn = NULL;
		}

		if (!sqn) {
			MEM(sqn = pair_make_config("WiMAX-SIM-SQN", NULL, T_OP_SET));
			fr_pair_value_memcpy(sqn, sqn_bin_arr, WIMAX_EPSAKA_SQN_SIZE);
		}
		RDEBUG_HEX(request, "SQN   ", sqn->vp_octets, WIMAX_EPSAKA_SQN_SIZE);

		/* Add RAND to control:WiMAX-SIM-RAND */
		rand = fr_pair_find_by_num(request->config, PW_WIMAX_SIM_RAND, 0, TAG_ANY);
		if (rand && (rand->vp_length < WIMAX_EPSAKA_RAND_SIZE)) {
			RWDEBUG("Found config:WiMAX-SIM-RAND with incorrect length: Ignoring it");
			rand = NULL;
		}

		if (!rand) {
			MEM(rand = pair_make_config("WiMAX-SIM-RAND", NULL, T_OP_SET));
			fr_pair_value_memcpy(rand, rand_bin, WIMAX_EPSAKA_RAND_SIZE);
		}
		RDEBUG_HEX(request, "RAND  ", rand->vp_octets, WIMAX_EPSAKA_RAND_SIZE);

		return RLM_MODULE_UPDATED;
	}

	return RLM_MODULE_NOOP;
}

/*
 *	Massage the request before recording it or proxying it
 */
static rlm_rcode_t CC_HINT(nonnull) mod_preacct(void *instance, REQUEST *request)
{
	return mod_authorize(instance, request);
}


/*
 *	This function generates the keys for old style WiMAX (v1 to v2.0)
 */
static int mip_keys_generate(void *instance, REQUEST *request, VALUE_PAIR *msk, VALUE_PAIR *emsk)
{
	rlm_wimax_t *inst = instance;
	VALUE_PAIR *vp;
	VALUE_PAIR *mn_nai, *ip, *fa_rk;
	HMAC_CTX *hmac;
	unsigned int rk1_len, rk2_len, rk_len;
	uint32_t mip_spi;
	uint8_t usage_data[24];
	uint8_t mip_rk_1[EVP_MAX_MD_SIZE], mip_rk_2[EVP_MAX_MD_SIZE];
	uint8_t mip_rk[2 * EVP_MAX_MD_SIZE];

	/*
	 *	If we delete the MS-MPPE-*-Key attributes, then add in
	 *	the WiMAX-MSK so that the client has a key available.
	 */
	if (inst->delete_mppe_keys) {
		fr_pair_delete_by_num(&request->reply->vps, 16, VENDORPEC_MICROSOFT, TAG_ANY);
		fr_pair_delete_by_num(&request->reply->vps, 17, VENDORPEC_MICROSOFT, TAG_ANY);

		MEM(vp = pair_make_reply("WiMAX-MSK", NULL, T_OP_EQ));
		fr_pair_value_memcpy(vp, msk->vp_octets, msk->vp_length);
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
	rk1_len = SHA256_DIGEST_LENGTH;

	HMAC_Update(hmac, &usage_data[0], sizeof(usage_data));
	HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

	/*
	 *	MIP-RK-2 = HMAC-SSHA256(EMSK, MIP-RK-1 | usage-data | 0x01)
	 */
	HMAC_Init_ex(hmac, emsk->vp_octets, emsk->vp_length, EVP_sha256(), NULL);

	HMAC_Update(hmac, (uint8_t const *) &mip_rk_1, rk1_len);
	HMAC_Update(hmac, &usage_data[0], sizeof(usage_data));
	rk2_len = SHA256_DIGEST_LENGTH;
	HMAC_Final(hmac, &mip_rk_2[0], &rk2_len);

	memcpy(mip_rk, mip_rk_1, rk1_len);
	memcpy(mip_rk + rk1_len, mip_rk_2, rk2_len);
	rk_len = rk1_len + rk2_len;

	/*
	 *	MIP-SPI = HMAC-SSHA256(MIP-RK, "SPI CMIP PMIP");
	 */
	HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha256(), NULL);

	HMAC_Update(hmac, (uint8_t const *) "SPI CMIP PMIP", 12);
	rk1_len = SHA256_DIGEST_LENGTH;
	HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

	/*
	 *	Take the 4 most significant octets.
	 *	If less than 256, add 256.
	 */
	mip_spi = ((mip_rk_1[0] << 24) | (mip_rk_1[1] << 16) |
		   (mip_rk_1[2] << 8) | mip_rk_1[3]);
	if (mip_spi < 256) mip_spi += 256;

	RDEBUG_HEX(request, "MIP-RK ", mip_rk, rk_len);
	RDEBUG("MIP-SPI = %08x", ntohl(mip_spi));

	/*
	 *	FIXME: Perform SPI collision prevention
	 */

	/*
	 *	Calculate mobility keys
	 */
	mn_nai = fr_pair_find_by_num(request->packet->vps, PW_WIMAX_MN_NAI, 0, TAG_ANY);
	if (!mn_nai) mn_nai = fr_pair_find_by_num(request->reply->vps, PW_WIMAX_MN_NAI, 0, TAG_ANY);
	if (!mn_nai) {
		RWDEBUG("WiMAX-MN-NAI was not found in the request or in the reply");
		RWDEBUG("We cannot calculate MN-HA keys");
	}

	/*
	 *	WiMAX-IP-Technology
	 */
	vp = NULL;
	if (mn_nai) vp = fr_pair_find_by_num(request->reply->vps, 23, VENDORPEC_WIMAX, TAG_ANY);
	if (!vp) {
		RWDEBUG("WiMAX-IP-Technology not found in reply");
		RWDEBUG("Not calculating MN-HA keys");
	}

	if (vp) switch (vp->vp_integer) {
	case 2:			/* PMIP4 */
		/*
		 *	Look for WiMAX-hHA-IP-MIP4
		 */
		ip = fr_pair_find_by_num(request->reply->vps, 6, VENDORPEC_WIMAX, TAG_ANY);
		if (!ip) {
			RWDEBUG("WiMAX-hHA-IP-MIP4 not found.  Cannot calculate MN-HA-PMIP4 key");
			break;
		}

		/*
		 *	MN-HA-PMIP4 =
		 *	   H(MIP-RK, "PMIP4 MN HA" | HA-IPv4 | MN-NAI);
		 */
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "PMIP4 MN HA", 11);
		HMAC_Update(hmac, (uint8_t const *) &ip->vp_ipaddr, 4);
		HMAC_Update(hmac, (uint8_t const *) &mn_nai->vp_strvalue, mn_nai->vp_length);
		rk1_len = SHA1_DIGEST_LENGTH;
		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-PMIP4 into WiMAX-MN-hHA-MIP4-Key
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 10, VENDORPEC_WIMAX, TAG_ANY);
		if (!vp) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       10, VENDORPEC_WIMAX);
		}
		if (!vp) {
			RWDEBUG("Failed creating WiMAX-MN-hHA-MIP4-Key");
			break;
		}
		fr_pair_value_memcpy(vp, &mip_rk_1[0], rk1_len);

		/*
		 *	Put MN-HA-PMIP4-SPI into WiMAX-MN-hHA-MIP4-SPI
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 11, VENDORPEC_WIMAX, TAG_ANY);
		if (!vp) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       11, VENDORPEC_WIMAX);
		}
		if (!vp) {
			RWDEBUG("Failed creating WiMAX-MN-hHA-MIP4-SPI");
			break;
		}
		vp->vp_integer = mip_spi + 1;
		break;

	case 3:			/* CMIP4 */
		/*
		 *	Look for WiMAX-hHA-IP-MIP4
		 */
		ip = fr_pair_find_by_num(request->reply->vps, 6, VENDORPEC_WIMAX, TAG_ANY);
		if (!ip) {
			RWDEBUG("WiMAX-hHA-IP-MIP4 not found.  Cannot calculate MN-HA-CMIP4 key");
			break;
		}

		/*
		 *	MN-HA-CMIP4 =
		 *	   H(MIP-RK, "CMIP4 MN HA" | HA-IPv4 | MN-NAI);
		 */
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "CMIP4 MN HA", 11);
		HMAC_Update(hmac, (uint8_t const *) &ip->vp_ipaddr, 4);
		HMAC_Update(hmac, (uint8_t const *) &mn_nai->vp_strvalue, mn_nai->vp_length);
		rk1_len = SHA1_DIGEST_LENGTH;
		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-CMIP4 into WiMAX-MN-hHA-MIP4-Key
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 10, VENDORPEC_WIMAX, TAG_ANY);
		if (!vp) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       10, VENDORPEC_WIMAX);
		}
		if (!vp) {
			RWDEBUG("Failed creating WiMAX-MN-hHA-MIP4-Key");
			break;
		}
		fr_pair_value_memcpy(vp, &mip_rk_1[0], rk1_len);

		/*
		 *	Put MN-HA-CMIP4-SPI into WiMAX-MN-hHA-MIP4-SPI
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 11, VENDORPEC_WIMAX, TAG_ANY);
		if (!vp) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       11, VENDORPEC_WIMAX);
		}
		if (!vp) {
			RWDEBUG("Failed creating WiMAX-MN-hHA-MIP4-SPI");
			break;
		}
		vp->vp_integer = mip_spi;
		break;

	case 4:			/* CMIP6 */
		/*
		 *	Look for WiMAX-hHA-IP-MIP6
		 */
		ip = fr_pair_find_by_num(request->reply->vps, 7, VENDORPEC_WIMAX, TAG_ANY);
		if (!ip) {
			RWDEBUG("WiMAX-hHA-IP-MIP6 not found.  Cannot calculate MN-HA-CMIP6 key");
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
		rk1_len = SHA1_DIGEST_LENGTH;
		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-CMIP6 into WiMAX-MN-hHA-MIP6-Key
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 12, VENDORPEC_WIMAX, TAG_ANY);
		if (!vp) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       12, VENDORPEC_WIMAX);
		}
		if (!vp) {
			RWDEBUG("Failed creating WiMAX-MN-hHA-MIP6-Key");
			break;
		}
		fr_pair_value_memcpy(vp, &mip_rk_1[0], rk1_len);

		/*
		 *	Put MN-HA-CMIP6-SPI into WiMAX-MN-hHA-MIP6-SPI
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 13, VENDORPEC_WIMAX, TAG_ANY);
		if (!vp) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       13, VENDORPEC_WIMAX);
		}
		if (!vp) {
			RWDEBUG("Failed creating WiMAX-MN-hHA-MIP6-SPI");
			break;
		}
		vp->vp_integer = mip_spi + 2;
		break;

	default:
		break;		/* do nothing */
	}

	/*
	 *	Generate FA-RK, if requested.
	 *
	 *	FA-RK= H(MIP-RK, "FA-RK")
	 */
	fa_rk = fr_pair_find_by_num(request->reply->vps, 14, VENDORPEC_WIMAX, TAG_ANY);
	if (fa_rk && (fa_rk->vp_length <= 1)) {
		HMAC_Init_ex(hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(hmac, (uint8_t const *) "FA-RK", 5);

		rk1_len = SHA1_DIGEST_LENGTH;
		HMAC_Final(hmac, &mip_rk_1[0], &rk1_len);

		fr_pair_value_memcpy(fa_rk, &mip_rk_1[0], rk1_len);
	}

	/*
	 *	Create FA-RK-SPI, which is really SPI-CMIP4, which is
	 *	really MIP-SPI.  Clear?  Of course.  This is WiMAX.
	 */
	if (fa_rk) {
		vp = fr_pair_find_by_num(request->reply->vps, 61, VENDORPEC_WIMAX, TAG_ANY);
		if (!vp) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       61, VENDORPEC_WIMAX);
		}
		if (!vp) {
			RWDEBUG("Failed creating WiMAX-FA-RK-SPI");
		} else {
			vp->vp_integer = mip_spi;
		}
	}

	/*
	 *	Give additional information about requests && responses
	 *
	 *	WiMAX-RRQ-MN-HA-SPI
	 */
	vp = fr_pair_find_by_num(request->packet->vps, 20, VENDORPEC_WIMAX, TAG_ANY);
	if (vp) {
		RDEBUG("Client requested MN-HA key: Should use SPI to look up key from storage");
		if (!mn_nai) {
			RWDEBUG("MN-NAI was not found!");
		}

		/*
		 *	WiMAX-RRQ-HA-IP
		 */
		if (!fr_pair_find_by_num(request->packet->vps, 18, VENDORPEC_WIMAX, TAG_ANY)) {
			RWDEBUG("HA-IP was not found!");
		}


		/*
		 *	WiMAX-HA-RK-Key-Requested
		 */
		vp = fr_pair_find_by_num(request->packet->vps, 58, VENDORPEC_WIMAX, TAG_ANY);
		if (vp && (vp->vp_integer == 1)) {
			RDEBUG("Client requested HA-RK: Should use IP to look it up from storage");
		}
	}

	/*
	 *	Wipe the context of all sensitive information.
	 */
	HMAC_CTX_free(hmac);

	return RLM_MODULE_UPDATED;
}

/*
 *	Generate the EPS-AKA authentication vector
 *
 *	These are the keys needed for new style WiMAX (LTE / 3gpp authentication),
 	for WiMAX v2.1
 */
static rlm_rcode_t aka_keys_generate(REQUEST *request, rlm_wimax_t const *inst, VALUE_PAIR *ki, VALUE_PAIR *opc,
				     VALUE_PAIR *amf, VALUE_PAIR *sqn, VALUE_PAIR *plmn)
{  
	size_t i;
	VALUE_PAIR *rand_previous, *rand, *xres, *autn, *kasme;

	/*
	 *	For most authentication requests we need to generate a fresh RAND
	 *
	 *	The exception is after SQN re-syncronisation - in this case we
	 *	get RAND in the request, and this module if called in authorize should
	 *	have put it in control:WiMAX-SIM-RAND so we can grab it from there)
	 */
	rand_previous = fr_pair_find_by_num(request->config, PW_WIMAX_SIM_RAND, 0, TAG_ANY);
	if (rand_previous && (rand_previous->vp_length < WIMAX_EPSAKA_RAND_SIZE)) {
		RWDEBUG("Found config:WiMAX-SIM-Rand with incorrect size.  Ignoring it.");
		rand_previous = NULL;
	}

	MEM(rand = pair_make_reply("WiMAX-E-UTRAN-Vector-RAND", NULL, T_OP_SET));
	if (!rand_previous) {
		uint32_t lvalue;
		uint8_t buffer[WIMAX_EPSAKA_RAND_SIZE];

		for (i = 0; i < (WIMAX_EPSAKA_RAND_SIZE / 4); i++) {
			lvalue = fr_rand();
			memcpy(buffer + i * 4, &lvalue, sizeof(lvalue));
		}

		fr_pair_value_memcpy(rand, buffer, WIMAX_EPSAKA_RAND_SIZE);

	} else {
		fr_pair_value_memcpy(rand, rand_previous->vp_octets, WIMAX_EPSAKA_RAND_SIZE);
	}

   	/*
	 *	Feed AMF, Ki, SQN and RAND into the Milenage algorithm (f1, f2, f3, f4, f5)
	 *	which returns AUTN, AK, CK, IK, XRES.
	 */
	uint8_t xres_bin[WIMAX_EPSAKA_XRES_SIZE];
	uint8_t ck_bin[WIMAX_EPSAKA_CK_SIZE];
	uint8_t ik_bin[WIMAX_EPSAKA_IK_SIZE];
	uint8_t ak_bin[WIMAX_EPSAKA_AK_SIZE];
	uint8_t autn_bin[WIMAX_EPSAKA_AUTN_SIZE];

	/* But first convert uint8 SQN to uint64 */
	uint64_t sqn_bin = 0x0000000000000000;
	for (i = 0; i < sqn->vp_length; ++i) sqn_bin = (sqn_bin << 8) | sqn->vp_octets[i];

	if (!opc || (opc->vp_length < MILENAGE_OPC_SIZE)) {
		RWDEBUG("Found config:WiMAX-SIM-OPC with incorrect size.  Ignoring it");
		return RLM_MODULE_NOOP;
	}
	if (!amf || (amf->vp_length < MILENAGE_AMF_SIZE)) {
		RWDEBUG("Found config:WiMAX-SIM-AMF with incorrect size.  Ignoring it");
		return RLM_MODULE_NOOP;
	}
	if (!ki || (ki->vp_length < MILENAGE_KI_SIZE)) {
		RWDEBUG("Found config:WiMAX-SIM-KI with incorrect size.  Ignoring it");
		return RLM_MODULE_NOOP;
	}

	/* Call milenage */
	milenage_umts_generate(autn_bin, ik_bin, ck_bin, ak_bin, xres_bin, opc->vp_octets,
			       amf->vp_octets, ki->vp_octets, sqn_bin, rand->vp_octets);

	/*
	 *	Now we genertate KASME
	 *
	 *	Officially described in 33401-g30.doc section A.2
	 *	But an easier to read explanation can be found at:
	 *	https://medium.com/uw-ictd/lte-authentication-2d0810a061ec
	 *
	*/

	/* k = CK || IK */
	uint8_t kk_bin[WIMAX_EPSAKA_KK_SIZE];
	memcpy(kk_bin, ck_bin, sizeof(ck_bin));
	memcpy(kk_bin + sizeof(ck_bin), ik_bin, sizeof(ik_bin));

	/* Initialize a 14 byte buffer s */
	uint8_t ks_bin[WIMAX_EPSAKA_KS_SIZE];

	/* Assign the first byte of s as 0x10 */
	ks_bin[0] = 0x10;
      
	/* Copy the 3 bytes of PLMN into s */
	memcpy(ks_bin + 1, plmn->vp_octets, 3);

	/* Assign 5th and 6th byte as 0x00 and 0x03 */
	ks_bin[4] = 0x00;
	ks_bin[5] = 0x03;
      
	/* Assign the next 6 bytes as SQN XOR AK */
	for (i = 0; i < 6; i++) {
		ks_bin[i+6] = sqn->vp_octets[i] ^ ak_bin[i];
	}
      
	/* Assign the last two bytes as 0x00 and 0x06 */
	ks_bin[12] = 0x00;
	ks_bin[13] = 0x06;

	/* Perform an HMAC-SHA256 using Key k from step 1 and s as the message. */
	uint8_t kasme_bin[WIMAX_EPSAKA_KASME_SIZE];
	HMAC_CTX *hmac;
	unsigned int kasme_len = sizeof(kasme_bin);

	hmac = HMAC_CTX_new();
	HMAC_Init_ex(hmac, kk_bin, sizeof(kk_bin), EVP_sha256(), NULL);
	HMAC_Update(hmac, ks_bin, sizeof(ks_bin));
	kasme_len = SHA256_DIGEST_LENGTH;
	HMAC_Final(hmac, &kasme_bin[0], &kasme_len);
	HMAC_CTX_free(hmac);

	/*
	 *	Add reply attributes XRES, AUTN and KASME (RAND we added earlier)
	 *
	 *	Note that we can't call fr_pair_find_by_num(), as
	 *	these attributes are buried deep inside of the WiMAX
	 *	hierarchy.
	 */
	xres = fr_pair_find_by_da(request->reply->vps, inst->xres, TAG_ANY);
	if (!xres) {
		MEM(xres = pair_make_reply("WiMAX-E-UTRAN-Vector-XRES", NULL, T_OP_SET));
		fr_pair_value_memcpy(xres, xres_bin, WIMAX_EPSAKA_XRES_SIZE);
	}

	autn = fr_pair_find_by_da(request->reply->vps, inst->autn, TAG_ANY);
	if (!autn) {
		MEM(autn = pair_make_reply("WiMAX-E-UTRAN-Vector-AUTN", NULL, T_OP_SET));
		fr_pair_value_memcpy(autn, autn_bin, WIMAX_EPSAKA_AUTN_SIZE);
	}

	kasme = fr_pair_find_by_da(request->reply->vps, inst->kasme, TAG_ANY);
	if (!kasme) {
		MEM(kasme = pair_make_reply("WiMAX-E-UTRAN-Vector-KASME", NULL, T_OP_SET));
		fr_pair_value_memcpy(kasme, kasme_bin, WIMAX_EPSAKA_KASME_SIZE);
	}

	/* Print keys to log for debugging */
	if (rad_debug_lvl) {
		RDEBUG("-------- Milenage in --------");
		RDEBUG_HEX(request, "OPc   ", opc->vp_octets, opc->vp_length);
		RDEBUG_HEX(request, "Ki    ", ki->vp_octets, ki->vp_length);
		RDEBUG_HEX(request, "RAND  ", rand->vp_octets, rand->vp_length);
		RDEBUG_HEX(request, "SQN   ", sqn->vp_octets, sqn->vp_length);
		RDEBUG_HEX(request, "AMF   ", amf->vp_octets, amf->vp_length);
		RDEBUG("-------- Milenage out -------");
		RDEBUG_HEX(request, "XRES  ", xres->vp_octets, xres->vp_length);
		RDEBUG_HEX(request, "Ck    ", ck_bin, sizeof(ck_bin));
		RDEBUG_HEX(request, "Ik    ", ik_bin, sizeof(ik_bin));
		RDEBUG_HEX(request, "Ak    ", ak_bin, sizeof(ak_bin));
		RDEBUG_HEX(request, "AUTN  ", autn->vp_octets, autn->vp_length);
		RDEBUG("-----------------------------");
		RDEBUG_HEX(request, "Kk    ", kk_bin, sizeof(kk_bin));
		RDEBUG_HEX(request, "Ks    ", ks_bin, sizeof(ks_bin));
		RDEBUG_HEX(request, "KASME ", kasme->vp_octets, kasme->vp_length);
	}

	return RLM_MODULE_UPDATED;
}

/*
 *	Generate the keys after the user has been authenticated.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	VALUE_PAIR *msk, *emsk, *ki, *opc, *amf, *sqn, *plmn;

	/*
	 *	If we have MSK and EMSK then assume we want MIP keys
	 *	Else if we have the SIM keys then we want the EPS-AKA vector
	 */

	msk = fr_pair_find_by_num(request->reply->vps, PW_EAP_MSK, 0, TAG_ANY);
	emsk = fr_pair_find_by_num(request->reply->vps, PW_EAP_EMSK, 0, TAG_ANY);

	if (msk && emsk) {
		RDEBUG("MSK and EMSK found.  Generating MIP keys");
		return mip_keys_generate(instance, request, msk, emsk);
	}

	ki = fr_pair_find_by_num(request->config, PW_WIMAX_SIM_KI, 0, TAG_ANY);
	opc = fr_pair_find_by_num(request->config, PW_WIMAX_SIM_OPC, 0, TAG_ANY);
	amf = fr_pair_find_by_num(request->config, PW_WIMAX_SIM_AMF, 0, TAG_ANY);
	sqn = fr_pair_find_by_num(request->config, PW_WIMAX_SIM_SQN, 0, TAG_ANY);
	plmn = fr_pair_find_by_num(request->packet->vps, 146, VENDORPEC_WIMAX, TAG_ANY);
	
	if (ki && opc && amf && sqn && plmn) {
		RDEBUG("AKA attributes found.  Generating AKA keys.");
		return aka_keys_generate(request, instance, ki, opc, amf, sqn, plmn);
	}

	RDEBUG("Input keys not found.  Cannot create WiMAX keys");
	return RLM_MODULE_NOOP;
}


static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	rlm_wimax_t *inst = instance;
      
	inst->resync_info = dict_attrbyname("WiMAX-Re-synchronization-Info");
	inst->xres = dict_attrbyname("WiMAX-E-UTRAN-Vector-XRES");
	inst->autn = dict_attrbyname("WiMAX-E-UTRAN-Vector-AUTN");
	inst->kasme = dict_attrbyname("WiMAX-E-UTRAN-Vector-KASME");

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
extern module_t rlm_wimax;
module_t rlm_wimax = {
	.magic		= RLM_MODULE_INIT,
	.name		= "wimax",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_wimax_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
