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

#ifdef HAVE_OPENSSL_HMAC_H
#include <openssl/hmac.h>
#endif

/*
 *	FIXME: Fix the build system to create definitions from names.
 */
typedef struct rlm_wimax_t {
	bool	delete_mppe_keys;
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
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(UNUSED void *instance, REQUEST *request)
{
	VALUE_PAIR *vp;

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
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(UNUSED void *instance, UNUSED REQUEST *request)
{
	return RLM_MODULE_OK;
}

/*
 *	Generate the keys after the user has been authenticated.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(void *instance, REQUEST *request)
{
	rlm_wimax_t *inst = instance;
	VALUE_PAIR *msk, *emsk, *vp;
	VALUE_PAIR *mn_nai, *ip, *fa_rk;
	HMAC_CTX *hmac;
	unsigned int rk1_len, rk2_len, rk_len;
	uint32_t mip_spi;
	uint8_t usage_data[24];
	uint8_t mip_rk_1[EVP_MAX_MD_SIZE], mip_rk_2[EVP_MAX_MD_SIZE];
	uint8_t mip_rk[2 * EVP_MAX_MD_SIZE];

	msk = fr_pair_find_by_num(request->reply->vps, PW_EAP_MSK, 0, TAG_ANY);
	emsk = fr_pair_find_by_num(request->reply->vps, PW_EAP_EMSK, 0, TAG_ANY);
	if (!msk || !emsk) {
		RDEBUG("No EAP-MSK or EAP-EMSK.  Cannot create WiMAX keys");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	If we delete the MS-MPPE-*-Key attributes, then add in
	 *	the WiMAX-MSK so that the client has a key available.
	 */
	if (inst->delete_mppe_keys) {
		fr_pair_delete_by_num(&request->reply->vps, 16, VENDORPEC_MICROSOFT, TAG_ANY);
		fr_pair_delete_by_num(&request->reply->vps, 17, VENDORPEC_MICROSOFT, TAG_ANY);

		vp = pair_make_reply("WiMAX-MSK", NULL, T_OP_EQ);
		if (vp) {
			fr_pair_value_memcpy(vp, msk->vp_octets, msk->vp_length);
		}
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

	if (rad_debug_lvl) {
		int len = rk_len;
		char buffer[512];

		if (len > 128) len = 128; /* buffer size */

		fr_bin2hex(buffer, mip_rk, len);
		RDEBUG("MIP-RK = 0x%s", buffer);
		RDEBUG("MIP-SPI = %08x", ntohl(mip_spi));
	}

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
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_POST_AUTH]		= mod_post_auth
	},
};
