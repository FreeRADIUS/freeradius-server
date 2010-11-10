/*
 * rlm_wimax.c
 *
 * Version:	$Id$
 *
 * Copyright (C) 2008 Alan DeKok <aland@networkradius.com>
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/*
 *	FIXME: Add check for this header to configure.in
 */
#include <openssl/hmac.h>

/*
 *	FIXME: Fix the build system to create definitions from names.
 */
#define WIMAX2ATTR(x) ((24757 << 16) | (x))

typedef struct rlm_wimax_t {
	int	delete_mppe_keys;
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
  { "delete_mppe_keys", PW_TYPE_BOOLEAN,
    offsetof(rlm_wimax_t,delete_mppe_keys), NULL,   "no" },

  { NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int wimax_detach(void *instance)
{
	free(instance);
	return 0;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int wimax_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_wimax_t *inst;

	/*
	 *	Set up a storage area for instance data
	 */
	inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		wimax_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int wimax_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR *vp;

	/* quiet the compiler */
	instance = instance;
	request = request;

	/*
	 *	Fix Calling-Station-Id.  Damn you, WiMAX!
	 */
	vp =  pairfind(request->packet->vps, PW_CALLING_STATION_ID);
	if (vp && (vp->length == 6)) {
		int i;
		uint8_t buffer[6];

		memcpy(buffer, vp->vp_octets, 6);

		/*
		 *	RFC 3580 Section 3.20 says this is the preferred
		 *	format.  Everyone *SANE* is using this format,
		 *	so we fix it here.
		 */
		for (i = 0; i < 6; i++) {
			fr_bin2hex(&buffer[i], &vp->vp_strvalue[i * 3], 1);
			vp->vp_strvalue[(i * 3) + 2] = '-';
		}

		vp->vp_strvalue[(5*3)+2] = '\0';
		vp->length = (5*3)+2;

		DEBUG2("rlm_wimax: Fixing WiMAX binary Calling-Station-Id to %s",
		       vp->vp_strvalue);
	}

	return RLM_MODULE_OK;
}


/*
 *	Massage the request before recording it or proxying it
 */
static int wimax_preacct(void *instance, REQUEST *request)
{
	return wimax_authorize(instance, request);
}

/*
 *	Write accounting information to this modules database.
 */
static int wimax_accounting(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;
	request = request;

	return RLM_MODULE_OK;
}

/*
 *	Generate the keys after the user has been authenticated.
 */
static int wimax_postauth(void *instance, REQUEST *request)
{
	rlm_wimax_t *inst = instance;
	VALUE_PAIR *msk, *emsk, *vp;
	VALUE_PAIR *mn_nai, *ip, *fa_rk;
	HMAC_CTX hmac;
	unsigned int rk1_len, rk2_len, rk_len;
	int rk_lifetime = 3600;	/* ? */
	uint32_t mip_spi;
	uint8_t usage_data[24];
	uint8_t mip_rk_1[EVP_MAX_MD_SIZE], mip_rk_2[EVP_MAX_MD_SIZE];
	uint8_t mip_rk[2 * EVP_MAX_MD_SIZE];

	msk = pairfind(request->reply->vps, 1129);
	emsk = pairfind(request->reply->vps, 1130);
	if (!msk || !emsk) {
		RDEBUG("No EAP-MSK or EAP-EMSK.  Cannot create WiMAX keys.");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	If we delete the MS-MPPE-*-Key attributes, then add in
	 *	the WiMAX-MSK so that the client has a key available.
	 */
	if (inst->delete_mppe_keys) {
		pairdelete(&request->reply->vps, ((311 << 16) | 16));
		pairdelete(&request->reply->vps, ((311 << 16) | 17));

		vp = radius_pairmake(request, &request->reply->vps, "WiMAX-MSK", "0x00", T_OP_EQ);
		if (vp) {
			memcpy(vp->vp_octets, msk->vp_octets, msk->length);
			vp->length = msk->length;
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
	HMAC_CTX_init(&hmac);
	HMAC_Init_ex(&hmac, emsk->vp_octets, emsk->length, EVP_sha256(), NULL);
	
	HMAC_Update(&hmac, &usage_data[0], sizeof(usage_data));
	HMAC_Final(&hmac, &mip_rk_1[0], &rk1_len);

	/*
	 *	MIP-RK-2 = HMAC-SSHA256(EMSK, MIP-RK-1 | usage-data | 0x01)
	 */
	HMAC_Init_ex(&hmac, emsk->vp_octets, emsk->length, EVP_sha256(), NULL);
	
	HMAC_Update(&hmac, (const uint8_t *) &mip_rk_1, rk1_len);
	HMAC_Update(&hmac, &usage_data[0], sizeof(usage_data));
	HMAC_Final(&hmac, &mip_rk_2[0], &rk2_len);

	vp = pairfind(request->reply->vps, PW_SESSION_TIMEOUT);
	if (vp) rk_lifetime = vp->vp_integer;

	memcpy(mip_rk, mip_rk_1, rk1_len);
	memcpy(mip_rk + rk1_len, mip_rk_2, rk2_len);
	rk_len = rk1_len + rk2_len;

	/*
	 *	MIP-SPI = HMAC-SSHA256(MIP-RK, "SPI CMIP PMIP");
	 */
	HMAC_Init_ex(&hmac, mip_rk, rk_len, EVP_sha256(), NULL);
	
	HMAC_Update(&hmac, (const uint8_t *) "SPI CMIP PMIP", 12);
	HMAC_Final(&hmac, &mip_rk_1[0], &rk1_len);

	/*
	 *	Take the 4 most significant octets.
	 *	If less than 256, add 256.
	 */
	mip_spi = ((mip_rk_1[0] << 24) | (mip_rk_1[1] << 16) |
		   (mip_rk_1[2] << 8) | mip_rk_1[3]);
	if (mip_spi < 256) mip_spi += 256;

	if (debug_flag) {
		int len = rk_len;
		char buffer[512];

		if (len > 128) len = 128; /* buffer size */

		fr_bin2hex(mip_rk, buffer, len);
		radlog_request(L_DBG, 0, request, "MIP-RK = 0x%s", buffer);
		radlog_request(L_DBG, 0, request, "MIP-SPI = %08x",
			       ntohl(mip_spi));
	}

	/*
	 *	FIXME: Perform SPI collision prevention
	 */

	/*
	 *	Calculate mobility keys
	 */
	mn_nai = pairfind(request->packet->vps, 1900);
	if (!mn_nai) mn_nai = pairfind(request->reply->vps, 1900);
	if (!mn_nai) {
		RDEBUG("WARNING: WiMAX-MN-NAI was not found in the request or in the reply.");
		RDEBUG("WARNING: We cannot calculate MN-HA keys.");
	}

	/*
	 *	WiMAX-IP-Technology
	 */
	vp = NULL;
	if (mn_nai) vp = pairfind(request->reply->vps, WIMAX2ATTR(23));
	if (!vp) {
		RDEBUG("WARNING: WiMAX-IP-Technology not found in reply.");
		RDEBUG("WARNING: Not calculating MN-HA keys");
	}

	if (vp) switch (vp->vp_integer) {
	case 2:			/* PMIP4 */
		/*
		 *	Look for WiMAX-hHA-IP-MIP4
		 */
		ip = pairfind(request->reply->vps, WIMAX2ATTR(6));
		if (!ip) {
			RDEBUG("WARNING: WiMAX-hHA-IP-MIP4 not found.  Cannot calculate MN-HA-PMIP4 key");
			break;
		}

		/*
		 *	MN-HA-PMIP4 =
		 *	   H(MIP-RK, "PMIP4 MN HA" | HA-IPv4 | MN-NAI);
		 */
		HMAC_Init_ex(&hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(&hmac, (const uint8_t *) "PMIP4 MN HA", 11);
		HMAC_Update(&hmac, (const uint8_t *) &ip->vp_ipaddr, 4);
		HMAC_Update(&hmac, (const uint8_t *) &mn_nai->vp_strvalue, mn_nai->length);
		HMAC_Final(&hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-PMIP4 into WiMAX-MN-hHA-MIP4-Key
		 */
		vp = pairfind(request->reply->vps, WIMAX2ATTR(10));
		if (!vp) {
			vp = radius_paircreate(request, &request->reply->vps,
					       WIMAX2ATTR(10), PW_TYPE_OCTETS);
		}
		if (!vp) {
			RDEBUG("WARNING: Failed creating WiMAX-MN-hHA-MIP4-Key");
			break;
		}
		memcpy(vp->vp_octets, &mip_rk_1[0], rk1_len);
		vp->length = rk1_len;

		/*
		 *	Put MN-HA-PMIP4-SPI into WiMAX-MN-hHA-MIP4-SPI
		 */
		vp = pairfind(request->reply->vps, WIMAX2ATTR(11));
		if (!vp) {
			vp = radius_paircreate(request, &request->reply->vps,
					       WIMAX2ATTR(11), PW_TYPE_INTEGER);
		}
		if (!vp) {
			RDEBUG("WARNING: Failed creating WiMAX-MN-hHA-MIP4-SPI");
			break;
		}
		vp->vp_integer = mip_spi + 1;
		break;

	case 3:			/* CMIP4 */
		/*
		 *	Look for WiMAX-hHA-IP-MIP4
		 */
		ip = pairfind(request->reply->vps, WIMAX2ATTR(6));
		if (!ip) {
			RDEBUG("WARNING: WiMAX-hHA-IP-MIP4 not found.  Cannot calculate MN-HA-CMIP4 key");
			break;
		}

		/*
		 *	MN-HA-CMIP4 =
		 *	   H(MIP-RK, "CMIP4 MN HA" | HA-IPv4 | MN-NAI);
		 */
		HMAC_Init_ex(&hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(&hmac, (const uint8_t *) "CMIP4 MN HA", 11);
		HMAC_Update(&hmac, (const uint8_t *) &ip->vp_ipaddr, 4);
		HMAC_Update(&hmac, (const uint8_t *) &mn_nai->vp_strvalue, mn_nai->length);
		HMAC_Final(&hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-CMIP4 into WiMAX-MN-hHA-MIP4-Key
		 */
		vp = pairfind(request->reply->vps, WIMAX2ATTR(10));
		if (!vp) {
			vp = radius_paircreate(request, &request->reply->vps,
					       WIMAX2ATTR(10), PW_TYPE_OCTETS);
		}
		if (!vp) {
			RDEBUG("WARNING: Failed creating WiMAX-MN-hHA-MIP4-Key");
			break;
		}
		memcpy(vp->vp_octets, &mip_rk_1[0], rk1_len);
		vp->length = rk1_len;

		/*
		 *	Put MN-HA-CMIP4-SPI into WiMAX-MN-hHA-MIP4-SPI
		 */
		vp = pairfind(request->reply->vps, WIMAX2ATTR(11));
		if (!vp) {
			vp = radius_paircreate(request, &request->reply->vps,
					       WIMAX2ATTR(11), PW_TYPE_INTEGER);
		}
		if (!vp) {
			RDEBUG("WARNING: Failed creating WiMAX-MN-hHA-MIP4-SPI");
			break;
		}
		vp->vp_integer = mip_spi;
		break;

	case 4:			/* CMIP6 */
		/*
		 *	Look for WiMAX-hHA-IP-MIP6
		 */
		ip = pairfind(request->reply->vps, WIMAX2ATTR(7));
		if (!ip) {
			RDEBUG("WARNING: WiMAX-hHA-IP-MIP6 not found.  Cannot calculate MN-HA-CMIP6 key");
			break;
		}

		/*
		 *	MN-HA-CMIP6 =
		 *	   H(MIP-RK, "CMIP6 MN HA" | HA-IPv6 | MN-NAI);
		 */
		HMAC_Init_ex(&hmac, mip_rk, rk_len, EVP_sha1(), NULL);

		HMAC_Update(&hmac, (const uint8_t *) "CMIP6 MN HA", 11);
		HMAC_Update(&hmac, (const uint8_t *) &ip->vp_ipv6addr, 16);
		HMAC_Update(&hmac, (const uint8_t *) &mn_nai->vp_strvalue, mn_nai->length);
		HMAC_Final(&hmac, &mip_rk_1[0], &rk1_len);

		/*
		 *	Put MN-HA-CMIP6 into WiMAX-MN-hHA-MIP6-Key
		 */
		vp = pairfind(request->reply->vps, WIMAX2ATTR(12));
		if (!vp) {
			vp = radius_paircreate(request, &request->reply->vps,
					       WIMAX2ATTR(12), PW_TYPE_OCTETS);
		}
		if (!vp) {
			RDEBUG("WARNING: Failed creating WiMAX-MN-hHA-MIP6-Key");
			break;
		}
		memcpy(vp->vp_octets, &mip_rk_1[0], rk1_len);
		vp->length = rk1_len;

		/*
		 *	Put MN-HA-CMIP6-SPI into WiMAX-MN-hHA-MIP6-SPI
		 */
		vp = pairfind(request->reply->vps, WIMAX2ATTR(13));
		if (!vp) {
			vp = radius_paircreate(request, &request->reply->vps,
					       WIMAX2ATTR(13), PW_TYPE_INTEGER);
		}
		if (!vp) {
			RDEBUG("WARNING: Failed creating WiMAX-MN-hHA-MIP6-SPI");
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
	fa_rk = pairfind(request->reply->vps, WIMAX2ATTR(14));
	if (fa_rk && (fa_rk->length <= 1)) {
		HMAC_Init_ex(&hmac, mip_rk, rk_len, EVP_sha1(), NULL);
		
		HMAC_Update(&hmac, (const uint8_t *) "FA-RK", 5);

		HMAC_Final(&hmac, &mip_rk_1[0], &rk1_len);

		memcpy(fa_rk->vp_octets, &mip_rk_1[0], rk1_len);
		fa_rk->length = rk1_len;
	}

	/*
	 *	Create FA-RK-SPI, which is really SPI-CMIP4, which is
	 *	really MIP-SPI.  Clear?  Of course.  This is WiMAX.
	 */
	if (fa_rk) {
		vp = pairfind(request->reply->vps, WIMAX2ATTR(61));
		if (!vp) {
			vp = radius_paircreate(request, &request->reply->vps,
					       WIMAX2ATTR(61), PW_TYPE_INTEGER);
		}
		if (!vp) {
			RDEBUG("WARNING: Failed creating WiMAX-FA-RK-SPI");
		} else {
			vp->vp_integer = mip_spi;
		}
	}

	/*
	 *	Give additional information about requests && responses
	 *
	 *	WiMAX-RRQ-MN-HA-SPI
	 */
	vp = pairfind(request->packet->vps, WIMAX2ATTR(20));
	if (vp) {
		RDEBUG("Client requested MN-HA key: Should use SPI to look up key from storage.");
		if (!mn_nai) {
			RDEBUG("WARNING: MN-NAI was not found!");
		}

		/*
		 *	WiMAX-RRQ-HA-IP
		 */
		if (!pairfind(request->packet->vps, WIMAX2ATTR(18))) {
			RDEBUG("WARNING: HA-IP was not found!");
		}


		/*
		 *	WiMAX-HA-RK-Key-Requested
		 */
		vp = pairfind(request->packet->vps, WIMAX2ATTR(58));
		if (vp && (vp->vp_integer == 1)) {
			RDEBUG("Client requested HA-RK: Should use IP to look it up from storage.");
		}
	}

	/*
	 *	Wipe the context of all sensitive information.
	 */
	HMAC_CTX_cleanup(&hmac);

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
module_t rlm_wimax = {
	RLM_MODULE_INIT,
	"wimax",
	RLM_TYPE_THREAD_SAFE,		/* type */
	wimax_instantiate,	        /* instantiation */
	wimax_detach,			/* detach */
	{
		NULL,			/* authentication */
		wimax_authorize,	/* authorization */
		wimax_preacct,		/* preaccounting */
		wimax_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		wimax_postauth 		/* post-auth */
	},
};
