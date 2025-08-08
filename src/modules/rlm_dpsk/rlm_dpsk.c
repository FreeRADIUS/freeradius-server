/*
 * Copyright (C) 2023 Network RADIUS SARL (legal@networkradius.com)
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

typedef struct {
	uint8_t			mac[6];
	uint8_t			pmk[32];

	uint8_t			*ssid;
	size_t			ssid_len;

	char			*identity;
	size_t			identity_len;

	char			*psk;
	size_t			psk_len;
	time_t			expires;

	fr_dlist_t		dlist;
	rlm_dpsk_t		*inst;
} rlm_dpsk_cache_t;

struct rlm_dpsk_s {
	char const		*xlat_name;
	bool			ruckus;
	bool			dynamic;

	rbtree_t		*cache;

	uint32_t		cache_size;
	uint32_t		cache_lifetime;

	char const		*filename;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		mutex;
#endif
	fr_dlist_t		head;

	DICT_ATTR const		*ssid;
	DICT_ATTR const		*anonce;
	DICT_ATTR const		*frame;
};

static const CONF_PARSER module_config[] = {
	{ "ruckus", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_dpsk_t, ruckus), "no" },

	{ "cache_size", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_dpsk_t, cache_size), "0" },
	{ "cache_lifetime", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_dpsk_t, cache_lifetime), "0" },

	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT,  rlm_dpsk_t, filename), NULL },

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

	if (!fr_pair_find_by_da(request->packet->vps, inst->anonce, TAG_ANY) &&
	    !fr_pair_find_by_da(request->packet->vps, inst->frame, TAG_ANY)) {
		return RLM_MODULE_NOOP;
	}

	if (fr_pair_find_by_num(request->config, PW_AUTH_TYPE, 0, TAG_ANY)) {
		RWDEBUG2("Auth-Type already set.  Not setting to %s", inst->xlat_name);
		return RLM_MODULE_NOOP;
	}

	RDEBUG2("Found %s.  Setting 'Auth-Type  = %s'", inst->frame->name, inst->xlat_name);

	/*
	 *	Set Auth-Type to MS-CHAP.  The authentication code
	 *	will take care of turning cleartext passwords into
	 *	NT/LM passwords.
	 */
	if (!pair_make_config("Auth-Type", inst->xlat_name, T_OP_EQ)) {
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

static rlm_dpsk_cache_t *dpsk_cache_find(REQUEST *request, rlm_dpsk_t const *inst, uint8_t *buffer, size_t buflen, VALUE_PAIR *ssid, uint8_t const *mac)
{
	rlm_dpsk_cache_t *entry, my_entry;

	memcpy(my_entry.mac, mac, sizeof(my_entry.mac));
	memcpy(&my_entry.ssid, &ssid->vp_octets, sizeof(my_entry.ssid)); /* const issues */
	my_entry.ssid_len = ssid->vp_length;

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


static int generate_pmk(REQUEST *request, uint8_t *buffer, size_t buflen, VALUE_PAIR *ssid, char const *psk, size_t psk_len)
{
	fr_assert(buflen == 32);

	if (PKCS5_PBKDF2_HMAC_SHA1((const char *) psk, psk_len, (const unsigned char *) ssid->vp_strvalue, ssid->vp_length, 4096, buflen, buffer) == 0) {
		RDEBUG("Failed calling OpenSSL to calculate the PMK");
		return -1;
	}

	return 0;
}

/*
 *	Verify the DPSK information.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	rlm_dpsk_t *inst = instance;
	VALUE_PAIR *anonce, *key_msg, *vp, *vp_psk = NULL, *vp_id = NULL, *vp_ssid = NULL;
	rlm_dpsk_cache_t *entry = NULL;
	int lineno = 0;
	int stage = 0;
	rlm_rcode_t rcode = RLM_MODULE_OK;
	size_t len, psk_len = 0;
	unsigned int digest_len, mic_len;
	eapol_attr_t const *eapol;
	eapol_attr_t *zeroed;
	FILE *fp = NULL;
	char const *filename = inst->filename;
	char const *psk_identity = NULL, *psk = NULL;
	uint8_t *p;
	uint8_t const *snonce, *ap_mac;
	uint8_t const *min_mac, *max_mac;
	uint8_t const *min_nonce, *max_nonce;
	uint8_t pmk[32];
	uint8_t s_mac[6], message[sizeof("Pairwise key expansion") + 6 + 6 + 32 + 32 + 1], frame[128];
	uint8_t digest[EVP_MAX_MD_SIZE], mic[EVP_MAX_MD_SIZE];
	char token_identity[256];
	char token_psk[256];
	char filename_buffer[1024];

	/*
	 *	Search for the information in a bunch of attributes.
	 */
	anonce = fr_pair_find_by_da(request->packet->vps, inst->anonce, TAG_ANY);
	if (!anonce) {
		RDEBUG("No FreeRADIUS-802.1X-Anonce in the request");
		return RLM_MODULE_NOOP;
	}

	if (anonce->vp_length != 32) {
		RDEBUG("%s has incorrect length (%zu, not 32)", inst->anonce->name, anonce->vp_length);
		return RLM_MODULE_NOOP;
	}

	key_msg = fr_pair_find_by_da(request->packet->vps, inst->frame, TAG_ANY);
	if (!key_msg) {
		RDEBUG("No %s in the request", inst->frame->name);
		return RLM_MODULE_NOOP;
	}

	if (key_msg->vp_length < sizeof(*eapol)) {
		RDEBUG("%s has incorrect length (%zu < %zu)", inst->frame->name, key_msg->vp_length, sizeof(*eapol));
		return RLM_MODULE_NOOP;
	}

	if (key_msg->vp_length > sizeof(frame)) {
		RDEBUG("%s has incorrect length (%zu > %zu)", inst->frame->name, key_msg->vp_length, sizeof(frame));
		return RLM_MODULE_NOOP;
	}

	vp_ssid = fr_pair_find_by_da(request->packet->vps, inst->ssid, TAG_ANY);
	if (!vp_ssid) {
		RDEBUG("No %s in the request", inst->ssid->name);
		return RLM_MODULE_NOOP;
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

	/*
	 *	Get supplicant MAC address from the User-Name
	 */
	vp = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
	if (!vp) {
		RDEBUG("Missing &User-Name");
		return RLM_MODULE_FAIL;
	}

	len = fr_hex2bin(s_mac, sizeof(s_mac), vp->vp_strvalue, vp->vp_length);
	if (len != 6) {
		RDEBUG("&User-Name is not a recognizable hex MAC address");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Get the AP MAC address.
	 */
	vp = fr_pair_find_by_num(request->packet->vps, PW_CALLED_STATION_MAC, 0, TAG_ANY);
	if (!vp) {
		RDEBUG("Missing &Called-Station-MAC");
		return RLM_MODULE_FAIL;
	}

	if (vp->length != 6) {
		RDEBUG("&Called-Station-MAC is not a recognizable MAC address");
		return RLM_MODULE_FAIL;
	}

	ap_mac = vp->vp_octets;

	/*
	 *	Sort the MACs
	 */
	if (memcmp(s_mac, ap_mac, 6) <= 0) {
		min_mac = s_mac;
		max_mac = ap_mac;
	} else {
		min_mac = ap_mac;
		max_mac = s_mac;
	}

	eapol = (eapol_attr_t const *) key_msg->vp_octets;

	/*
	 *	Get supplicant nonce and AP nonce.
	 *
	 *	Then sort the nonces.
	 */
	snonce = key_msg->vp_octets + 17;
	if (memcmp(snonce, anonce->vp_octets, 32) <= 0) {
		min_nonce = snonce;
		max_nonce = anonce->vp_octets;
	} else {
		min_nonce = anonce->vp_octets;
		max_nonce = snonce;
	}

	/*
	 *	Create the base message which we will hash.
	 */
	memcpy(message, "Pairwise key expansion", sizeof("Pairwise key expansion")); /* including trailing NUL */
	p = &message[sizeof("Pairwise key expansion")];

	memcpy(p, min_mac, 6);
	memcpy(p + 6, max_mac, 6);
	p += 12;

	memcpy(p, min_nonce, 32);
	memcpy(p + 32, max_nonce, 32);
	p += 64;
	*p = '\0';
	fr_assert(sizeof(message) == (p + 1 - message));

	/*
	 *	If we're caching, then check the cache first, before
	 *	trying the file.  This check allows us to avoid the
	 *	PMK calculation in many situations, as that can be
	 *	expensive.
	 */
	if (inst->cache) {
		entry = dpsk_cache_find(request, inst, pmk, sizeof(pmk), vp_ssid, s_mac);
		if (entry) {
			psk_identity = entry->identity;
			psk = entry->psk;
			psk_len = entry->psk_len;
			goto make_digest;
		}
	}

	/*
	 *	No cache, or no cache entry.  Look for an external PMK
	 *	taken from a database.
	 */
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

	/*
	 *	No external PMK.  Try an external PSK.
	 */
	vp_psk = fr_pair_find_by_num(request->config, PW_PRE_SHARED_KEY, 0, TAG_ANY);
	if (vp_psk) {
		RDEBUG("Trying &control:Pre-Shared-Key");
		if (generate_pmk(request, pmk, sizeof(pmk), vp_ssid, vp_psk->vp_strvalue, vp_psk->vp_length) < 0) {
			fr_assert(!fp);
			return RLM_MODULE_FAIL;
		}

		vp_id = fr_pair_find_by_num(request->config, PW_PSK_IDENTITY, 0, TAG_ANY);
		if (vp_id) {
			psk_identity = vp_id->vp_strvalue;
		} else {
			vp = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
			if (!vp) return RLM_MODULE_REJECT;

			psk_identity = vp->vp_strvalue;
		}

		psk = vp_psk->vp_strvalue;
		psk_len = vp_psk->vp_length;

		goto make_digest;
	}

	/*
	 *	No external PSK was found.  If there's no file, then
	 *	we can't do anything else.
	 */
stage2:
	stage = 2;

	if (!inst->filename) {
		RDEBUG("No &control:Pre-Shared-Key was found, and no 'filename' was configured");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	If there's an PSK from an external database, then we
	 *	never read the filename.
	 */
	if (inst->filename) {
		FR_TOKEN token;
		char const *q;
		char token_mac[256];
		char buffer[1024];

		if (inst->dynamic) {
			if (radius_xlat(filename_buffer, sizeof(filename_buffer),
					request, inst->filename, NULL, NULL) < 0) {
				return RLM_MODULE_FAIL;
			}

			filename = filename_buffer;
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
		if (!q) {
			RDEBUG("Failed to find matching PSK or MAC in %s", filename);
		fail_file:
			fclose(fp);
			return RLM_MODULE_FAIL;
		}

		/*
		 *	Split the line on commas, paying attention to double quotes.
		 */
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

		/*
		 *	The MAC is optional.  If there is a MAC, we
		 *	loop over the file until we find a matching
		 *	one.
		 */
		if (*q == ',') {
			q++;

			token = getstring(&q, token_mac, sizeof(token_mac), true);
			if (token == T_INVALID) {
				RDEBUG("%s[%d] Failed parsing MAC", filename, lineno);
				goto fail_file;
			}

			/*
			 *	See if the MAC matches.  If not, skip
			 *	this entry.  That's a basic negative cache.
			 */
			if ((strlen(token_mac) != 12) ||
			    (fr_hex2bin((uint8_t *) token_mac, 6, token_mac, 12) != 12)) {
				RDEBUG("%s[%d] Failed parsing MAC", filename, lineno);
				goto fail_file;
			}

			/*
			 *	The MAC doesn't match, don't even bother trying to generate the PMK.
			 */
			if (memcmp(s_mac, token_mac, 6) != 0) {
				goto stage2a;
			}

			RDEBUG3("Found matching MAC");
			stage = 3;
		}

		/*
		 *	Generate the PMK using the SSID, this MAC, and the PSK we just read.
		 */
		psk = token_psk;
		psk_len = strlen(token_psk);
		psk_identity = token_identity;

		RDEBUG3("%s[%d] Trying PSK %s", filename, lineno, token_psk);
		if (generate_pmk(request, pmk, sizeof(pmk), vp_ssid, psk, psk_len) < 0) {
			goto fail_file;
		}
	}

	/*
	 *	HMAC = HMAC_SHA1(pmk, message);
	 *
	 *	We need the first 16 octets of this.
	 */
make_digest:
	digest_len = sizeof(digest);
	HMAC(EVP_sha1(), pmk, sizeof(pmk), message, sizeof(message), digest, &digest_len);

	RDEBUG_HEX(request, "message:", message, sizeof(message));
	RDEBUG_HEX(request, "pmk   :", pmk, sizeof(pmk));
	RDEBUG_HEX(request, "kck   :", digest, 16);

	/*
	 *	Create the frame with the middle field zero, and hash it with the KCK digest we calculated from the key expansion.
	 */
	memcpy(frame, key_msg->vp_octets, key_msg->vp_length);
	zeroed = (eapol_attr_t *) &frame[0];
	memset(&zeroed->frame.mic[0], 0, 16);

	RDEBUG_HEX(request, "zeroed:", frame, key_msg->vp_length);

	mic_len = sizeof(mic);
	HMAC(EVP_sha1(), digest, 16, frame, key_msg->vp_length, mic, &mic_len);

	/*
	 *	The MICs don't match.
	 */
	if (memcmp(&eapol->frame.mic[0], mic, 16) != 0) {
		RDEBUG3("Stage %d", stage);
		RDEBUG_HEX(request, "calculated mic:", mic, 16);
		RDEBUG_HEX(request, "packet mic    :", &eapol->frame.mic[0], 16);

		psk_identity = NULL;
		psk = NULL;
		psk_len = 0;

		/*
		 *	Found a cached entry, but it didn't match.  Go
		 *	check external PMK / PSK.
		 */
		if (stage == 0) {
			fr_assert(entry != NULL);
			rbtree_deletebydata(inst->cache, entry); /* locks and unlinks the entry */
			entry = NULL;
			goto stage1;
		}

		/*
		 *	Found an external PMK or PSK, but it didn't
		 *	match.  Go check the file.
		 */
		if (stage == 1) {
			if (vp_psk) RDEBUG("&control:Pre-Shared-Key did not match");

			if (inst->filename) {
				RDEBUG("Checking file %s for PSK and MAC", inst->filename);
				goto stage2;
			}

			RDEBUG("No 'filename' was configured.");
			return RLM_MODULE_REJECT;
		}

		/*
		 *	The file is open, so we keep reading it until
		 *	we find a matching entry.
		 */
		fr_assert(fp);

		if (stage == 2) goto stage2a;

		fclose(fp);

		/*
		 *	We found a PSK associated with this MAC in the
		 *	file.  But it didn't match, so we're done.
		 */
		fr_assert(stage == 3);

		RDEBUG("Found matching MAC in %s, but the PSK does not match", inst->filename);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	We found a matching PSK.  If we read it from the file,
	 *	then close the file, and ensure that we return
	 *	UPDATED.  This tells the caller to write the entry
	 *	into the database, so that we don't need to scan the
	 *	file again.
	 */
	if (fp) {
		rcode = RLM_MODULE_UPDATED;
		fr_assert(psk == token_psk);
		fr_assert(psk_identity == token_identity);
		fclose(fp);
	}

	/*
	 *	Extend the lifetime of the cache entry, or add the
	 *	cache entry if necessary.  We only add / update the
	 *	cache entry if the PSK was not found in a VP.
	 *
	 *	If the caller gave us only a PMK, then don't cache anything.
	 */
	if (inst->cache && psk && psk_identity) {
		rlm_dpsk_cache_t my_entry;

		/*
		 *	We've found an entry. Just update it.
		 */
		if (entry) goto update_entry;

		/*
		 *	No cached entry, or the PSK in the cached
		 *	entry didn't match.  We need to create one.
		 */
		memcpy(my_entry.mac, s_mac, sizeof(my_entry.mac));
		memcpy(&my_entry.ssid, &vp_ssid->vp_octets, sizeof(my_entry.ssid)); /* const ptr issues */
		my_entry.ssid_len = vp_ssid->vp_length;

		entry = rbtree_finddata(inst->cache, &my_entry);
		if (!entry) {
			/*
			 *	Maybe there are oo many entries in the
			 *	cache.  If so, delete the oldest one.
			 */
			if (rbtree_num_elements(inst->cache) > inst->cache_size) {
				PTHREAD_MUTEX_LOCK(&inst->mutex);
				entry = fr_dlist_head(&inst->head);
				PTHREAD_MUTEX_UNLOCK(&inst->mutex);

				rbtree_deletebydata(inst->cache, entry); /* locks and unlinks the entry */
			}

			MEM(entry = talloc_zero(inst->cache, rlm_dpsk_cache_t));

			memcpy(entry->mac, s_mac, sizeof(entry->mac));
			memcpy(entry->pmk, pmk, sizeof(entry->pmk));

			fr_dlist_entry_init(&entry->dlist);
			entry->inst = inst;

			/*
			 *	Save the SSID, PSK, and PSK identity in the cache entry.
			 */
			MEM(entry->ssid = talloc_memdup(entry, vp_ssid->vp_octets, vp_ssid->vp_length));
			entry->ssid_len = vp_ssid->vp_length;

			MEM(entry->psk = talloc_memdup(entry, psk, psk_len));
			entry->psk_len = psk_len;

			entry->identity_len = strlen(psk_identity);
			MEM(entry->identity = talloc_memdup(entry, psk_identity, entry->identity_len));

			/*
			 *	Cache it.
			 */
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

		/*
		 *	Add the PSK to the reply items, if it was cached.
		 */
		if (entry->psk) {
			MEM(vp = fr_pair_afrom_num(request->reply, PW_PRE_SHARED_KEY, 0));
			fr_pair_value_bstrncpy(vp, entry->psk, entry->psk_len);

			fr_pair_add(&request->reply->vps, vp);
		}
	}

update_attributes:
	/*
	 *	We found a cache entry, or an external PSK.  Don't
	 *	create new attributes.
	 */
	if (rcode == RLM_MODULE_OK) return RLM_MODULE_OK;

	fr_assert(psk != NULL);
	fr_assert(psk_identity != NULL);

	/*
	 *	Create the attributes which the caller can then save
	 *	in the database.
	 */
	RDEBUG("Creating &reply:PSK-Identity and &reply:Pre-Shared-Key");
	MEM(vp = fr_pair_afrom_num(request->reply, PW_PRE_SHARED_KEY, 0));
	fr_pair_value_bstrncpy(vp, psk, psk_len);
	fr_pair_add(&request->reply->vps, vp);

	MEM(vp = fr_pair_afrom_num(request->reply, PW_PSK_IDENTITY, 0));
	fr_pair_value_bstrncpy(vp, psk_identity, strlen(psk_identity));
	fr_pair_add(&request->reply->vps, vp);

	return RLM_MODULE_UPDATED;
}

/*
 *	Generate the PMK from SSID and Pre-Shared-Key
 */
static ssize_t dpsk_xlat(void *instance, REQUEST *request,
			 char const *fmt, char *out, size_t outlen)
{
	rlm_dpsk_t *inst = instance;
	char const *p, *ssid, *psk;
	size_t ssid_len, psk_len;
	uint8_t buffer[32];

	/*
	 *	Prefer xlat arguments.  But if they don't exist, use the attributes.
	 */
	p = fmt;
	while (isspace((uint8_t) *p)) p++;

	if (!*p) {
		VALUE_PAIR *vp_ssid, *vp_psk;

		vp_ssid = fr_pair_find_by_da(request->packet->vps, inst->ssid, TAG_ANY);
		if (!vp_ssid) {
			RDEBUG("No %s in the request", inst->ssid->name);
			return 0;
		}

		vp_psk = fr_pair_find_by_num(request->config, PW_PRE_SHARED_KEY, 0, TAG_ANY);
		if (!vp_psk) {
			RDEBUG("No &config:Pre-Shared-Key");
			return 0;
		}

		psk = vp_psk->vp_strvalue;
		psk_len = vp_psk->vp_length;

		ssid = vp_ssid->vp_strvalue;
		ssid_len = vp_ssid->vp_length;
		goto get_pmk;

	} else {
		ssid = p;

		while (*p && !isspace((uint8_t) *p)) p++;

		ssid_len = p - ssid;

		if (!*p) {
			REDEBUG("Found SSID, but no PSK");
			return 0;
		}

		psk = p;

		while (*p && !isspace((uint8_t) *p)) p++;

		psk_len = p - psk;

	get_pmk:
		if (PKCS5_PBKDF2_HMAC_SHA1(psk, psk_len, (const unsigned char *) ssid, ssid_len, 4096, sizeof(buffer), buffer) == 0) {
			RDEBUG("Failed calling OpenSSL to calculate the PMK");
			return 0;
		}
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
	rlm_dpsk_t *inst = instance;

	/*
	 *	Create the dynamic translation.
	 */
	name = cf_section_name2(conf);
	if (!name) name = cf_section_name1(conf);
	inst->xlat_name = name;
	xlat_register(inst->xlat_name, dpsk_xlat, NULL, inst);

	if (inst->ruckus) {
		inst->ssid = dict_attrbyvalue(PW_RUCKUS_BSSID, VENDORPEC_RUCKUS);
		inst->anonce = dict_attrbyvalue(PW_RUCKUS_DPSK_ANONCE, VENDORPEC_RUCKUS);
		inst->frame = dict_attrbyvalue(PW_RUCKUS_DPSK_EAPOL_KEY_FRAME, VENDORPEC_RUCKUS);
	} else {
		inst->ssid = dict_attrbyvalue(PW_CALLED_STATION_SSID, 0);
		inst->anonce = dict_attrbyvalue(PW_FREERADIUS_8021X_ANONCE, VENDORPEC_FREERADIUS_EVS5);
		inst->frame = dict_attrbyvalue(PW_FREERADIUS_8021X_EAPOL_KEY_MSG, VENDORPEC_FREERADIUS_EVS5);
	}

	if (!inst->ssid || !inst->anonce || !inst->frame) {
		cf_log_err_cs(conf, "Failed to find attributes in the dictionary.  Please do not edit the default dictionaries!");
		return -1;
	}

	inst->dynamic = inst->filename && (strchr(inst->filename, '%') != NULL);

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
