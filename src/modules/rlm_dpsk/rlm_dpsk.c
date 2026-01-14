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
#include <freeradius-devel/util/rb.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <ctype.h>

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

typedef struct {
	fr_rb_node_t		node;
	uint8_t			mac[6];
	uint8_t			pmk[32];

	uint8_t			*ssid;
	size_t			ssid_len;

	char			*identity;
	size_t			identity_len;

	char			*psk;
	size_t			psk_len;
	fr_time_t		expires;

	fr_dlist_t		dlist;
	rlm_dpsk_t const	*inst;
} rlm_dpsk_cache_t;

typedef struct {
	fr_rb_tree_t			cache;

	pthread_mutex_t			mutex;
	fr_dlist_head_t			head;
} rlm_dpsk_mutable_t;

struct rlm_dpsk_s {
	fr_dict_enum_value_t const	*auth_type;

	uint32_t			cache_size;
	fr_time_delta_t			cache_lifetime;

	rlm_dpsk_mutable_t		*mutable;
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_dpsk_dict[];
fr_dict_autoload_t rlm_dpsk_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_auth_type;

extern fr_dict_attr_autoload_t rlm_dpsk_dict_attr[];
fr_dict_attr_autoload_t rlm_dpsk_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	DICT_AUTOLOAD_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("cache_size", rlm_dpsk_t, cache_size) },
	{ FR_CONF_OFFSET("cache_lifetime", rlm_dpsk_t, cache_lifetime) },

	CONF_PARSER_TERMINATOR
};

typedef struct {
	tmpl_t		*anonce_tmpl;
	tmpl_t		*key_msg_tmpl;
} dpsk_autz_call_env_t;

typedef struct {
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
					  CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED,
					  dpsk_auth_call_env_t, ssid, ssid_tmpl), .pair.dflt = "Called-Station-SSID",
					  .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_OFFSET("anonce", FR_TYPE_OCTETS,
					  CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED,
					  dpsk_auth_call_env_t, anonce, anonce_tmpl), .pair.dflt = "FreeRADIUS-EV5.802_1X-Anonce",
					  .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_OFFSET("key_msg", FR_TYPE_OCTETS,
					  CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED,
					  dpsk_auth_call_env_t, key_msg, key_msg_tmpl), .pair.dflt = "FreeRADIUS-EV5.802_1X-EAPoL-Key-Msg",
					  .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("username", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED,
				     dpsk_auth_call_env_t, username), .pair.dflt = "User-Name", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("called_station", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED,
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

/*
 *	mod_authorize() - authorize user if we can authenticate
 *	it later. Add Auth-Type attribute if present in module
 *	configuration (usually Auth-Type must be "DPSK")
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_dpsk_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_dpsk_t);
	dpsk_autz_call_env_t	*env = talloc_get_type_abort(mctx->env_data, dpsk_autz_call_env_t);
	tmpl_dcursor_ctx_t	cc;
	fr_dcursor_t		cursor;
	fr_pair_t		*vp;

	vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, env->anonce_tmpl);
	tmpl_dcursor_clear(&cc);
	if (!vp) RETURN_UNLANG_NOOP;

	vp = tmpl_dcursor_init(NULL, NULL, &cc, &cursor, request, env->key_msg_tmpl);
	tmpl_dcursor_clear(&cc);
	if (!vp) RETURN_UNLANG_NOOP;

	if (!inst->auth_type) {
		WARN("No 'authenticate %s {...}' section or 'Auth-Type = %s' set.  Cannot setup DPSK authentication.",
		     mctx->mi->name, mctx->mi->name);
		RETURN_UNLANG_NOOP;
	}

	if (!module_rlm_section_type_set(request, attr_auth_type, inst->auth_type)) RETURN_UNLANG_NOOP;

	RETURN_UNLANG_UPDATED;
}

static rlm_dpsk_cache_t *dpsk_cache_find(request_t *request, rlm_dpsk_t const *inst, uint8_t *buffer, size_t buflen,
					 fr_value_box_t *ssid, uint8_t const *mac)
{
	rlm_dpsk_cache_t *entry, my_entry;

	memcpy(my_entry.mac, mac, sizeof(my_entry.mac));
	memcpy(&my_entry.ssid, &ssid->vb_octets, sizeof(my_entry.ssid)); /* const issues */
	my_entry.ssid_len = ssid->vb_length;

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


static int generate_pmk(request_t *request, uint8_t *buffer, size_t buflen, fr_value_box_t *ssid, char const *psk, size_t psk_len)
{
	fr_assert(buflen == 32);

	if (PKCS5_PBKDF2_HMAC_SHA1((const char *) psk, psk_len, (const unsigned char *) ssid->vb_strvalue,
				   ssid->vb_length, 4096, buflen, buffer) == 0) {
		RERROR("Failed calling OpenSSL to calculate the PMK");
		return -1;
	}

	return 0;
}

/*
 *	Verify the DPSK information.
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_dpsk_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_dpsk_t);
	dpsk_auth_call_env_t	*env = talloc_get_type_abort(mctx->env_data, dpsk_auth_call_env_t);
	rlm_dpsk_cache_t	*entry = NULL;
	int			lineno = 0;
	int			stage = 0;
	rlm_rcode_t		rcode = RLM_MODULE_OK;
	size_t			psk_len = 0;
	unsigned int		digest_len, mic_len;
	eapol_attr_t const	*eapol;
	eapol_attr_t		*zeroed;
	FILE			*fp = NULL;
	char const		*filename = (env->filename.type == FR_TYPE_STRING) ? env->filename.vb_strvalue : NULL;
	char const		*psk_identity = NULL, *psk = NULL;
	uint8_t			*p;
	uint8_t const		*snonce, *ap_mac;
	uint8_t const		*min_mac, *max_mac;
	uint8_t const		*min_nonce, *max_nonce;
	uint8_t			pmk[32];
	uint8_t			s_mac[6], message[sizeof("Pairwise key expansion") + 6 + 6 + 32 + 32 + 1], frame[128];
	uint8_t			digest[EVP_MAX_MD_SIZE], mic[EVP_MAX_MD_SIZE];
	char			token_identity[256];
	char			token_psk[256];

	/*
	 *	Search for the information in a bunch of attributes.
	 */
	if (env->anonce.vb_length != 32) {
		RWARN("%s has incorrect length (%zu, not 32)", env->anonce_tmpl->name, env->anonce.vb_length);
		RETURN_UNLANG_NOOP;
	}

	if (env->key_msg.vb_length < sizeof(*eapol)) {
		RWARN("%s has incorrect length (%zu < %zu)", env->key_msg_tmpl->name, env->key_msg.vb_length, sizeof(*eapol));
		RETURN_UNLANG_NOOP;
	}

	if (env->key_msg.vb_length > sizeof(frame)) {
		RWARN("%s has incorrect length (%zu > %zu)", env->key_msg_tmpl->name, env->key_msg.vb_length, sizeof(frame));
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
		       &FR_SBUFF_IN(env->username.vb_strvalue, env->username.vb_length), false) != 6) {
		RERROR("User-Name is not a recognizable hex MAC address");
		RETURN_UNLANG_FAIL;
	}

	if (env->calledstation.vb_length != 6) {
		RERROR("Called-Station-MAC is not a recognizable MAC address");
		RETURN_UNLANG_FAIL;
	}

	ap_mac = env->calledstation.vb_octets;

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

	eapol = (eapol_attr_t const *) env->key_msg.vb_octets;

	/*
	 *	Get supplicant nonce and AP nonce.
	 *
	 *	Then sort the nonces.
	 */
	snonce = env->key_msg.vb_octets + 17;
	if (memcmp(snonce, env->anonce.vb_octets, 32) <= 0) {
		min_nonce = snonce;
		max_nonce = env->anonce.vb_octets;
	} else {
		min_nonce = env->anonce.vb_octets;
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
	if (inst->cache_size) {
		entry = dpsk_cache_find(request, inst, pmk, sizeof(pmk), &env->ssid, s_mac);
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

	if (env->masterkey.type == FR_TYPE_OCTETS) {
		if (env->masterkey.vb_length != sizeof(pmk)) {
			RWARN("%s has incorrect length (%zu != %zu) - ignoring it", env->masterkey_tmpl->name,
			      env->masterkey.vb_length, sizeof(pmk));
		} else {
			RDEBUG2("Using %s", env->masterkey_tmpl->name);
			memcpy(pmk, env->masterkey.vb_octets, sizeof(pmk));
			goto make_digest;
		}
	}

	/*
	 *	No external PMK.  Try an external PSK.
	 */
	if (env->psk.type == FR_TYPE_STRING) {
		RDEBUG3("Trying %s", env->psk_tmpl->name);
		if (generate_pmk(request, pmk, sizeof(pmk), &env->ssid, env->psk.vb_strvalue, env->psk.vb_length) < 0) {
			fr_assert(!fp);
			RETURN_UNLANG_FAIL;
		}

		if (env->psk_identity.type == FR_TYPE_STRING) {
			psk_identity = env->psk_identity.vb_strvalue;
		} else {
			psk_identity = env->username.vb_strvalue;
		}

		psk = env->psk.vb_strvalue;
		psk_len = env->psk.vb_length;

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

	/*
	 *	If there's an PSK from an external database, then we
	 *	never read the filename.
	 */
	if (filename) {
		char			token_mac[256];
		char			buffer[1024];
		fr_sbuff_t		sbuff;
		fr_sbuff_uctx_file_t	fctx;
		size_t			len;
		fr_sbuff_term_t const	terms = FR_SBUFF_TERMS(L("\n"),L("\r"),L(","));
		fr_sbuff_term_t const	quoted_terms = FR_SBUFF_TERMS(L("\""));
		bool			quoted = false;

		RDEBUG3("Looking for PSK in file %s", filename);

		fp = fopen(filename, "r");
		if (!fp) {
			REDEBUG("Failed opening %s - %s", filename, fr_syserror(errno));
			RETURN_UNLANG_FAIL;
		}

		fr_sbuff_init_file(&sbuff, &fctx, buffer, sizeof(buffer), fp, SIZE_MAX);

stage2a:
		lineno++;
		fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX, NULL);
		quoted = fr_sbuff_next_if_char(&sbuff, '"');
		len = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(token_identity, sizeof(token_identity)), &sbuff,
						  sizeof(token_identity), quoted ? &quoted_terms : &terms, NULL);
		if (len == 0) {
			RDEBUG("Failed to find matching PSK or MAC in %s", filename);
		fail_file:
			fclose(fp);
			RETURN_UNLANG_FAIL;
		}
		if (quoted) {
			fr_sbuff_next_if_char(&sbuff, '"');
			fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL);
		}

		if (!fr_sbuff_next_if_char(&sbuff, ',')) {
			RDEBUG("%s[%d] Failed to find ',' after identity", filename, lineno);
			goto fail_file;
		}

		fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL);
		quoted = fr_sbuff_next_if_char(&sbuff, '"');
		len = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(token_psk, sizeof(token_psk)), &sbuff,
						  sizeof(token_identity), quoted ? &quoted_terms : &terms, NULL);
		if (len == 0) {
			RDEBUG("%s[%d] Failed parsing PSK", filename, lineno);
			goto fail_file;
		}
		if (quoted) {
			fr_sbuff_next_if_char(&sbuff, '"');
			fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL);
		}

		/*
		 *	The MAC is optional.  If there is a MAC, we
		 *	loop over the file until we find a matching
		 *	one.
		 */
		if (fr_sbuff_next_if_char(&sbuff, ',')) {

			fr_sbuff_adv_past_blank(&sbuff, SIZE_MAX, NULL);
			quoted = fr_sbuff_next_if_char(&sbuff, '"');
			len = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(token_mac, sizeof(token_mac)), &sbuff,
							  sizeof(token_identity), quoted ? &quoted_terms : &terms, NULL);
			if (len == 0) {
				RERROR("%s[%d] Failed parsing MAC", filename, lineno);
				goto fail_file;
			}

			/*
			 *	See if the MAC matches.  If not, skip
			 *	this entry.  That's a basic negative cache.
			 */
			if ((len != 12) ||
			    (fr_base16_decode(NULL, &FR_DBUFF_TMP((uint8_t *)token_mac, 6),
			    		      &FR_SBUFF_IN(token_mac, 12), false) != 6)) {
				RERROR("%s[%d] Failed parsing MAC", filename, lineno);
				goto fail_file;
			}
			if (quoted) fr_sbuff_next_if_char(&sbuff, '"');

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
		if (generate_pmk(request, pmk, sizeof(pmk), &env->ssid, psk, psk_len) < 0) {
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
#ifdef __COVERITY__
	/*
	 * Coverity doesn't see that HMAC will populate digest
	 */
	memset(digest, 0, digest_len);
#endif
	HMAC(EVP_sha1(), pmk, sizeof(pmk), message, sizeof(message), digest, &digest_len);

	RHEXDUMP3(message, sizeof(message), "message:");
	RHEXDUMP3(pmk, sizeof(pmk), "pmk   :");
	RHEXDUMP3(digest, 16, "kck   :");

	/*
	 *	Create the frame with the middle field zero, and hash it with the KCK digest we calculated from the key expansion.
	 */
	memcpy(frame, env->key_msg.vb_octets, env->key_msg.vb_length);
	zeroed = (eapol_attr_t *) &frame[0];
	memset(&zeroed->frame.mic[0], 0, 16);

	RHEXDUMP3(frame, env->key_msg.vb_length, "zeroed:");

	mic_len = sizeof(mic);
#ifdef __COVERITY__
	/*
	 * Coverity doesn't see that HMAC will populate mic
	 */
	memset(mic, 0, mic_len);
#endif
	HMAC(EVP_sha1(), digest, 16, frame, env->key_msg.vb_length, mic, &mic_len);

	/*
	 *	The MICs don't match.
	 */
	if (memcmp(&eapol->frame.mic[0], mic, 16) != 0) {
		RDEBUG3("Stage %d", stage);
		RHEXDUMP3(mic, 16, "calculated mic:");
		RHEXDUMP3(eapol->frame.mic, 16, "packet mic    :");

		psk_identity = NULL;
		psk = NULL;
		psk_len = 0;

		/*
		 *	Found a cached entry, but it didn't match.  Go
		 *	check external PMK / PSK.
		 */
		if (stage == 0) {
			fr_assert(entry != NULL);
			fr_rb_delete(&inst->mutable->cache, entry); /* locks and unlinks the entry */
			entry = NULL;
			goto stage1;
		}

		/*
		 *	Found an external PMK or PSK, but it didn't
		 *	match.  Go check the file.
		 */
		if (stage == 1) {
			if (env->psk.type == FR_TYPE_STRING) RWARN("%s did not match", env->psk_tmpl->name);

			if (filename) {
				RDEBUG("Checking file %s for PSK and MAC", filename);
				goto stage2;
			}

			RWARN("No 'filename' was configured.");
			RETURN_UNLANG_REJECT;
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

		RWARN("Found matching MAC in %s, but the PSK does not match", filename);
		RETURN_UNLANG_FAIL;
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
	if (inst->cache_size && psk && psk_identity) {
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
		memcpy(&my_entry.ssid, env->ssid.vb_octets, sizeof(my_entry.ssid)); /* const ptr issues */
		my_entry.ssid_len = env->ssid.vb_length;

		entry = fr_rb_find(&inst->mutable->cache, &my_entry);
		if (!entry) {
			/*
			 *	Maybe there are oo many entries in the
			 *	cache.  If so, delete the oldest one.
			 */
			if (fr_rb_num_elements(&inst->mutable->cache) > inst->cache_size) {
				pthread_mutex_lock(&inst->mutable->mutex);
				entry = fr_dlist_head(&inst->mutable->head);
				pthread_mutex_unlock(&inst->mutable->mutex);

				fr_rb_delete(&inst->mutable->cache, entry); /* locks and unlinks the entry */
			}

			MEM(entry = talloc_zero(&inst->mutable->cache, rlm_dpsk_cache_t));

			memcpy(entry->mac, s_mac, sizeof(entry->mac));
			memcpy(entry->pmk, pmk, sizeof(entry->pmk));

			entry->inst = inst;

			/*
			 *	Save the SSID, PSK, and PSK identity in the cache entry.
			 */
			MEM(entry->ssid = talloc_memdup(entry, env->ssid.vb_octets, env->ssid.vb_length));
			entry->ssid_len = env->ssid.vb_length;

			MEM(entry->psk = talloc_strdup(entry, psk));
			entry->psk_len = psk_len;

			entry->identity_len = strlen(psk_identity);
			MEM(entry->identity = talloc_strdup(entry, psk_identity));

			/*
			 *	Cache it.
			 */
			if (!fr_rb_insert(&inst->mutable->cache, entry)) {
				TALLOC_FREE(entry);
				goto update_attributes;
			}
			RDEBUG3("Cache entry saved");
		}

	update_entry:
		pthread_mutex_lock(&inst->mutable->mutex);
		entry->expires = fr_time_add(fr_time(), inst->cache_lifetime);
		if (fr_dlist_entry_in_list(&entry->dlist)) fr_dlist_remove(&inst->mutable->head, entry);
		fr_dlist_insert_tail(&inst->mutable->head, entry);
		pthread_mutex_unlock(&inst->mutable->mutex);

		/*
		 *	Add the PSK to the reply items, if it was cached.
		 */
		if (entry->psk) {
			tmpl_t psk_rhs;
			map_t psk_map = {
				.lhs = env->psk_dest_tmpl,
				.op = T_OP_SET,
				.rhs = &psk_rhs
			};

			tmpl_init_shallow(&psk_rhs, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0, NULL);
			fr_value_box_bstrndup_shallow(&psk_map.rhs->data.literal,
						      NULL, entry->psk, entry->psk_len, true);
			if (map_to_request(request, &psk_map, map_to_vp, NULL) < 0) RETURN_UNLANG_FAIL;
		}
	}

update_attributes:
	/*
	 *	We found a cache entry, or an external PSK.  Don't
	 *	create new attributes.
	 */
	if (rcode == RLM_MODULE_OK) RETURN_UNLANG_OK;

	fr_assert(psk != NULL);
	fr_assert(psk_identity != NULL);

	{
		tmpl_t rhs;
		map_t map = {
			.lhs = env->psk_dest_tmpl,
			.op = T_OP_SET,
			.rhs = &rhs
		};

		RDEBUG2("Creating %s and %s", env->psk_dest_tmpl->name, env->psk_identity_dest_tmpl->name);
		tmpl_init_shallow(&rhs, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0, NULL);
		fr_value_box_bstrndup_shallow(&map.rhs->data.literal, NULL, psk, psk_len, true);
		if (map_to_request(request, &map, map_to_vp, NULL) < 0) RETURN_UNLANG_FAIL;

		map.lhs = env->psk_identity_dest_tmpl;
		fr_value_box_bstrndup_shallow(&map.rhs->data.literal, NULL, psk_identity, strlen(psk_identity), true);
		if (map_to_request(request, &map, map_to_vp, NULL) < 0) RETURN_UNLANG_FAIL;
	}

	RETURN_UNLANG_UPDATED;
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

static int8_t cmp_cache_entry(void const *one, void const *two)
{
	rlm_dpsk_cache_t const *a = (rlm_dpsk_cache_t const *) one;
	rlm_dpsk_cache_t const *b = (rlm_dpsk_cache_t const *) two;
	int rcode;

	rcode = memcmp(a->mac, b->mac, sizeof(a->mac));
	if (rcode != 0) return rcode;

	if (a->ssid_len < b->ssid_len) return -1;
	if (a->ssid_len > b->ssid_len) return +1;

	return CMP(memcmp(a->ssid, b->ssid, a->ssid_len), 0);
}

static void free_cache_entry(void *data)
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

	if (!inst->cache_size) return 0;

	pthread_mutex_destroy(&inst->mutable->mutex);

	talloc_free(inst->mutable);

	return 0;
}
#endif

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
#ifdef WITH_TLS
	rlm_dpsk_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_dpsk_t);

	inst->auth_type = fr_dict_enum_by_name(attr_auth_type, mctx->mi->name, -1);
	if (!inst->auth_type) {
		WARN("Failed to find 'authenticate %s {...}' section.  DPSK will likely not work",
		     mctx->mi->name);
	}

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

	fr_rb_inline_init(&inst->mutable->cache, rlm_dpsk_cache_t, node, cmp_cache_entry, free_cache_entry);

	fr_dlist_init(&inst->mutable->head, rlm_dpsk_cache_t, dlist);

	if (pthread_mutex_init(&inst->mutable->mutex, NULL) < 0) {
		cf_log_err(mctx->mi->conf, "Failed creating mutex");
		return -1;
	}

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
