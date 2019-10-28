/**
 * $Id$
 * @file decrypt.c
 * @brief Authentication for yubikey OTP tokens using the yubikey library.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@networkradius.com)
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Network RADIUS (legal@networkradius.com)
 */
#include "rlm_yubikey.h"

#ifdef HAVE_YUBIKEY
extern fr_dict_attr_t const *attr_yubikey_key;
extern fr_dict_attr_t const *attr_yubikey_private_id;
extern fr_dict_attr_t const *attr_yubikey_timestamp;
extern fr_dict_attr_t const *attr_yubikey_random;
extern fr_dict_attr_t const *attr_yubikey_counter;

/** Decrypt a Yubikey OTP AES block
 *
 * @param inst Module configuration.
 * @param request The current request.
 * @param passcode string to decrypt.
 * @return one of the RLM_RCODE_* constants.
 */
rlm_rcode_t rlm_yubikey_decrypt(rlm_yubikey_t const *inst, REQUEST *request, char const *passcode)
{
	uint32_t counter, timestamp;
	yubikey_token_st token;

	VALUE_PAIR *key, *vp;

	key = fr_pair_find_by_da(request->control, attr_yubikey_key, TAG_ANY);
	if (!key) {
		REDEBUG("Yubikey-Key attribute not found in control list, can't decrypt OTP data");
		return RLM_MODULE_INVALID;
	}

	if (key->vp_length != YUBIKEY_KEY_SIZE) {
		REDEBUG("Yubikey-Key length incorrect, expected %u got %zu", YUBIKEY_KEY_SIZE, key->vp_length);
		return RLM_MODULE_INVALID;
	}

	yubikey_parse((uint8_t const *) passcode + inst->id_len, key->vp_octets, &token);

	/*
	 *	Apparently this just uses byte offsets...
	 */
	if (!yubikey_crc_ok_p((uint8_t *) &token)) {
		REDEBUG("Decrypting OTP token data failed, rejecting");
		return RLM_MODULE_REJECT;
	}

	RDEBUG2("Token data decrypted successfully");

	counter = (yubikey_counter(token.ctr) << 8) | token.use;
	timestamp = (token.tstph << 16) | token.tstpl;

	RDEBUG2("Private ID        : %pH", fr_box_octets(token.uid, YUBIKEY_UID_SIZE));
	RDEBUG2("Session counter   : %u", counter);

	RDEBUG2("Token timestamp   : %u", timestamp);

	RDEBUG2("Random data       : %u", token.rnd);
	RDEBUG2("CRC data          : 0x%x", token.crc);

	/*
	 *	Private ID used for validation purposes
	 */
	MEM(pair_update_request(&vp, attr_yubikey_private_id) >= 0);
	fr_pair_value_memcpy(vp, token.uid, YUBIKEY_UID_SIZE, true);

	/*
	 *	Token timestamp
	 */
	MEM(pair_update_request(&vp, attr_yubikey_timestamp) >= 0);
	vp->vp_uint32 = timestamp;

	/*
	 *	Token random
	 */
	MEM(pair_update_request(&vp, attr_yubikey_random) >= 0);
	vp->vp_uint32 = token.rnd;

	/*
	 *	Combine the two counter fields together so we can do
	 *	replay attack checks.
	 */
	MEM(pair_update_request(&vp, attr_yubikey_counter) >= 0);
	vp->vp_uint32 = counter;

	/*
	 *	Now we check for replay attacks
	 */
	vp = fr_pair_find_by_da(request->control, attr_yubikey_counter, TAG_ANY);
	if (!vp) {
		RWDEBUG("Yubikey-Counter not found in control list, skipping replay attack checks");
		return RLM_MODULE_OK;
	}

	if (counter <= vp->vp_uint32) {
		REDEBUG("Replay attack detected! Counter value %u, is lt or eq to last known counter value %u",
			counter, vp->vp_uint32);
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}
#endif
