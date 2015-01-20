/**
 * $Id$
 * @file decrypt.c
 * @brief Authentication for yubikey OTP tokens using the yubikey library.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@networkradius.com>
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Network RADIUS <info@networkradius.com>
 */

#include "rlm_yubikey.h"

#ifdef HAVE_YUBIKEY
const uint8_t uid_unused[YUBIKEY_UID_SIZE] = { 0, 0, 0, 0, 0, 0 };

/** Decrypt a Yubikey OTP AES block
 *
 * @param inst Module configuration.
 * @param passcode string to decrypt.
 * @return one of the RLM_RCODE_* constants.
 */
rlm_rcode_t rlm_yubikey_decrypt(rlm_yubikey_t *inst, REQUEST *request, char const *passcode)
{
	uint32_t counter, timestamp;
	yubikey_token_st token;
	DICT_ATTR const *da;
	char private_id[(YUBIKEY_UID_SIZE * 2) + 1];
	VALUE_PAIR *vp;

	/*
	 * Key control list info must exist
	 */
	da = dict_attrbyname("Yubikey-Key");
	if (!da) {
		REDEBUG("Dictionary missing entry for 'Yubikey-Key'");
		return RLM_MODULE_FAIL;
	}

	vp = pair_find_by_da(request->config_items, da, TAG_ANY);
	if (!vp) {
		REDEBUG("Yubikey-Key attribute not found in control list, can't decrypt OTP data");
		return RLM_MODULE_INVALID;
	}

	if (inst->normify)
		rlm_yubikey_normify(request, vp, YUBIKEY_KEY_SIZE);

	if (vp->vp_length != YUBIKEY_KEY_SIZE) {
		REDEBUG("Yubikey-Key length incorrect, expected %u got %zu", YUBIKEY_KEY_SIZE, vp->vp_length);
		return RLM_MODULE_INVALID;
	}

	yubikey_parse((uint8_t const *) passcode + inst->id_len, vp->vp_octets, &token);

	if (!yubikey_crc_ok_p((uint8_t *) &token)) {
		REDEBUG("Decrypting OTP token data failed, rejecting");
		return RLM_MODULE_REJECT;
	}

	RDEBUG("Token data decrypted successfully");

	counter = (yubikey_counter(token.ctr) << 8) | token.use;
	timestamp = (token.tstph << 16) | token.tstpl;

	if (request->log.lvl && request->log.func) {
		(void) fr_bin2hex(private_id, token.uid, YUBIKEY_UID_SIZE);
		RDEBUG2("Private ID : 0x%s", private_id);
		RDEBUG2("Counter    : %u", counter);
		RDEBUG2("Timestamp  : %u", timestamp);
		RDEBUG2("Random     : %u", token.rnd);
		RDEBUG2("CRC        : 0x%x", token.crc);
	}

	/*
	 * If token Private-ID is non-zero, then compare (if info exists)
	 */
	if (memcmp(token.uid, uid_unused, YUBIKEY_UID_SIZE)) {
		da = dict_attrbyname("Yubikey-Private-ID");
		if (!da) {
			REDEBUG("Dictionary missing entry for 'Yubikey-Private-ID'");
			return RLM_MODULE_FAIL;
		}

		vp = pair_find_by_da(request->config_items, da, TAG_ANY);
		if (vp) {
			if (inst->normify)
				rlm_yubikey_normify(request, vp, YUBIKEY_UID_SIZE);
			if (vp->vp_length != YUBIKEY_UID_SIZE) {
				REDEBUG("Yubikey-Private-ID length incorrect, expected %u got %zu", YUBIKEY_UID_SIZE, vp->vp_length);
				return RLM_MODULE_INVALID;
			}

			if (memcmp(token.uid, vp->vp_octets, YUBIKEY_UID_SIZE)) {
				REDEBUG("Private ID mismatch!");
				return RLM_MODULE_REJECT;
			}
		}
	}

	/*
	 * Now check for replay attacks (if info exists)
	 */
	da = dict_attrbyname("Yubikey-Counter");
	if (!da) {
		REDEBUG("Dictionary missing entry for 'Yubikey-Counter'");
		return RLM_MODULE_FAIL;
	}

	vp = pair_find_by_da(request->config_items, da, TAG_ANY);
	if (vp) {
		if (counter <= vp->vp_integer) {
			REDEBUG("Replay attack detected! Counter value %u, is lt or eq to last known counter value %u",
				counter, vp->vp_integer);
			return RLM_MODULE_REJECT;
		}
	}

	/* 
	 * Record attributes for further validation and optional SQL storage
	 */
	vp = pairmake(request, &request->packet->vps, "Yubikey-Private-ID", NULL, T_OP_SET);
	if (!vp) {
		REDEBUG("Failed creating Yubikey-Private-ID");
		return RLM_MODULE_FAIL;
	}
	pairmemcpy(vp, token.uid, YUBIKEY_UID_SIZE);

	vp = pairmake(request, &request->packet->vps, "Yubikey-Counter", NULL, T_OP_SET);
	if (!vp) {
		REDEBUG("Failed creating Yubikey-Counter");
		return RLM_MODULE_FAIL;
	}

	vp->vp_integer = counter;
	vp->vp_length = 4;

	vp = pairmake(request, &request->packet->vps, "Yubikey-Timestamp", NULL, T_OP_SET);
	if (!vp) {
		REDEBUG("Failed creating Yubikey-Timestamp");
		return RLM_MODULE_FAIL;
	}
	vp->vp_integer = timestamp;
	vp->vp_length = 4;

	vp = pairmake(request, &request->packet->vps, "Yubikey-Random", NULL, T_OP_SET);
	if (!vp) {
		REDEBUG("Failed creating Yubikey-Random");
		return RLM_MODULE_FAIL;
	}
	vp->vp_integer = token.rnd;
	vp->vp_length = 4;


	return RLM_MODULE_OK;
}
#endif
