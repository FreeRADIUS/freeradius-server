/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

/**
 * @file src/fuzzer/fuzzer_rlm_eap_conversation.c
 * @brief Drive fixture-backed EAP method conversations to reply composition.
 *
 * The low bit of the first input byte selects success (zero) or failure
 * (one).  The remaining bits select EAP-MD5, EAP-GTC, or EAP-MSCHAPv2.
 * The remaining input is fuzzed as "FUZZ"-delimited raw EAP frames after the
 * deterministic conversation prefix completes.
 */
#define LLVMFuzzerInitialize rlm_eap_fuzzer_initialize
#define LLVMFuzzerTestOneInput rlm_eap_fuzzer_test_one_input
#undef RCSID
#define RCSID(_id)
#include "fuzzer_rlm_eap.c"
#undef RCSID
#undef LLVMFuzzerInitialize
#undef LLVMFuzzerTestOneInput

#include <freeradius-devel/util/md5.h>
#include "../lib/eap/types.h"
#include "../modules/rlm_mschap/mschap.h"
#include "../modules/rlm_mschap/smbdes.h"
#include "../modules/rlm_eap/types/rlm_eap_mschapv2/eap_mschapv2.h"

static char const fixture_user[] = "fuzz-user";
static char const fixture_password[] = "fuzz-password";

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len);

static fr_pair_t *conversation_step(TALLOC_CTX *ctx, CONF_SECTION *server, eap_frame_t const *frame,
				    fr_pair_t **state)
{
	request_t *request;
	fr_pair_t *reply = NULL;

	request = request_alloc(ctx, server, frame, *state);
	talloc_free(*state);
	*state = NULL;
	if (!request) return NULL;

	if (fr_timer_in(request, el->tl, &request->timeout, fr_time_delta_from_msec(10),
			false, cancel_request, request) >= 0) {
		unlang_interpret_synchronous(el, request);
		*state = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_state);
		if (*state) *state = fr_pair_copy(ctx, *state);
		reply = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_eap_message);
		if (reply) reply = fr_pair_copy(ctx, reply);
	}

	talloc_free(request);
	return reply;
}

static bool frame_identity(eap_frame_t *frame, uint8_t *packet)
{
	packet[0] = FR_EAP_CODE_RESPONSE;
	packet[1] = 0;
	packet[2] = 0;
	packet[3] = 4 + 1 + sizeof(fixture_user) - 1;
	packet[4] = FR_EAP_METHOD_IDENTITY;
	memcpy(packet + 5, fixture_user, sizeof(fixture_user) - 1);
	frame->eap = packet;
	frame->eap_len = packet[3];
	frame->chbind = NULL;
	frame->chbind_len = 0;
	return true;
}

static bool frame_md5(eap_frame_t *frame, fr_pair_t const *challenge, bool fail, uint8_t *packet)
{
	uint8_t digest[MD5_DIGEST_LENGTH];
	uint8_t input[1 + sizeof(fixture_password) - 1 + 16];
	uint8_t const *data = challenge->vp_octets;

	if ((challenge->vp_length != 22) || (data[0] != FR_EAP_CODE_REQUEST) ||
	    (data[4] != FR_EAP_METHOD_MD5) || (data[5] != 16)) return false;

	input[0] = data[1];
	memcpy(input + 1, fixture_password, sizeof(fixture_password) - 1);
	memcpy(input + 1 + sizeof(fixture_password) - 1, data + 6, 16);
	fr_md5_calc(digest, input, sizeof(input));
	if (fail) digest[0] ^= 0xff;

	packet[0] = FR_EAP_CODE_RESPONSE;
	packet[1] = data[1];
	packet[2] = 0;
	packet[3] = 22;
	packet[4] = FR_EAP_METHOD_MD5;
	packet[5] = 16;
	memcpy(packet + 6, digest, sizeof(digest));
	frame->eap = packet;
	frame->eap_len = 22;
	frame->chbind = NULL;
	frame->chbind_len = 0;
	return true;
}

static bool frame_gtc(eap_frame_t *frame, fr_pair_t const *challenge, bool fail, uint8_t *packet)
{
	uint8_t const *data = challenge->vp_octets;
	size_t length = sizeof(fixture_password) - 1;

	if ((challenge->vp_length < 5) || (data[0] != FR_EAP_CODE_REQUEST) ||
	    (data[4] != FR_EAP_METHOD_GTC)) return false;

	packet[0] = FR_EAP_CODE_RESPONSE;
	packet[1] = data[1];
	packet[2] = 0;
	packet[3] = 5 + length;
	packet[4] = FR_EAP_METHOD_GTC;
	memcpy(packet + 5, fixture_password, length);
	if (fail) packet[5] ^= 0xff;
	frame->eap = packet;
	frame->eap_len = packet[3];
	frame->chbind = NULL;
	frame->chbind_len = 0;
	return true;
}

static bool frame_mschapv2(eap_frame_t *frame, fr_pair_t const *challenge, bool fail, uint8_t *packet)
{
	uint8_t const *data = challenge->vp_octets;
	uint8_t peer[16] = { 0x42 };
	uint8_t hash[16], challenge_hash[8], response[24];
	size_t user_len = sizeof(fixture_user) - 1;
	size_t type_len = 5 + 49 + user_len;
	size_t eap_len = 5 + type_len;

	if ((challenge->vp_length < 5 + 5 + 16) || (data[0] != FR_EAP_CODE_REQUEST) ||
	    (data[4] != FR_EAP_METHOD_MSCHAPV2) || (data[5] != FR_EAP_MSCHAPV2_CHALLENGE)) return false;
	if (mschap_nt_password_hash(hash, fixture_password) < 0) return false;

	mschap_challenge_hash(challenge_hash, peer, data + 10, fixture_user, user_len);
	smbdes_mschap(hash, challenge_hash, response);
	if (fail) response[0] ^= 0xff;

	packet[0] = FR_EAP_CODE_RESPONSE;
	packet[1] = data[1];
	packet[2] = (uint8_t)(eap_len >> 8);
	packet[3] = (uint8_t)eap_len;
	packet[4] = FR_EAP_METHOD_MSCHAPV2;
	packet[5] = FR_EAP_MSCHAPV2_RESPONSE;
	packet[6] = data[6];
	packet[7] = (uint8_t)(type_len >> 8);
	packet[8] = (uint8_t)type_len;
	packet[9] = 49;
	memcpy(packet + 10, peer, sizeof(peer));
	memset(packet + 26, 0, 8);
	memcpy(packet + 34, response, sizeof(response));
	packet[58] = 0;
	memcpy(packet + 59, fixture_user, user_len);
	frame->eap = packet;
	frame->eap_len = eap_len;
	frame->chbind = NULL;
	frame->chbind_len = 0;
	return true;
}

static bool frame_mschapv2_ack(eap_frame_t *frame, fr_pair_t const *reply, uint8_t *packet)
{
	uint8_t const *data = reply->vp_octets;

	if ((reply->vp_length < 9) || (data[0] != FR_EAP_CODE_REQUEST) ||
	    (data[4] != FR_EAP_METHOD_MSCHAPV2) ||
	    ((data[5] != FR_EAP_MSCHAPV2_SUCCESS) && (data[5] != FR_EAP_MSCHAPV2_FAILURE))) return false;

	packet[0] = FR_EAP_CODE_RESPONSE;
	packet[1] = data[1];
	packet[2] = 0;
	packet[3] = 9;
	packet[4] = FR_EAP_METHOD_MSCHAPV2;
	packet[5] = data[5];
	packet[6] = data[6];
	packet[7] = 0;
	packet[8] = 4;
	frame->eap = packet;
	frame->eap_len = 9;
	frame->chbind = NULL;
	frame->chbind_len = 0;
	return true;
}

static void fuzz_remaining_frames(TALLOC_CTX *ctx, CONF_SECTION *server, uint8_t const *buf, size_t len,
				  fr_pair_t **state)
{
	uint8_t const *frame, *next, *end;
	eap_frame_t eap_frame;
	fr_pair_t *reply;

	frame = buf;
	end = buf + len;
	while (frame < end) {
		next = memmem(frame, end - frame, frame_delimiter, sizeof(frame_delimiter) - 1);
		eap_frame_parse(&eap_frame, frame, next ? (size_t)(next - frame) : (size_t)(end - frame));
		reply = conversation_step(ctx, server, &eap_frame, state);
		talloc_free(reply);

		if (!next) break;
		frame = next + sizeof(frame_delimiter) - 1;
	}
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	return rlm_eap_fuzzer_initialize(argc, argv);
}

int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len)
{
	static size_t const profiles[] = { 0, 2, 3 };
	TALLOC_CTX *ctx;
	fr_pair_t *state = NULL, *reply;
	eap_frame_t frame;
	uint8_t packet[128];
	bool fail;
	unsigned int method;
	CONF_SECTION *server;

	if (len < 1) return 0;
	if (!attr_eap_message) LLVMFuzzerInitialize(NULL, NULL);

	method = (buf[0] >> 1) % NUM_ELEMENTS(profiles);
	fail = (buf[0] & 1) != 0;
	server = server_cs[profiles[method]];
	ctx = talloc_init_const("fuzzer_rlm_eap_conversation");
	if (!ctx) return 0;

	frame_identity(&frame, packet);
	reply = conversation_step(ctx, server, &frame, &state);
	if (!reply) goto finish;

	switch (method) {
	case 0:
		if (!frame_md5(&frame, reply, fail, packet)) goto finish;
		break;
	case 1:
		if (!frame_gtc(&frame, reply, fail, packet)) goto finish;
		break;
	default:
		if (!frame_mschapv2(&frame, reply, fail, packet)) goto finish;
		break;
	}

	talloc_free(reply);
	reply = conversation_step(ctx, server, &frame, &state);
	if ((method == 2) && reply && frame_mschapv2_ack(&frame, reply, packet)) {
		talloc_free(reply);
		reply = conversation_step(ctx, server, &frame, &state);
	}
	talloc_free(reply);

	fuzz_remaining_frames(ctx, server, buf + 1, len - 1, &state);

finish:
	talloc_free(state);
	talloc_free(ctx);
	fr_strerror_clear();
	return 0;
}
