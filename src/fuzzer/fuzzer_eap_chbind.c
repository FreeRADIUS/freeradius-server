/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

/**
 * @file src/fuzzer/fuzzer_eap_chbind.c
 * @brief Fuzz EAP channel-binding reconstruction and processing.
 *
 * Byte 0 selects where the attributes are installed: bit 0 set uses the
 * nested UKERNA hierarchy produced by RADIUS decoding, which
 * eap_chbind_vp2packet() currently does not find because it only searches
 * the top level of the list; bit 0 clear installs them at the top level so
 * packet reconstruction and processing are reachable.  The remaining bytes
 * are one or more channel-binding attribute fragments separated by "FUZZ".
 */
RCSID("$Id$")

#include <freeradius-devel/eap/chbind.h>
#include <freeradius-devel/fuzzer/common.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/strerror.h>

static fr_dict_attr_t const	*attr_chbind;
static uint8_t const		frame_delimiter[] = "FUZZ";

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fr_dict_t const *dict_radius;
	fr_dict_attr_t const *attr_vendor_specific, *attr_ukerna;

	default_log.dst = L_DST_STDERR;
	default_log.fd = STDERR_FILENO;
	default_log.suppress_secrets = true;

	if (fuzzer_common_init(argc, argv, false) < 0) {
		fr_perror("fuzzer_eap_chbind: failed initializing common state");
		fr_exit_now(EXIT_FAILURE);
	}
	if (log_global_init(&default_log, false) < 0) {
		fr_perror("fuzzer_eap_chbind: failed initializing logging");
		fr_exit_now(EXIT_FAILURE);
	}
	default_log.dst = L_DST_NULL;
	if (request_global_init() < 0) {
		fr_perror("fuzzer_eap_chbind: failed initializing requests");
		fr_exit_now(EXIT_FAILURE);
	}
	if (eap_base_init() < 0) {
		fr_perror("fuzzer_eap_chbind: failed loading EAP dictionaries");
		fr_exit_now(EXIT_FAILURE);
	}

	dict_radius = fr_dict_by_protocol_name("radius");
	if (!dict_radius) {
		fr_perror("fuzzer_eap_chbind: RADIUS dictionary is not loaded");
		fr_exit_now(EXIT_FAILURE);
	}
	attr_vendor_specific = fr_dict_attr_by_name(NULL, fr_dict_root(dict_radius), "Vendor-Specific");
	if (!attr_vendor_specific) {
		fr_perror("fuzzer_eap_chbind: Vendor-Specific attribute is not defined");
		fr_exit_now(EXIT_FAILURE);
	}
	attr_ukerna = fr_dict_vendor_da_by_num(attr_vendor_specific, 25622);
	if (!attr_ukerna) {
		fr_perror("fuzzer_eap_chbind: UKERNA vendor is not defined");
		fr_exit_now(EXIT_FAILURE);
	}
	attr_chbind = fr_dict_attr_child_by_num(attr_ukerna, 135);
	if (!attr_chbind) {
		fr_perror("fuzzer_eap_chbind: EAP-Channel-Binding-Message is not defined");
		fr_exit_now(EXIT_FAILURE);
	}

	return 0;
}

int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len)
{
	TALLOC_CTX *ctx;
	request_t *request;
	CHBIND_REQ *chbind_req;
	chbind_packet_t *packet;
	fr_pair_t *vp;
	uint8_t const *frame, *next, *end;
	bool nested;

	if (!attr_chbind) LLVMFuzzerInitialize(NULL, NULL);
	if (len < 2) return 0;
	nested = buf[0] & 1;
	buf++;
	len--;

	ctx = talloc_init_const("fuzzer_eap_chbind");
	if (!ctx) return 0;
	request = request_local_alloc_internal(ctx, NULL);
	if (!request) goto cleanup;
	request->packet = fr_packet_alloc(request, false);
	if (!request->packet) goto cleanup;
	request->packet->code = FR_RADIUS_CODE_ACCESS_REQUEST;
	request->packet->timestamp = fr_time();

	frame = buf;
	end = buf + len;
	while (frame < end) {
		next = memmem(frame, end - frame, frame_delimiter, sizeof(frame_delimiter) - 1);
		if (nested) {
			vp = fr_pair_afrom_da_nested(request->request_ctx, &request->request_pairs, attr_chbind);
		} else {
			vp = fr_pair_afrom_da(request->request_ctx, attr_chbind);
			if (vp) fr_pair_append(&request->request_pairs, vp);
		}
		if (!vp) goto cleanup;
		if (fr_pair_value_memdup(vp, frame, next ? (size_t)(next - frame) : (size_t)(end - frame), false) < 0) {
			talloc_free(vp);
			goto cleanup;
		}

		if (!next) break;
		frame = next + sizeof(frame_delimiter) - 1;
	}

	packet = eap_chbind_vp2packet(ctx, &request->request_pairs);
	if (!packet) goto cleanup;
	vp = eap_chbind_packet2vp(ctx, packet);
	talloc_free(vp);

	chbind_req = talloc_zero(ctx, CHBIND_REQ);
	if (!chbind_req) goto cleanup;
	chbind_req->request = packet;
	(void)chbind_process(request, chbind_req);

cleanup:
	talloc_free(ctx);
	fr_strerror_clear();
	return 0;
}
