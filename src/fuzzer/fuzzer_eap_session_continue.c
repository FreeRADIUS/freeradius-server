/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 * @file src/fuzzer/fuzzer_eap_session_continue.c
 * @brief Fuzz EAP session creation and continuation.
 *
 * The fuzzer controls EAP responses.  The first byte selects the
 * server's configured EAP method, allowing the session lifecycle to be
 * exercised for every supported method number.  Each response goes through
 * eap_packet_from_vp() and eap_session_continue(), with freeze/thaw between
 * rounds.
 *
 * Input layout:
 *   byte[0]             Server-selected EAP method (or EAP-MD5 if invalid)
 *   byte[1..]           Raw EAP responses delimited by "FUZZ"
 *
 * The first packet must be an EAP-Response/Identity to start a session.
 */
RCSID("$Id$")

#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/fuzzer/common.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/strerror.h>

static fr_dict_attr_t const	*attr_eap_message;
static int const		eap_instance;
static uint8_t const		frame_delimiter[] = "FUZZ";

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

static eap_packet_raw_t *eap_packet_from_bytes(TALLOC_CTX *ctx, request_t *request,
						uint8_t const *data, size_t len)
{
	fr_pair_t *vp;

	fr_pair_delete_by_da(&request->request_pairs, attr_eap_message);

	vp = fr_pair_afrom_da(request->request_ctx, attr_eap_message);
	if (!vp) return NULL;

	if (fr_pair_value_memdup(vp, data, len, false) < 0) {
		talloc_free(vp);
		return NULL;
	}
	fr_pair_append(&request->request_pairs, vp);

	return eap_packet_from_vp(ctx, &request->request_pairs);
}

static void eap_session_next_round(eap_session_t *eap_session)
{
	talloc_free(eap_session->prev_round);
	eap_session->prev_round = eap_session->this_round;
	eap_session->this_round = NULL;
	eap_session_freeze(&eap_session);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fr_dict_t const *dict_radius;

	default_log.dst = L_DST_STDERR;
	default_log.fd = STDERR_FILENO;
	default_log.print_level = true;
	default_log.suppress_secrets = true;

	if (fuzzer_common_init(argc, argv, false) < 0) fr_exit_now(EXIT_FAILURE);

	if (log_global_init(&default_log, false) < 0) {
		fr_perror("fuzzer_eap_session_continue: failed initializing logging");
		fr_exit_now(EXIT_FAILURE);
	}

	default_log.dst = L_DST_NULL;

	if (request_global_init() < 0) {
		fr_perror("fuzzer_eap_session_continue: failed initializing requests");
		fr_exit_now(EXIT_FAILURE);
	}

	if (eap_base_init() < 0) {
		fr_perror("fuzzer_eap_session_continue: failed loading EAP dictionaries");
		fr_exit_now(EXIT_FAILURE);
	}

	dict_radius = fr_dict_by_protocol_name("radius");
	if (!dict_radius) {
		fr_perror("fuzzer_eap_session_continue: RADIUS dictionary is not loaded");
		fr_exit_now(EXIT_FAILURE);
	}

	attr_eap_message = fr_dict_attr_by_name(NULL, fr_dict_root(dict_radius), "EAP-Message");
	if (!attr_eap_message) {
		fr_perror("fuzzer_eap_session_continue: EAP-Message attribute is not defined");
		fr_exit_now(EXIT_FAILURE);
	}

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	TALLOC_CTX		*ctx;
	request_t		*request;
	eap_session_t		*eap_session = NULL;
	eap_packet_raw_t	*packet;
	eap_type_t		server_method;
	uint8_t const		*frame, *next, *end;
	unsigned int		i;

	if (!attr_eap_message) LLVMFuzzerInitialize(NULL, NULL);
	if (len < 2) return 0;

	ctx = talloc_init_const("fuzzer_eap_session_continue");
	if (!ctx) return 0;

	request = request_local_alloc_internal(ctx, NULL);
	if (!request) goto cleanup;

	request->packet = fr_packet_alloc(request, false);
	if (!request->packet) goto cleanup;
	request->packet->timestamp = fr_time();

	server_method = (eap_type_t)buf[0];
	if ((server_method < FR_EAP_METHOD_IDENTITY) || (server_method >= FR_EAP_METHOD_MAX)) {
		server_method = FR_EAP_METHOD_MD5;
	}

	frame = buf + 1;
	end = buf + len;
	for (i = 0; (frame < end); i++) {
		next = memmem(frame, end - frame, frame_delimiter, sizeof(frame_delimiter) - 1);
		packet = eap_packet_from_bytes(ctx, request, frame, next ? (size_t)(next - frame) : (size_t)(end - frame));
		if (!packet) goto next_frame;

		request->packet->timestamp = fr_time();
		eap_session = eap_session_continue(&eap_instance, &packet, request);
		if (!eap_session) break;

		if (i == 0) eap_session->type = server_method;
		eap_session_next_round(eap_session);

	next_frame:
		if (!next) break;
		frame = next + sizeof(frame_delimiter) - 1;
	}

	eap_session = eap_session_thaw(request);
	if (eap_session) eap_session_destroy(&eap_session);

cleanup:
	talloc_free(ctx);
	fr_strerror_clear();

	return 0;
}
