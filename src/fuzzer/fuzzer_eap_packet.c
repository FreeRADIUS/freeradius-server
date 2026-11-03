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
 * @file src/fuzzer/fuzzer_eap_packet.c
 * @brief Fuzz EAP-Message reconstruction after RADIUS decoding.
 *
 * A supplicant controls the EAP packet carried by RADIUS EAP-Message.  The
 * RADIUS decoder concatenates EAP-Message attributes before rlm_eap passes
 * that resulting attribute to eap_packet_from_vp().  This harness constructs
 * that decoded attribute, so the fuzzer controls exactly the EAP packet while
 * the pair-list and dictionary preconditions remain valid.
 */
RCSID("$Id$")

#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/fuzzer/common.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/util/strerror.h>

static fr_dict_attr_t const	*attr_eap_message;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	fr_dict_t const	*dict_radius;

	if (fuzzer_common_init(argc, argv, false) < 0) fr_exit_now(EXIT_FAILURE);

	if (eap_base_init() < 0) {
		fr_perror("fuzzer_eap_packet: failed loading EAP dictionaries");
		fr_exit_now(EXIT_FAILURE);
	}

	dict_radius = fr_dict_by_protocol_name("radius");
	if (!dict_radius) {
		fr_perror("fuzzer_eap_packet: RADIUS dictionary is not loaded");
		fr_exit_now(EXIT_FAILURE);
	}

	attr_eap_message = fr_dict_attr_by_name(NULL, fr_dict_root(dict_radius), "EAP-Message");
	if (!attr_eap_message) {
		fr_perror("fuzzer_eap_packet: EAP-Message attribute is not defined");
		fr_exit_now(EXIT_FAILURE);
	}

	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
	TALLOC_CTX		*ctx;
	fr_pair_list_t		vps;
	fr_pair_t		*vp;
	eap_packet_raw_t	*packet;

	if (!attr_eap_message) LLVMFuzzerInitialize(NULL, NULL);

	if (len > 0xFFFF) {
		// EAP length is u16 encoded
		len = 0xFFFF;
	}
	ctx = talloc_init_const("fuzzer_eap_packet");
	if (!ctx) return 0;

	fr_pair_list_init(&vps);

	vp = fr_pair_afrom_da(ctx, attr_eap_message);
	if (!vp) goto cleanup;

	if (fr_pair_value_memdup(vp, buf, len, false) < 0) goto cleanup;
	fr_pair_append(&vps, vp);

	packet = eap_packet_from_vp(ctx, &vps);
	talloc_free(packet);

cleanup:
	talloc_free(ctx);
	fr_strerror_clear();

	return 0;
}
