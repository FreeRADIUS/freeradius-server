/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file protocols/radius/bio.c
 * @brief Functions to support RADIUS bio handlers
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/radius/bio.h>

/** Callback for RADIUS packet verification.
 *
 */
fr_bio_verify_action_t fr_radius_bio_verify(UNUSED fr_bio_t *bio, void *verify_ctx, UNUSED void *packet_ctx, const void *data, size_t *size)
{
	fr_radius_decode_fail_t	failure;
	size_t		in_buffer = *size;
	fr_radius_bio_verify_t *uctx = verify_ctx;
	uint8_t const	*hdr = data;
	size_t		want;

	if (in_buffer < 4) {
		*size = RADIUS_HEADER_LENGTH;
		return FR_BIO_VERIFY_WANT_MORE;
	}

	want = fr_nbo_to_uint16(hdr + 2);
	if (uctx->max_packet_size && (want > uctx->max_packet_size)) {
		return FR_BIO_VERIFY_ERROR_CLOSE;
	}

	/*
	 *	See if we need to discard the packet.
	 */
	if (!fr_radius_ok(data, size, uctx->max_attributes, uctx->require_message_authenticator, &failure)) {
		if (failure == FR_RADIUS_FAIL_UNKNOWN_PACKET_CODE) return FR_BIO_VERIFY_DISCARD;

		return FR_BIO_VERIFY_ERROR_CLOSE;
	}

	if (!uctx->allowed[hdr[0]]) return FR_BIO_VERIFY_DISCARD;

	/*
	 *	On input, *size is how much data we have.  On output, *size is how much data we want.
	 */
	return (in_buffer >= *size) ? FR_BIO_VERIFY_OK : FR_BIO_VERIFY_WANT_MORE;
}

/** And verify a datagram packet.
 *
 */
fr_bio_verify_action_t fr_radius_bio_verify_datagram(UNUSED fr_bio_t *bio, void *verify_ctx, UNUSED void *packet_ctx, const void *data, size_t *size)
{
	fr_radius_decode_fail_t	failure;
	size_t		in_buffer = *size;
	fr_radius_bio_verify_t *uctx = verify_ctx;
	uint8_t const	*hdr = data;
	size_t		want;

	if (in_buffer < RADIUS_HEADER_LENGTH) return FR_BIO_VERIFY_DISCARD;

	want = fr_nbo_to_uint16(hdr + 2);
	if (uctx->max_packet_size && (want > uctx->max_packet_size)) {
		return FR_BIO_VERIFY_DISCARD;
	}

	/*
	 *	See if we need to discard the packet.
	 *
	 *	@todo - move the "allowed" list to this function
	 */
	if (!fr_radius_ok(data, size, uctx->max_attributes, uctx->require_message_authenticator, &failure)) {
		return FR_BIO_VERIFY_DISCARD;
	}

	if (!uctx->allowed[hdr[0]]) return FR_BIO_VERIFY_DISCARD;

	/*
	 *	On input, *size is how much data we have.  On output, *size is how much data we want.
	 */
	return (in_buffer >= *size) ? FR_BIO_VERIFY_OK : FR_BIO_VERIFY_DISCARD;
}
