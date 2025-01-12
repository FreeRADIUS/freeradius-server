#pragma once
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
 * $Id$
 * @file lib/bio/mem.h
 * @brief Binary IO abstractions for memory buffers
 *
 * Allow reads and writes from memory buffers
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_mem_h, "$Id$")

/** Status returned by the verification callback.
 *
 */
typedef enum {
	FR_BIO_VERIFY_OK = 0,		//!< packet is OK
	FR_BIO_VERIFY_DISCARD,		//!< the packet should be discarded
	FR_BIO_VERIFY_WANT_MORE,	//!< not enough data for one packet
	FR_BIO_VERIFY_ERROR_CLOSE,	//!< fatal error, the bio should be closed.
} fr_bio_verify_action_t;

/** Verifies the packet
 *
 *  If the packet is a dup, then this function can return DISCARD, or
 *  update the packet_ctx to say "dup", and then return OK.
 *
 *  @param	bio	   the bio to read
 *  @param	verify_ctx data specific for verifying
 *  @param	packet_ctx as passed in to fr_bio_read()
 *  @param	buffer	   pointer to the raw data
 *  @param[in,out] size	   in: size of data in the buffer.  out: size of the packet to return, or data to discard.
 *  @return		   action to take
 */
typedef fr_bio_verify_action_t (*fr_bio_verify_t)(fr_bio_t *bio,  void *verify_ctx, void *packet_ctx, const void *buffer, size_t *size);

fr_bio_t	*fr_bio_mem_alloc(TALLOC_CTX *ctx, size_t read_size, size_t write_size, fr_bio_t *next) CC_HINT(nonnull);

fr_bio_t	*fr_bio_mem_source_alloc(TALLOC_CTX *ctx, size_t buffer_size, fr_bio_t *next) CC_HINT(nonnull);

fr_bio_t	*fr_bio_mem_sink_alloc(TALLOC_CTX *ctx, size_t buffer_size) CC_HINT(nonnull);

uint8_t const	*fr_bio_mem_read_peek(fr_bio_t *bio, size_t *size) CC_HINT(nonnull);

void		fr_bio_mem_read_discard(fr_bio_t *bio, size_t size) CC_HINT(nonnull);

int		fr_bio_mem_set_verify(fr_bio_t *bio, fr_bio_verify_t verify, void *verify_ctx, bool datagram) CC_HINT(nonnull);

int		fr_bio_mem_write_resume(fr_bio_t *bio) CC_HINT(nonnull);

int		fr_bio_mem_write_pause(fr_bio_t *bio) CC_HINT(nonnull);
