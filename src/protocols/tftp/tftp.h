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
 * @file src/protocols/tftp/tftp.h
 * @brief Functions to encode/decode TFTP packets.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

RCSIDH(tftp_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/protocol/tftp/freeradius.internal.h>
#include <freeradius-devel/protocol/tftp/rfc1350.h>

#define FR_TFTP_MAX_CODE				(FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND+1)
#define FR_TFTP_MAX_ERROR_CODE				(FR_TFTP_ERROR_CODE_VALUE_NO_SUCH_USER+1)
#define FR_TFTP_HDR_LEN				(4)	/* at least: 2-bytes opcode + 2-bytes */

/*
 *  2. Overview of the Protocol
 *
 *  Any transfer begins with a request to read or write a file, which
 *  also serves to request a connection.  If the server grants the
 *  request, the connection is opened and the file is sent in fixed
 *  length blocks of 512 bytes.  Each data packet contains one block of
 *  data, and must be acknowledged by an acknowledgment packet before the
 *  next packet can be sent.  A data packet of less than 512 bytes
 *  signals termination of a transfer.  If a packet gets lost in the
 *  network, the intended recipient will timeout and may retransmit his
 *  last packet (which may be data or an acknowledgment), thus causing
 *  the sender of the lost packet to retransmit that lost packet.  The
 *  sender has to keep just one packet on hand for retransmission, since
 *  the lock step acknowledgment guarantees that all older packets have
 *  been received.  Notice that both machines involved in a transfer are
 *  considered senders and receivers.  One sends data and receives
 *  acknowledgments, the other sends acknowledgments and receives data.
 */
#define FR_TFTP_DEFAULT_BLOCK_SIZE			1024

/*
 *	As described in https://tools.ietf.org/html/rfc2348
 *
 *  The number of octets in a block, specified in ASCII.  Valid
 *  values range between "8" and "65464" octets, inclusive.  The
 *  blocksize refers to the number of data octets; it does not
 *  include the four octets of TFTP header.
 */
#define FR_TFTP_BLOCK_MIN_SIZE				8
#define FR_TFTP_BLOCK_MAX_SIZE				65464

/*
 * The original protocol has a transfer file size limit of 512 bytes/block x 65535 blocks = 32 MB.
 * In 1998 this limit was extended to 65535 bytes/block x 65535 blocks = 4 GB
 * by TFTP Blocksize Option RFC 2348.
 */
#define FR_TFTP_MAX_FILESIZE				(FR_TFTP_BLOCK_MAX_SIZE * FR_TFTP_BLOCK_MAX_SIZE)

/* tftp.c */
int fr_tftp_decode(TALLOC_CTX *ctx, uint8_t const *data, size_t data_len, fr_pair_t **vps) CC_HINT(nonnull(2,4));

/* base.c */
extern char const	*fr_tftp_codes[FR_TFTP_MAX_CODE];
extern char const 	*fr_tftp_error_codes[FR_TFTP_MAX_ERROR_CODE];

int fr_tftp_init(void);
void fr_tftp_free(void);

#ifdef __cplusplus
}
#endif
