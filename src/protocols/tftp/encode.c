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
 * @file src/protocols/tftp/enoce.c
 * @brief Functions to encode TFTP packets.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2021 The FreeRADIUS server project.
 * @copyright 2021 Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/udp.h>

#include <freeradius-devel/io/test_point.h>

#include "tftp.h"
#include "attrs.h"

/*
 *  https://tools.ietf.org/html/rfc1350
 *
 *  Order of Headers
 *
 *                                                 2 bytes
 *   ----------------------------------------------------------
 *  |  Local Medium  |  Internet  |  Datagram  |  TFTP Opcode  |
 *   ----------------------------------------------------------
 *
 *  TFTP Formats
 *
 *  Type   Op #     Format without header
 *
 *         2 bytes    string   1 byte     string   1 byte
 *         -----------------------------------------------
 *  RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
 *  WRQ    -----------------------------------------------
 *          2 bytes    2 bytes       n bytes
 *         ---------------------------------
 *  DATA  | 03    |   Block #  |    Data    |
 *         ---------------------------------
 *          2 bytes    2 bytes
 *         -------------------
 *  ACK   | 04    |   Block #  |
 *         --------------------
 *         2 bytes  2 bytes        string    1 byte
 *         ----------------------------------------
 *  ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
 *         ----------------------------------------
 *
 *  Initial Connection Protocol for reading a file
 *
 *  1. Host  A  sends  a  "RRQ"  to  host  B  with  source= A's TID,
 *     destination= 69.
 *
 *  2. Host B sends a "DATA" (with block number= 1) to host  A  with
 *     source= B's TID, destination= A's TID.
 */
ssize_t fr_tftp_encode(fr_dbuff_t *dbuff, fr_pair_list_t *vps)
{
	fr_dbuff_t 	work_dbuff = FR_DBUFF_MAX(dbuff, FR_TFTP_BLOCK_MAX_SIZE);
	fr_pair_t 	*vp;
	uint16_t 	opcode;
	char const 	*buf;

	vp = fr_pair_find_by_da(vps, NULL, attr_tftp_opcode);
	if (!vp) {
		fr_strerror_printf("Cannot send TFTP packet without %s", attr_tftp_opcode->name);
		return -1;
	}

	opcode = vp->vp_uint16;
	fr_dbuff_in(&work_dbuff, opcode);

	switch (opcode) {
	case FR_OPCODE_VALUE_READ_REQUEST:
	case FR_OPCODE_VALUE_WRITE_REQUEST:
		/*
		 *  2 bytes     string    1 byte     string   1 byte   string    1 byte   string   1 byte
		 *  +------------------------------------------------------------------------------------+
		 *  | Opcode |  Filename  |   0  |    Mode    |   0  |  blksize  |  0  |  #blksize |  0  |
		 *  +------------------------------------------------------------------------------------+
		 *  Figure 5-1: RRQ/WRQ packet
		 */

		/* <Filename> */
		vp = fr_pair_find_by_da(vps, NULL, attr_tftp_filename);
		if (!vp) {
			fr_strerror_printf("Invalid TFTP packet without %s", attr_tftp_filename->name);
			return -1;
		}

		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_strvalue, vp->vp_length);
		fr_dbuff_in_bytes(&work_dbuff, '\0');

		/* <mode> */
		vp = fr_pair_find_by_da(vps, NULL, attr_tftp_mode);
		if (!vp) {
			fr_strerror_printf("Invalid TFTP packet without %s", attr_tftp_mode->name);
			return -1;
		}

		switch(vp->vp_uint16) {
		case FR_MODE_VALUE_ASCII: buf = "ascii"; break;
		case FR_MODE_VALUE_OCTET: buf = "octet"; break;
		default:
			fr_strerror_printf("Invalid %s value", attr_tftp_mode->name);
			return -1;
		}

		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, buf, 5);
		fr_dbuff_in_bytes(&work_dbuff, '\0');

		/* <blksize> is optional */
		vp = fr_pair_find_by_da(vps, NULL, attr_tftp_block_size);
		if (vp) {
			char tmp[5+1];                                   /* max: 65535 */

			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, "blksize", 7);
			fr_dbuff_in_bytes(&work_dbuff, '\0');

			snprintf(tmp, sizeof(tmp), "%d", vp->vp_uint16); /* #blksize */
			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, tmp, strlen(tmp));
			fr_dbuff_in_bytes(&work_dbuff, '\0');
		}

		break;

	case FR_OPCODE_VALUE_ACKNOWLEDGEMENT:
	case FR_OPCODE_VALUE_DATA:
		/**
		 * 2 bytes     2 bytes
		 * ---------------------
		 * | Opcode |   Block #  |
		 * ---------------------
		 * Figure 5-3: ACK packet
		 */

		/* <Block> */
		vp = fr_pair_find_by_da(vps, NULL, attr_tftp_block);
		if (!vp) {
			fr_strerror_printf("Invalid TFTP packet without %s", attr_tftp_block->name);
			return -1;
		}

		fr_dbuff_in(&work_dbuff, vp->vp_uint16);

		/*
		 *	From that point...
		 *
		 *  2 bytes     2 bytes      n bytes
		 *  ----------------------------------
		 *  | Opcode |   Block #  |   Data     |
		 *  ----------------------------------
		 *  Figure 5-2: DATA packet
		 */
		if (opcode != FR_OPCODE_VALUE_DATA) goto done;

		/* <Data> */
		vp = fr_pair_find_by_da(vps, NULL, attr_tftp_data);
		if (!vp) {
			fr_strerror_printf("Invalid TFTP packet without %s", attr_tftp_data->name);
			return -1;
		}

		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_octets, vp->vp_length);

		break;

	case FR_OPCODE_VALUE_ERROR:
	{
		/**
		 * 2 bytes     2 bytes      string    1 byte
		 * -----------------------------------------
		 * | Opcode |  ErrorCode |   ErrMsg   |   0  |
		 * -----------------------------------------
		 *
		 * Figure 5-4: ERROR packet
		 */
		uint16_t 	error_code;
		char const 	*error_msg;
		size_t 		error_msg_len;

		/* <ErroCode> */
		vp = fr_pair_find_by_da(vps, NULL, attr_tftp_error_code);
		if (!vp) {
			fr_strerror_printf("Invalid TFTP packet without %s", attr_tftp_error_code->name);
			return -1;
		}

		error_code = vp->vp_uint16;
		fr_dbuff_in(&work_dbuff, error_code);

		/* <ErrMsg> */
		vp = fr_pair_find_by_da(vps, NULL, attr_tftp_error_message);
		if (vp) {
			error_msg = vp->vp_strvalue;
			error_msg_len = vp->vp_length;
		} else {
			error_msg = fr_tftp_error_codes[error_code] ? fr_tftp_error_codes[error_code] : "Invalid ErrorCode";
			error_msg_len = strlen(error_msg);
		}

		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, error_msg, error_msg_len);
		fr_dbuff_in_bytes(&work_dbuff, '\0');
		break;
	}

	default:
		fr_strerror_printf("Invalid TFTP opcode %#04x", opcode);
		return -1;
	}

done:
	fr_dbuff_set(dbuff, &work_dbuff);

	return fr_dbuff_used(dbuff);
}

/**
 *	Used as the encoder ctx.
 */
typedef struct {
	int		nothing;
} fr_tftp_ctx_t;
/*
 *	Test points for protocol encode
 */
static ssize_t fr_tftp_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps, uint8_t *data, size_t data_len, UNUSED void *proto_ctx)
{
	return fr_tftp_encode(&FR_DBUFF_TMP(data, data_len), vps);
}

static int _encode_test_ctx(UNUSED fr_tftp_ctx_t *proto_ctx)
{
	fr_tftp_free();

	return 0;
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_tftp_ctx_t *test_ctx;

	if (fr_tftp_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_tftp_ctx_t);
	if (!test_ctx) return -1;

	talloc_set_destructor(test_ctx, _encode_test_ctx);

	*out = test_ctx;

	return 0;
}

/*
 *	Test points
 */
extern fr_test_point_proto_encode_t tftp_tp_encode_proto;
fr_test_point_proto_encode_t tftp_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_tftp_encode_proto
};
