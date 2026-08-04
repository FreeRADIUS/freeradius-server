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
 * @file src/protocols/tftp/decode.c
 * @brief Functions to decode TFTP packets.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2021 The FreeRADIUS server project.
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

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
int fr_tftp_decode(TALLOC_CTX *ctx, fr_pair_list_t *out, uint8_t const *data, size_t data_len)
{
	uint8_t const  	*q, *p, *end;
	uint16_t 	opcode;
	fr_pair_t	*vp = NULL;

	if (data_len == 0) return -1;

	if (data_len < FR_TFTP_HDR_LEN) {
		fr_strerror_printf("TFTP packet is too small. (%zu < %d)", data_len, FR_TFTP_HDR_LEN);
		return -1;
	}

	p = data;
	end = (data + data_len);

	/*
	 *	Two bytes of Opcode
	 */
	opcode = fr_nbo_to_uint16(p);
	if (!opcode || (opcode > 5)) {
		fr_strerror_printf("Invalid TFTP opcode %#04x", opcode);
		return -1;
	}

	vp = fr_pair_afrom_da(ctx, attr_tftp_opcode);
	if (!vp) return -1;

	vp->vp_uint16 = opcode;
	fr_pair_append(out, vp);
	p += 2;

	/*
	 *	Parse the data.
	 */
	switch (opcode) {
	case FR_OPCODE_VALUE_READ_REQUEST:
	case FR_OPCODE_VALUE_WRITE_REQUEST:
		/*
		 *	Read / write requests end with a NUL byte.
		 */
		if (*(end - 1) != '\0') {
			fr_strerror_const("trailing NUL character is missing");
			return -1;
		}

		/*
		 *   2 bytes     string    1 byte     string   1 byte   string    1 byte   string   1 byte
		 *  +------------------------------------------------------------------------------------+
		 *  | Opcode |  Filename  |   0  |    Mode    |   0  |  blksize  |  0  |  #blksize |  0  |
		 *  +------------------------------------------------------------------------------------+
		 *  Figure 5-1: RRQ/WRQ packet
		 */

		/*
		 *	Find the end of the filename.
		 */
		q = memchr(p, '\0', (end - p));
		if (!q || (q == (end - 1))) {
		missing_mode:
			fr_strerror_const("'mode' field is missing");
			return -1;
		}

		/*
		 *	Sanity check the filename
		 */
		for (q = p; *q != '\0'; q++) {
			if (*q < ' ') {
				fr_strerror_const("Invalid control character in filename");
				return -1;
			}
		}

		vp = fr_pair_afrom_da(ctx, attr_tftp_filename);
		if (!vp) return -1;

		fr_pair_value_bstrndup(vp, (const char *) p, (q - p), true);
		fr_pair_append(out, vp);
		p = q + 1;

		if (p == end) goto missing_mode;

		/*
		 *	ascii + NUL
		 *	octet + NUL
		 *	netascii + NUL
		 */
		q = memchr(p, '\0', (end - p));
		if (!q) goto missing_mode;

		vp = fr_pair_afrom_da(ctx, attr_tftp_mode);
		if (!vp) return -1;

		/* (netascii || ascii || octet) + \0 */
		if ((q - p) == 5 && !memcmp(p, "octet", 5)) {
			p += 6;
			vp->vp_uint8 = FR_MODE_VALUE_OCTET;

		} else if ((q - p) == 5 && !memcmp(p, "ascii", 5)) {
			p += 6;
			vp->vp_uint8 = FR_MODE_VALUE_ASCII;

		} else if ((q - p) == 8 && !memcmp(p, "netascii", 8)) {
			p += 9;
			vp->vp_uint8 = FR_MODE_VALUE_ASCII;

		} else {
			fr_strerror_printf("Invalid mode '%.*s'", (int) (q - p), p);
			talloc_free(vp);
			return -1;
		}

		fr_pair_append(out, vp);
		if (p >= end) goto done;

		/*
		 * 	"blksize" is optional.
		 *
		 *	If it exists, then it's at least
		 *
		 *	blksize | \0 | #blksize | \0 |
		 */
		if ((end - p) < 10) {
		invalid_option:
			fr_strerror_const("Invalid TFTP option");
			return -1;
		}

		if (!memcmp(p, "blksize\0", 8)) {
			char *p_end = NULL;
			long blksize;

			p += 8;

			if ((p >= end) || ((end - p) < 1) || ((end - p) > 6)) goto invalid_option;

			vp = fr_pair_afrom_da(ctx, attr_tftp_block_size);
			if (!vp) return -1;

			blksize = strtol((const char *)p, &p_end, 10);

			if (((p == (const uint8_t *)p_end)) ||
			    (blksize < FR_TFTP_BLOCK_MIN_SIZE) ||
			    (blksize > FR_TFTP_BLOCK_MAX_SIZE)) {
				fr_strerror_printf("Invalid Block-Size %ld value", blksize);
				talloc_free(vp);
				return -1;
			}

			vp->vp_uint16 = (uint16_t)blksize;
			fr_pair_append(out, vp);
		}

		break;

	case FR_OPCODE_VALUE_ACKNOWLEDGEMENT:
	case FR_OPCODE_VALUE_DATA:
		/**
		 *  2 bytes     2 bytes
		 *  ---------------------
		 *  | Opcode |   Block #  |
		 *  ---------------------
		 *  Figure 5-3: ACK packet
		 */

		vp = fr_pair_afrom_da(ctx, attr_tftp_block);
		if (!vp) return -1;

		vp->vp_uint16 = fr_nbo_to_uint16(p);

		fr_pair_append(out, vp);

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

		if ((p + 2) > end) {
			fr_strerror_const("Malformed Acknowledgment packet");
			return -1;
		}

		p += 2;

		vp = fr_pair_afrom_da(ctx, attr_tftp_data);
		if (!vp) return -1;

		fr_pair_value_memdup(vp, p, (end - p), true);
		fr_pair_append(out, vp);
		break;

	case FR_OPCODE_VALUE_ERROR:
		/**
		 *  2 bytes     2 bytes      string    1 byte
		 *  -----------------------------------------
		 *  | Opcode |  ErrorCode |   ErrMsg   |   0  |
		 *  -----------------------------------------
		 *
		 *  Figure 5-4: ERROR packet
		 */

		/*
		 *	Error packets end with a NUL byte.
		 */
		if (*(end - 1) != '\0') {
			fr_strerror_const("trailing NUL character is missing");
			return -1;
		}

		if ((p + 2) >= end) {
			fr_strerror_const("Malformed Error packet");
			return -1;
		}

		vp = fr_pair_afrom_da(ctx, attr_tftp_error_code);
		if (!vp) return -1;

		vp->vp_uint16 = fr_nbo_to_uint16(p);
		fr_pair_append(out, vp);

		p  += 2; /* <ErrorCode> */
		q   = memchr(p, '\0', (end - p));
		if (!q || q[0] != '\0') {
			fr_strerror_const("Missing Error-Code");
			return -1;
		}

		vp = fr_pair_afrom_da(ctx, attr_tftp_error_message);
		if (!vp) return -1;

		fr_pair_value_bstrndup(vp, (char const *)p, (q - p), true);
		fr_pair_append(out, vp);
		break;

	default:
		fr_strerror_printf("Invalid TFTP opcode %#04x", opcode);
		return -1;
	}

done:
	return data_len;
}

/**
 *	Used as the decoder ctx.
 */
typedef struct {
	int		nothing;
} fr_tftp_ctx_t;

/*
 *	Test points for protocol decode
 */
static ssize_t fr_tftp_decode_proto(TALLOC_CTX *ctx, fr_pair_list_t *out,
				    uint8_t const *data, size_t data_len, UNUSED void *proto_ctx)
{
	return fr_tftp_decode(ctx, out, data, data_len);
}

static int _decode_test_ctx(UNUSED fr_tftp_ctx_t *proto_ctx)
{
	fr_tftp_global_free();

	return 0;
}

static int decode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict,
			   UNUSED fr_dict_attr_t const *root_da)
{
	fr_tftp_ctx_t *test_ctx;

	if (fr_tftp_global_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_tftp_ctx_t);
	if (!test_ctx) return -1;

	talloc_set_destructor(test_ctx, _decode_test_ctx);

	*out = test_ctx;

	return 0;
}

extern fr_test_point_proto_decode_t tftp_tp_decode_proto;
fr_test_point_proto_decode_t tftp_tp_decode_proto = {
	.test_ctx	= decode_test_ctx,
	.func		= fr_tftp_decode_proto
};
