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
 * @file protocols/tacacs/encode.c
 * @brief Low-Level TACACS+ encode functions
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/protocol/tacacs/tacacs.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/struct.h>

#include "tacacs.h"
#include "attrs.h"

int fr_tacacs_code_to_packet(fr_tacacs_packet_t *pkt, uint32_t code)
{
	switch (code) {
	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_START:
		pkt->hdr.type = FR_TAC_PLUS_AUTHEN;
		pkt->hdr.seq_no = 1;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_PASS:
		pkt->hdr.type = FR_TAC_PLUS_AUTHEN;
		pkt->authen_reply.status = FR_TAC_PLUS_AUTHEN_STATUS_PASS;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_FAIL:
		pkt->hdr.type = FR_TAC_PLUS_AUTHEN;
		pkt->authen_reply.status = FR_TAC_PLUS_AUTHEN_STATUS_FAIL;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETDATA:
		pkt->hdr.type = FR_TAC_PLUS_AUTHEN;
		pkt->authen_reply.status = FR_TAC_PLUS_AUTHEN_STATUS_GETDATA;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETUSER:
		pkt->hdr.type = FR_TAC_PLUS_AUTHEN;
		pkt->authen_reply.status = FR_TAC_PLUS_AUTHEN_STATUS_GETUSER;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_GETPASS:
		pkt->hdr.type = FR_TAC_PLUS_AUTHEN;
		pkt->authen_reply.status = FR_TAC_PLUS_AUTHEN_STATUS_GETPASS;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_RESTART:
		pkt->hdr.type = FR_TAC_PLUS_AUTHEN;
		pkt->authen_reply.status = FR_TAC_PLUS_AUTHEN_STATUS_RESTART;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_ERROR:
		pkt->hdr.type = FR_TAC_PLUS_AUTHEN;
		pkt->authen_reply.status = FR_TAC_PLUS_AUTHEN_STATUS_ERROR;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE:
		pkt->hdr.type = FR_TAC_PLUS_AUTHEN;
		pkt->authen_cont.flags = FR_TAC_PLUS_CONTINUE_FLAG_UNSET;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE_ABORT:
		pkt->hdr.type = FR_TAC_PLUS_AUTHEN;
		pkt->authen_cont.flags = FR_TAC_PLUS_CONTINUE_FLAG_ABORT;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHORIZATION_REQUEST:
		pkt->hdr.type = FR_TAC_PLUS_AUTHOR;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHORIZATION_PASS_ADD:
		pkt->hdr.type = FR_TAC_PLUS_AUTHOR;
		pkt->author_reply.status = FR_TAC_PLUS_AUTHOR_STATUS_PASS_ADD;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHORIZATION_PASS_REPLACE:
		pkt->hdr.type = FR_TAC_PLUS_AUTHOR;
		pkt->author_reply.status = FR_TAC_PLUS_AUTHOR_STATUS_PASS_REPL;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHORIZATION_FAIL:
		pkt->hdr.type = FR_TAC_PLUS_AUTHOR;
		pkt->author_reply.status = FR_TAC_PLUS_AUTHOR_STATUS_FAIL;
		break;

	case FR_PACKET_TYPE_VALUE_ACCOUNTING_REQUEST:
		pkt->hdr.type = FR_TAC_PLUS_ACCT;
		break;

	case FR_PACKET_TYPE_VALUE_ACCOUNTING_SUCCESS:
		pkt->hdr.type = FR_TAC_PLUS_ACCT;
		pkt->acct_reply.status = FR_TAC_PLUS_ACCT_STATUS_SUCCESS;
		break;

	case FR_PACKET_TYPE_VALUE_ACCOUNTING_ERROR:
		pkt->hdr.type = FR_TAC_PLUS_ACCT;
		pkt->acct_reply.status = FR_TAC_PLUS_ACCT_STATUS_ERROR;
		break;

	default:
		fr_strerror_const("Invalid TACACS+ packet type");
		return -1;
	}

	return 0;
}

/**
 *	Encode a TACACS+ 'arg_N' fields.
 */
static uint8_t tacacs_encode_body_arg_cnt(fr_pair_list_t *vps, fr_dict_attr_t const *da)
{
	int		arg_cnt = 0;
	fr_pair_t	*vp;

	for (vp = fr_pair_list_head(vps);
	     vp;
	     vp = fr_pair_list_next(vps, vp)) {
		if (arg_cnt == 255) break;

		if (vp->da->flags.internal) continue;

		if (vp->da == attr_tacacs_packet) continue;

		/*
		 *	Argument-List = "foo=bar"
		 */
		if (vp->da == da) {
			if (vp->vp_length > 0xff) continue;
			arg_cnt++;
			continue;
		}

		fr_assert(fr_dict_by_da(vp->da) == dict_tacacs);

		/*
		 *	RFC 8907 attributes.
		 */
		if (vp->da->parent->flags.is_root) {
			arg_cnt++;
			continue;
		}

		/*
		 *	Recurse into children.
		 */
		if (vp->vp_type == FR_TYPE_VENDOR) {
			arg_cnt += tacacs_encode_body_arg_cnt(&vp->vp_group, NULL);
			continue;
		}

		if (vp->da->parent->type != FR_TYPE_VENDOR) continue;

		arg_cnt++;
	}

	return arg_cnt;
}

static ssize_t tacacs_encode_body_arg_n(fr_dbuff_t *dbuff, uint8_t arg_cnt, uint8_t *arg_len, fr_pair_list_t *vps, fr_dict_attr_t const *da)
{
	fr_pair_t   *vp;
	uint8_t     i = 0;
	fr_dbuff_t  work_dbuff = FR_DBUFF(dbuff);

	for (vp = fr_pair_list_head(vps);
	     vp;
	     vp = fr_pair_list_next(vps, vp)) {
		int len;

		if (i == 255) break;
		if (i > arg_cnt) break;

		if (vp->da->flags.internal) continue;

		if (vp->da == attr_tacacs_packet) continue;

		/*
		 *	Argument-List = "foo=bar"
		 */
		if (vp->da == da) {
			if (vp->vp_length > 0xff) continue;

			/* Append the <arg_N> field */
			FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_strvalue, vp->vp_length);

			FR_PROTO_TRACE("arg[%d] --> %s", i, vp->vp_strvalue);
			len = vp->vp_length;

		} else if (vp->vp_type == FR_TYPE_VENDOR) {
			ssize_t slen;
			uint8_t child_argc;

			/*
			 *	Nested attribute: just recurse.
			 */
			child_argc = fr_pair_list_num_elements(&vp->vp_group);
			if (child_argc > (arg_cnt - i)) child_argc = arg_cnt = i;

			slen = tacacs_encode_body_arg_n(&work_dbuff, child_argc, &arg_len[i], &vp->vp_group, vp->da);
			if (slen < 0) return FR_DBUFF_ERROR_OFFSET(slen, fr_dbuff_used(&work_dbuff));

			i += child_argc;
			continue;

		} else if (!vp->da->parent || (!vp->da->parent->flags.is_root && (vp->da->parent->type != FR_TYPE_VENDOR))) {
			continue;

		} else {
			ssize_t slen;
			fr_sbuff_t sbuff;
			fr_dbuff_t arg_dbuff = FR_DBUFF_MAX(&work_dbuff, 255);
			fr_value_box_t box;
			char buffer[256];

			/*
			 *	Print it as "name=value"
			 */
			FR_DBUFF_IN_MEMCPY_RETURN(&arg_dbuff, vp->da->name, strlen(vp->da->name));
			FR_DBUFF_IN_BYTES_RETURN(&arg_dbuff, (uint8_t) '=');

			sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

			switch (vp->vp_type) {
				/*
				 *	For now, we always print time deltas and dates as integers.
				 *
				 *	Because everyone else's date formats are insane.
				 */
			case FR_TYPE_DATE:
			case FR_TYPE_TIME_DELTA:
				fr_value_box_init(&box, FR_TYPE_UINT64, vp->data.enumv, vp->vp_tainted);
				if (fr_value_box_cast(NULL, &box, FR_TYPE_UINT64, NULL, &vp->data) < 0) {
					buffer[0] = '\0';
					slen = 0;
					break;
				}

				slen = fr_sbuff_in_sprintf(&sbuff, "%lu", box.vb_uint64);
				if (slen <= 0) return -1;
				break;

			default:
				slen = fr_pair_print_value_quoted(&sbuff, vp, T_BARE_WORD);
				if (slen <= 0) return -1;
			}

			FR_DBUFF_IN_MEMCPY_RETURN(&arg_dbuff, buffer, (size_t) slen);

			len = fr_dbuff_used(&arg_dbuff);

			FR_PROTO_TRACE("arg[%d] --> %.*s", i, len, fr_dbuff_start(&arg_dbuff));

			fr_dbuff_set(&work_dbuff, &arg_dbuff);
		}

		fr_assert(len <= UINT8_MAX);

		FR_PROTO_TRACE("len(arg[%d]) = %d", i, len);
		arg_len[i++] = len;
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/*
 *	Encode a TACACS+ field.
 */
static ssize_t tacacs_encode_field(fr_dbuff_t *dbuff, fr_pair_list_t *vps, fr_dict_attr_t const *da, size_t max_len)
{
	fr_pair_t  *vp;
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);

	vp = fr_pair_find_by_da(vps, NULL, da);
	if (!vp || !vp->vp_length || (vp->vp_length > max_len)) return 0;

	if (da->type == FR_TYPE_STRING) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_strvalue, vp->vp_length);
	} else {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_octets, vp->vp_length);
	}

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), fr_dbuff_used(&work_dbuff), da->name);

	return fr_dbuff_set(dbuff, &work_dbuff);
}

static ssize_t tacacs_encode_chap(fr_dbuff_t *dbuff, fr_tacacs_packet_t *packet, fr_pair_list_t *vps, fr_dict_attr_t const *da_chap, fr_dict_attr_t const *da_challenge)
{
	fr_pair_t *chap, *challenge;
	fr_dbuff_t work_dbuff = FR_DBUFF(dbuff);

	chap = fr_pair_find_by_da(vps, NULL, da_chap);
	if (!chap) {
		packet->authen_start.data_len = 0;
		return 0;
	}

	challenge = fr_pair_find_by_da(vps, NULL, da_challenge);
	if (!challenge) {
		fr_strerror_printf("Packet contains %s but no %s", da_chap->name, da_challenge->name);
		return -1;
	}

	if (!challenge->vp_length) {
		fr_strerror_printf("%s is empty", da_challenge->name);
		return -1;
	}

	if ((chap->vp_length + challenge->vp_length) > 255) {
		fr_strerror_printf("%s and %s are longer than 255 octets", da_chap->name, da_challenge->name);
		return -1;
	}

	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, chap->vp_octets, 1);
	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, challenge->vp_octets, challenge->vp_length);
	FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, chap->vp_octets + 1, chap->vp_length - 1);

	packet->authen_start.data_len = chap->vp_length + challenge->vp_length;

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/*
 *	Magic macros to keep things happy.
 *
 *	Note that the various fields are optional.  If the caller
 *	doesn't specify them, then they don't get encoded.
 */
#define ENCODE_FIELD_UINT8(_field, _da) do { \
	vp = fr_pair_find_by_da(vps, NULL, _da); \
	_field = (vp) ? vp->vp_uint8 : 0; \
} while (0)

#define ENCODE_FIELD_STRING8(_field, _da) _field = tacacs_encode_field(&work_dbuff, vps, _da, 0xff)
#define ENCODE_FIELD_STRING16(_field, _da) _field = htons(tacacs_encode_field(&work_dbuff, vps, _da, 0xffff))

/**
 *	Encode VPS into a raw TACACS packet.
 */
ssize_t fr_tacacs_encode(fr_dbuff_t *dbuff, uint8_t const *original_packet, char const *secret, size_t secret_len,
			 unsigned int code, fr_pair_list_t *vps)
{
	fr_pair_t		*vp;
	fr_tacacs_packet_t 	*packet;
	fr_dcursor_t		cursor;
	fr_da_stack_t 		da_stack;
	ssize_t			len = 0;
	size_t 			body_len, packet_len;
	fr_dbuff_t		work_dbuff = FR_DBUFF(dbuff);
	fr_dbuff_marker_t	hdr, body, hdr_io;
	uint8_t			version_byte = 0;

	fr_tacacs_packet_hdr_t const *original = (fr_tacacs_packet_hdr_t const *) original_packet;

	if (!vps) {
	error:
		fr_strerror_const("Cannot encode empty packet");
		return -1;
	}

	/*
	 *	Verify space for the packet...
	 */
	FR_DBUFF_REMAINING_RETURN(&work_dbuff, sizeof(fr_tacacs_packet_t));

	/*
	 * 3.4. The TACACS+ Packet Header
	 *
	 * 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
	 * +----------------+----------------+----------------+----------------+
	 * |major  | minor  |                |                |                |
	 * |version| version|      type      |     seq_no     |   flags        |
	 * +----------------+----------------+----------------+----------------+
	 * |                                                                   |
	 * |                            session_id                             |
	 * +----------------+----------------+----------------+----------------+
	 * |                                                                   |
	 * |                              length                               |
	 * +----------------+----------------+----------------+----------------+
	 */

	/*
	 *	Let's keep reference for packet header.
	 */
	fr_dbuff_marker(&hdr, &work_dbuff);
	/*
	 *	Add marker letting us read/write header bytes without moving hdr.
	 */
	fr_dbuff_marker(&hdr_io, &work_dbuff);

	/*
	 *	Handle the fields in-place.
	 */
	packet = (fr_tacacs_packet_t *)fr_dbuff_start(&work_dbuff);

	/*
	 *	Find the first attribute which is parented by TACACS-Packet.
	 */
	for (vp = fr_pair_dcursor_init(&cursor, vps);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		if (vp->da == attr_tacacs_packet) break;
		if (vp->da->parent == attr_tacacs_packet) break;
	}

	/*
	 *	No "Packet" struct to encode.  We MUST have an original packet to copy the various fields
	 *	from.
	 */
	if (!vp) {
		if (!original) {
			fr_strerror_printf("%s: No TACACS+ %s in the attribute list",
					   __FUNCTION__, attr_tacacs_packet->name);
			return -1;
		}

		/*
		 *	Initialize the buffer avoiding invalid values.
		 */
		memset(packet, 0, sizeof(fr_tacacs_packet_t));

		/*
		 *	Initialize the reply from the request.
		 *
		 *	Make room and fill up the original header. We shouldn't just copy the original packet,
		 *	because the fields 'seq_no' and 'length' are not the same.
		 */
		FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(fr_tacacs_packet_hdr_t));

	} else if (vp->da == attr_tacacs_packet) {
		fr_dcursor_t child_cursor;

		fr_proto_da_stack_build(&da_stack, attr_tacacs_packet);
		FR_PROTO_STACK_PRINT(&da_stack, 0);

		fr_pair_dcursor_init(&child_cursor, &vp->vp_group);

		/*
		 *	Call the struct encoder to do the actual work,
		 *	which fills the struct fields with zero if the member VP is not used.
		 */
		len = fr_struct_to_network(&work_dbuff, &da_stack, 0, &child_cursor, NULL, NULL, NULL);
		if (len != sizeof(fr_tacacs_packet_hdr_t)) {
			fr_strerror_printf("%s: Failed encoding %s using fr_struct_to_network()",
					   __FUNCTION__, attr_tacacs_packet->name);
			return -1;
		}
		fr_dcursor_next(&cursor);

	} else {
		fr_proto_da_stack_build(&da_stack, attr_tacacs_packet);
		FR_PROTO_STACK_PRINT(&da_stack, 0);

		/*
		 *	Call the struct encoder to do the actual work,
		 *	which fills the struct fields with zero if the member VP is not used.
		 */
		len = fr_struct_to_network(&work_dbuff, &da_stack, 0, &cursor, NULL, NULL, NULL);
		if (len != sizeof(fr_tacacs_packet_hdr_t)) {
			fr_strerror_printf("%s: Failed encoding %s using fr_struct_to_network()",
					   __FUNCTION__, attr_tacacs_packet->name);
			return -1;
		}
	}

	/*
	 *	Ensure that we send a sane reply to a request.
	 */
	if (original) {
		packet->hdr.version = original->version;
		packet->hdr.type = original->type;
		packet->hdr.flags = original->flags; /* encrypted && single connection */
		packet->hdr.session_id = original->session_id;

		/*
		 *	The client may not set SINGLE_CONNECT flag.  So if the administrator has set it in the reply,
		 *	we allow setting the flag.  This lets the server tell the client that it supports "single
		 *	connection" mode.
		 */
		vp = fr_pair_find_by_da_nested(vps, NULL, attr_tacacs_flags);
		if (vp) packet->hdr.flags |= (vp->vp_uint8 & FR_TAC_PLUS_SINGLE_CONNECT_FLAG);
	}

	/*
	 * 	Starting here is a 'body' that may require encryption.
	 */
	fr_dbuff_marker(&body, &work_dbuff);

	/*
	 *	Encode 8 octets of various fields not members of STRUCT
	 */
	switch (packet->hdr.type) {
	case FR_TAC_PLUS_AUTHEN:
		/*
		 * seq_no
		 *
		 * This is the sequence number of the current packet for the current session.
		 * The first packet in a session MUST have the sequence number 1 and each
		 * subsequent packet will increment the sequence number by one. Thus clients
		 * only send packets containing odd sequence numbers, and TACACS+ servers only
		 * send packets containing even sequence numbers.
		 */
		if (packet_is_authen_start_request(packet)) { /* Start */
			/**
			 * 4.1. The Authentication START Packet Body
			 *
			 * 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |    action      |    priv_lvl    |  authen_type   | authen_service |
			 * +----------------+----------------+----------------+----------------+
			 * |    user_len    |    port_len    |  rem_addr_len  |    data_len    |
			 * +----------------+----------------+----------------+----------------+
			 * |    user ...
			 * +----------------+----------------+----------------+----------------+
			 * |    port ...
			 * +----------------+----------------+----------------+----------------+
			 * |    rem_addr ...
			 * +----------------+----------------+----------------+----------------+
			 * |    data...
			 * +----------------+----------------+----------------+----------------+
			 */

			/*
			 *	Make room for such body request.
			 */
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->authen_start));

			/*
			 *	Encode 4 octets of various flags.
			 */
			ENCODE_FIELD_UINT8(packet->authen_start.action, attr_tacacs_action);
			ENCODE_FIELD_UINT8(packet->authen_start.priv_lvl, attr_tacacs_privilege_level);
			ENCODE_FIELD_UINT8(packet->authen_start.authen_type, attr_tacacs_authentication_type);
			ENCODE_FIELD_UINT8(packet->authen_start.authen_service, attr_tacacs_authentication_service);

			/*
			 *	Encode 4 mandatory fields.
			 */
			ENCODE_FIELD_STRING8(packet->authen_start.user_len, attr_tacacs_user_name);
			ENCODE_FIELD_STRING8(packet->authen_start.port_len, attr_tacacs_client_port);
			ENCODE_FIELD_STRING8(packet->authen_start.rem_addr_len, attr_tacacs_remote_address);

			/*
			 *	No explicit "Data" attribute, try to automatically determine what to do.
			 */
			if (fr_pair_find_by_da_nested(vps, NULL, attr_tacacs_data)) {
				ENCODE_FIELD_STRING8(packet->authen_start.data_len, attr_tacacs_data);

			} else switch (packet->authen_start.authen_type) {
				default:
					break;

				case FR_AUTHENTICATION_TYPE_VALUE_PAP:
					ENCODE_FIELD_STRING8(packet->authen_start.data_len, attr_tacacs_user_password);
					break;

				case FR_AUTHENTICATION_TYPE_VALUE_CHAP:
					if (tacacs_encode_chap(&work_dbuff, packet, vps, attr_tacacs_chap_password, attr_tacacs_chap_challenge) < 0) return -1;
					break;

				case FR_AUTHENTICATION_TYPE_VALUE_MSCHAP: {
					int rcode;

					rcode = tacacs_encode_chap(&work_dbuff, packet, vps, attr_tacacs_mschap_response, attr_tacacs_mschap_challenge);
					if (rcode < 0) return rcode;

					if (rcode > 0) break;

					if (tacacs_encode_chap(&work_dbuff, packet, vps, attr_tacacs_mschap2_response, attr_tacacs_mschap_challenge) < 0) return -1;
					}
					break;
			}

			goto check_request;

		} else if (packet_is_authen_continue(packet)) {
			/*
			 * 4.3. The Authentication CONTINUE Packet Body
			 *
			 * This packet is sent from the client to the server following the receipt of
			 * a REPLY packet.
			 *
			 *  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |          user_msg len           |            data_len             |
			 * +----------------+----------------+----------------+----------------+
			 * |     flags      |  user_msg ...
			 * +----------------+----------------+----------------+----------------+
			 * |    data ...
			 * +----------------+
			 */

			/*
			 *	Make room for such body request.
			 */
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->authen_cont));

			/*
			 *	Encode 2 mandatory fields.
			 */
			ENCODE_FIELD_STRING16(packet->authen_cont.user_msg_len, attr_tacacs_user_message);
			ENCODE_FIELD_STRING16(packet->authen_cont.data_len, attr_tacacs_data);

			/*
			 *	Look at the abort flag after encoding the fields.
			 */
			ENCODE_FIELD_UINT8(packet->authen_cont.flags, attr_tacacs_authentication_continue_flags);

			goto check_request;

		} else if (packet_is_authen_reply(packet)) {
			/*
			 * 4.2. The Authentication REPLY Packet Body
			 *
			 * 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |     status     |      flags     |        server_msg_len           |
			 * +----------------+----------------+----------------+----------------+
			 * |           data_len              |        server_msg ...
			 * +----------------+----------------+----------------+----------------+
			 * |           data ...
			 * +----------------+----------------+
			 */

			/*
			 *	Make room for such body request.
			 */
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->authen_reply));

			ENCODE_FIELD_UINT8(packet->authen_reply.status, attr_tacacs_authentication_status);
			ENCODE_FIELD_UINT8(packet->authen_reply.flags, attr_tacacs_authentication_flags);

			/*
			 *	Encode 2 mandatory fields.
			 */
			ENCODE_FIELD_STRING16(packet->authen_reply.server_msg_len, attr_tacacs_server_message);
			ENCODE_FIELD_STRING16(packet->authen_reply.data_len, attr_tacacs_data);

			goto check_reply;
		}

		fr_strerror_const("encode: Unknown authentication packet type");
		return -1;

	case FR_TAC_PLUS_AUTHOR:
		if (packet_is_author_request(packet)) {
			/*
			 * 5.1. The Authorization REQUEST Packet Body
			 *
			 *  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |  authen_method |    priv_lvl    |  authen_type   | authen_service |
			 * +----------------+----------------+----------------+----------------+
			 * |    user_len    |    port_len    |  rem_addr_len  |    arg_cnt     |
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_1_len    |   arg_2_len    |      ...       |   arg_N_len    |
			 * +----------------+----------------+----------------+----------------+
			 * |   user ...
			 * +----------------+----------------+----------------+----------------+
			 * |   port ...
			 * +----------------+----------------+----------------+----------------+
			 * |   rem_addr ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_1 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_2 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_N ...
			 * +----------------+----------------+----------------+----------------+
			 */

			/*
			 *	Make room for such body request.
			 */
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->author_req));

			/*
			 *	Encode 4 octets of various flags.
			 */
			ENCODE_FIELD_UINT8(packet->author_req.authen_method, attr_tacacs_authentication_method);
			ENCODE_FIELD_UINT8(packet->author_req.priv_lvl, attr_tacacs_privilege_level);
			ENCODE_FIELD_UINT8(packet->author_req.authen_type, attr_tacacs_authentication_type);
			ENCODE_FIELD_UINT8(packet->author_req.authen_service, attr_tacacs_authentication_service);

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 */
			packet->author_req.arg_cnt = tacacs_encode_body_arg_cnt(vps, attr_tacacs_argument_list);
			if (packet->author_req.arg_cnt) FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, packet->author_req.arg_cnt);

			/*
			 *	Encode 3 mandatory fields.
			 */
			ENCODE_FIELD_STRING8(packet->author_req.user_len, attr_tacacs_user_name);
			ENCODE_FIELD_STRING8(packet->author_req.port_len, attr_tacacs_client_port);
			ENCODE_FIELD_STRING8(packet->author_req.rem_addr_len, attr_tacacs_remote_address);

			/*
			 *	Append 'args_body' to the end of buffer
			 */
			if (packet->author_req.arg_cnt > 0) {
				if (tacacs_encode_body_arg_n(&work_dbuff, packet->author_req.arg_cnt, &packet->author_req.arg_len[0], vps, attr_tacacs_argument_list) < 0) goto error;
			}

			goto check_request;
		} else if (packet_is_author_reply(packet)) {
			/*
			 * 5.2. The Authorization RESPONSE Packet Body
			 *
			 *  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |    status      |     arg_cnt    |         server_msg len          |
			 * +----------------+----------------+----------------+----------------+
			 * +            data_len             |    arg_1_len   |    arg_2_len   |
			 * +----------------+----------------+----------------+----------------+
			 * |      ...       |   arg_N_len    |         server_msg ...
			 * +----------------+----------------+----------------+----------------+
			 * |   data ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_1 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_2 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_N ...
			 * +----------------+----------------+----------------+----------------+
			 */

			/*
			 *	Make room for such body request.
			 */
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->author_reply));

			/*
			 * 	Encode 1 mandatory field.
			 */
			ENCODE_FIELD_UINT8(packet->author_reply.status, attr_tacacs_authorization_status);

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 *
			 *	For ERRORs, we don't encode arguments.
			 *
			 *	5.2
			 *
			 *	   A status of TAC_PLUS_AUTHOR_STATUS_ERROR indicates an error occurred
			 *	   on the server.  For the differences between ERROR and FAIL, refer to
			 *	   section Session Completion (Section 3.4) . None of the arg values
			 *	   have any relevance if an ERROR is set, and must be ignored.
			 *
			 *	   When the status equals TAC_PLUS_AUTHOR_STATUS_FOLLOW, then the
			 *	   arg_cnt MUST be 0.
			 */
			if (!((packet->author_reply.status == FR_AUTHORIZATION_STATUS_VALUE_ERROR) ||
			      (packet->author_reply.status == FR_AUTHORIZATION_STATUS_VALUE_FOLLOW))) {
				packet->author_reply.arg_cnt = tacacs_encode_body_arg_cnt(vps, attr_tacacs_argument_list);
				if (packet->author_reply.arg_cnt) FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, packet->author_reply.arg_cnt);
			} else {
				packet->author_reply.arg_cnt = 0;
			}

			/*
			 *	Encode 2 mandatory fields.
			 */
			ENCODE_FIELD_STRING16(packet->author_reply.server_msg_len, attr_tacacs_server_message);
			ENCODE_FIELD_STRING16(packet->author_reply.data_len, attr_tacacs_data);

			/*
			 *	Append 'args_body' to the end of buffer
			 */
			if (packet->author_reply.arg_cnt > 0) {
				if (tacacs_encode_body_arg_n(&work_dbuff, packet->author_reply.arg_cnt, &packet->author_reply.arg_len[0], vps, attr_tacacs_argument_list) < 0) goto error;
			}

			goto check_reply;

		}

		fr_strerror_const("encode: Unknown authorization packet type");
		return -1;

	case FR_TAC_PLUS_ACCT:
		if (packet_is_acct_request(packet)) {
			/**
			 * 6.1. The Account REQUEST Packet Body
			 *
			 * 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |      flags     |  authen_method |    priv_lvl    |  authen_type   |
			 * +----------------+----------------+----------------+----------------+
			 * | authen_service |    user_len    |    port_len    |  rem_addr_len  |
			 * +----------------+----------------+----------------+----------------+
			 * |    arg_cnt     |   arg_1_len    |   arg_2_len    |      ...       |
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_N_len    |    user ...
			 * +----------------+----------------+----------------+----------------+
			 * |   port ...
			 * +----------------+----------------+----------------+----------------+
			 * |   rem_addr ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_1 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_2 ...
			 * +----------------+----------------+----------------+----------------+
			 * |   ...
			 * +----------------+----------------+----------------+----------------+
			 * |   arg_N ...
			 * +----------------+----------------+----------------+----------------+
			 */

			/*
			 *	Make room for such body request.
			 */
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->acct_req));

			/*
			 *	Encode 5 octets of various flags.
			 */
			ENCODE_FIELD_UINT8(packet->acct_req.flags, attr_tacacs_accounting_flags);
			ENCODE_FIELD_UINT8(packet->acct_req.authen_method, attr_tacacs_authentication_method);
			ENCODE_FIELD_UINT8(packet->acct_req.priv_lvl, attr_tacacs_privilege_level);
			ENCODE_FIELD_UINT8(packet->acct_req.authen_type, attr_tacacs_authentication_type);
			ENCODE_FIELD_UINT8(packet->acct_req.authen_service, attr_tacacs_authentication_service);

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 */
			packet->acct_req.arg_cnt = tacacs_encode_body_arg_cnt(vps, attr_tacacs_argument_list);
			if (packet->acct_req.arg_cnt) FR_DBUFF_MEMSET_RETURN(&work_dbuff, 0, packet->acct_req.arg_cnt);

			/*
			 *	Encode 3 mandatory fields.
			 */
			ENCODE_FIELD_STRING8(packet->acct_req.user_len, attr_tacacs_user_name);
			ENCODE_FIELD_STRING8(packet->acct_req.port_len, attr_tacacs_client_port);
			ENCODE_FIELD_STRING8(packet->acct_req.rem_addr_len, attr_tacacs_remote_address);

			/*
			 *	Append 'args_body' to the end of buffer
			 */
			if (packet->acct_req.arg_cnt > 0) {
				if (tacacs_encode_body_arg_n(&work_dbuff, packet->acct_req.arg_cnt, &packet->acct_req.arg_len[0], vps, attr_tacacs_argument_list) < 0) goto error;
			}

		check_request:
			/*
			 *	Just to avoid malformed packet.
			 */
			fr_dbuff_set(&hdr_io, &hdr);
			fr_dbuff_out(&version_byte, &hdr_io);
			if (!version_byte) {
				version_byte = 0xc1; /* version 12.1 */
				fr_dbuff_set(&hdr_io, &hdr);
				FR_DBUFF_IN_RETURN(&hdr_io, version_byte);
			}
			/*
			 *	If the caller didn't set a session ID, use a random one.
			 */
			if (!fr_pair_find_by_da_nested(vps, NULL, attr_tacacs_session_id)) {
				packet->hdr.session_id = fr_rand();
			}

			/*
			 *	Requests have odd sequence numbers.
			 */
			packet->hdr.seq_no |= 0x01;
			break;

		} else if (packet_is_acct_reply(packet)) {
			/**
			 * 6.2. The Accounting REPLY Packet Body
			 *
			 * 1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
			 * +----------------+----------------+----------------+----------------+
			 * |         server_msg len          |            data_len             |
			 * +----------------+----------------+----------------+----------------+
			 * |     status     |         server_msg ...
			 * +----------------+----------------+----------------+----------------+
			 * |     data ...
			 * +----------------+
			 */

			/*
			 *	Make room for such body request.
			 */
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->acct_reply));

			/*
			 *	Encode 2 mandatory fields.
			 */
			ENCODE_FIELD_STRING16(packet->acct_reply.server_msg_len, attr_tacacs_server_message);
			ENCODE_FIELD_STRING16(packet->acct_reply.data_len, attr_tacacs_data);

			/*
			 *	And also, the status field.
			 */
			ENCODE_FIELD_UINT8(packet->acct_reply.status, attr_tacacs_accounting_status);

		check_reply:
			/*
			 *	fr_struct_to_network() fills the struct fields with 0
			 *	if there is no matching VP.  In the interest of making
			 *	things easier for the user, we don't require them to
			 *	copy all of the fields from the request to the reply.
			 *
			 *	Instead, we copy the fields manually, and ensure that
			 *	they have the correct values.
			 */
			if (original) {
				fr_dbuff_set(&hdr_io, &hdr);
				fr_dbuff_out(&version_byte, &hdr_io);
				if (!version_byte) {
				 	packet->hdr.version = original->version;
				}

				if (!packet->hdr.seq_no) {
					packet->hdr.seq_no = original->seq_no + 1; /* uint8_t */
				}

				if (!packet->hdr.session_id) {
					packet->hdr.session_id = original->session_id;
				}
			}

			/*
			 *	Replies have even sequence numbers.
			 */
			packet->hdr.seq_no &= 0xfe;
			break;
		}

		fr_strerror_const("encode: Unknown accounting packet type");
		return -1;

	default:
		fr_strerror_printf("encode: unknown packet type %d", packet->hdr.type);
		return -1;
	}

	/*
	 *	Force the correct header type, and randomly-placed
	 *	status fields.  But only if there's no code field.
	 *	Only the unit tests pass a zero code field, as that's
	 *	normally invalid.  The unit tests ensure that all of
	 *	the VPs are passed to encode a packet, and they all
	 *	must be correct
	 */
	if (code && (fr_tacacs_code_to_packet(packet, code) < 0)) return -1;

	/*
	 *	The packet length we store in the header doesn't
	 *	include the size of the header.  But we tell the
	 *	caller about the total length of the packet.
	 */
	packet_len = fr_dbuff_used(&work_dbuff);
	fr_assert(packet_len >= sizeof(fr_tacacs_packet_hdr_t));

	body_len = (packet_len - sizeof(fr_tacacs_packet_hdr_t));
	fr_assert(packet_len < FR_MAX_PACKET_SIZE);
	packet->hdr.length = htonl(body_len);

	/*
	 *	If the original packet is encrypted, then the reply
	 *	MUST be encrypted too.
	 *
	 *	On the other hand, if the request is unencrypted,
	 *	we're OK with sending an encrypted reply.  Because,
	 *	whatever.
	 */
	if (original &&
	    ((original->flags & FR_TAC_PLUS_UNENCRYPTED_FLAG) == 0)) {
		packet->hdr.flags &= ~FR_TAC_PLUS_UNENCRYPTED_FLAG;
	}

#ifndef NDEBUG
	if (fr_debug_lvl >= L_DBG_LVL_4) {
		uint8_t flags = packet->hdr.flags;

		packet->hdr.flags |= FR_TAC_PLUS_UNENCRYPTED_FLAG;
		fr_tacacs_packet_log_hex(&default_log, packet, packet_len);
		packet->hdr.flags = flags;
	}
#endif

	/*
	 *	3.6. Encryption
	 *
	 *	Packets are encrypted if the unencrypted flag is clear.
	 */
	if (secret) {
		if (!secret_len) {
			fr_strerror_const("Packet should be decrypted, but the secret has zero length");
			return -1;
		}

		FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), packet_len, "fr_tacacs_packet_t (unencrypted)");

		if (fr_tacacs_body_xor(packet, fr_dbuff_current(&body), body_len, secret, secret_len) != 0) return -1;

		packet->hdr.flags &= ~FR_TAC_PLUS_UNENCRYPTED_FLAG;
	} else {
		/*
		 *	Packets which have no secret cannot be encrypted.
		 */
		packet->hdr.flags |= FR_TAC_PLUS_UNENCRYPTED_FLAG;

	}

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), packet_len, "fr_tacacs_packet_t (encoded)");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/*
 *	Test points for protocol encode
 */
static ssize_t fr_tacacs_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_list_t *vps,
				      uint8_t *data, size_t data_len, void *proto_ctx)
{
	fr_tacacs_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_tacacs_ctx_t);

	return fr_tacacs_encode(&FR_DBUFF_TMP(data, data_len), NULL, test_ctx->secret, (talloc_array_length(test_ctx->secret)-1), 0, vps);
}

static int _encode_test_ctx(fr_tacacs_ctx_t *proto_ctx)
{
	talloc_const_free(proto_ctx->secret);

	fr_tacacs_global_free();

	return 0;
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx, UNUSED fr_dict_t const *dict,
			   UNUSED fr_dict_attr_t const *root_da)
{
	fr_tacacs_ctx_t *test_ctx;

	if (fr_tacacs_global_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_tacacs_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->root = fr_dict_root(dict_tacacs);
	talloc_set_destructor(test_ctx, _encode_test_ctx);

	*out = test_ctx;

	return 0;
}

/*
 *	Test points
 */
extern fr_test_point_proto_encode_t tacacs_tp_encode_proto;
fr_test_point_proto_encode_t tacacs_tp_encode_proto = {
	.test_ctx	= encode_test_ctx,
	.func		= fr_tacacs_encode_proto
};
