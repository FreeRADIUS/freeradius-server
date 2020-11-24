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
 * @copyright 2017 Network RADIUS SARL (legal@networkradius.com)
 */

#include <freeradius-devel/io/test_point.h>
#include <freeradius-devel/protocol/tacacs/tacacs.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/util/struct.h>

#include "tacacs.h"
#include "attrs.h"

/**
 *	Encode a TACACS+ 'arg_N' fields.
 */
static uint8_t tacacs_encode_body_arg_n_len(fr_dbuff_t *dbuff, fr_pair_t *vps, fr_dict_attr_t const *da)
{
	uint8_t     arg_cnt = 0;
	fr_pair_t   *vp;
	fr_cursor_t cursor;
	fr_dbuff_t  work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (arg_cnt == 255) break;

		if ((vp->da != da) || (vp->vp_length > 0xff)) continue;

		/* Append the <arg_N_len> fields length */
		fr_dbuff_in(&work_dbuff, (uint8_t) vp->vp_length);

		arg_cnt++;
	}

	fr_dbuff_set(dbuff, &work_dbuff);

	return arg_cnt;
}

static ssize_t tacacs_encode_body_arg_n(fr_dbuff_t *dbuff, fr_pair_t *vps, fr_dict_attr_t const *da)
{
	fr_pair_t   *vp;
	fr_cursor_t cursor;
	uint8_t     arg_cnt = 0;
	fr_dbuff_t  work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor), arg_cnt++) {
		if (arg_cnt == 255) break;

		if (vp->da != da || vp->vp_length > 0xff) continue;

		/* Append the <arg_N> field */
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_strvalue, vp->vp_length);
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/*
 *	Encode a TACACS+ field.
 */
static ssize_t tacacs_encode_field(fr_dbuff_t *dbuff, fr_pair_t *vps, fr_dict_attr_t const *da, size_t max_len)
{
	fr_pair_t  *vp;
	fr_dbuff_t work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);

	vp = fr_pair_find_by_da(&vps, da);
	if (!vp || !vp->vp_length || (vp->vp_length > max_len)) return 0;

	if (da->type == FR_TYPE_STRING) {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_strvalue, vp->vp_length);
	} else {
		FR_DBUFF_IN_MEMCPY_RETURN(&work_dbuff, vp->vp_octets, vp->vp_length);
	}

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/*
 *	Magic macros to keep things happy.
 *
 *	Note that the various fields are optional.  If the caller
 *	doesn't specify them, then they don't get encoded.
 */
#define ENCODE_FIELD_UINT8(_field, _da) do { \
	vp = fr_pair_find_by_da(&vps, _da); \
	_field = (vp) ? vp->vp_uint8 : 0; \
} while (0)

#define ENCODE_FIELD_STRING8(_field, _da) _field = tacacs_encode_field(&work_dbuff, vps, _da, 0xff)
#define ENCODE_FIELD_STRING16(_field, _da) _field = htons(tacacs_encode_field(&work_dbuff, vps, _da, 0xffff))

/**
 *	Encode VPS into a raw TACACS packet.
 */
ssize_t fr_tacacs_encode(fr_dbuff_t *dbuff, uint8_t const *original_packet, char const *secret, size_t secret_len, fr_pair_t *vps)
{
	fr_pair_t		*vp;
	fr_tacacs_packet_t 	*packet;
	fr_cursor_t		cursor;
	fr_da_stack_t 		da_stack;
	ssize_t			len = 0;
	size_t 			body_len, packet_len;
	fr_dbuff_t		work_dbuff = FR_DBUFF_NO_ADVANCE(dbuff);
	fr_dbuff_marker_t	hdr, body;

	fr_tacacs_packet_hdr_t const *original = (fr_tacacs_packet_hdr_t const *) original_packet;

	if (!vps) {
	error:
		fr_strerror_printf("Cannot encode empty packet");
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
	 *	Handle the fields in-place.
	 */
	packet = (fr_tacacs_packet_t *)fr_dbuff_start(&work_dbuff);

	/*
	 *	Initialize the buffer avoiding invalid values.
	 */
	memset(packet, 0, sizeof(fr_tacacs_packet_t));

	/*
	 *	Initialize the reply from the request.
	 */
	if (original) {
		/*
		 *	Make room and fill up the original header. Ah! we shouldn't just copy the original packet,
		 *	because the fields 'seq_no' and 'length' are not the same.
		 */
		FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(fr_tacacs_packet_hdr_t));
		packet->hdr.version = original->version;
		packet->hdr.type = original->type;
		packet->hdr.flags = original->flags;
		packet->hdr.session_id = original->session_id;
	}

	/*
	 *	Find the first attribute which is parented by TACACS-Packet.
	 */
	for (vp = fr_cursor_init(&cursor, &vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da->parent == attr_tacacs_packet) break;
	}

	if (!vp) {
		if (!original) {
			fr_strerror_printf("%s: No TACACS+ %s in the attribute list",
					   __FUNCTION__, attr_tacacs_packet->name);
			return -1;
		}
	} else {
		fr_proto_da_stack_build(&da_stack, attr_tacacs_packet);
		FR_PROTO_STACK_PRINT(&da_stack, 0);

		/*
		 *	Call the struct encoder to do the actual work.
		 */
		len = fr_struct_to_network_dbuff(&work_dbuff, &da_stack, 0, &cursor, NULL, NULL);
		if (len != sizeof(fr_tacacs_packet_hdr_t)) {
			fr_strerror_printf("%s: Failed encoding %s using fr_struct_to_network()",
					   __FUNCTION__, attr_tacacs_packet->name);
			return -1;
		}
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
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->authen.start));

			/*
			 *	Encode 4 octets of various flags.
			 */
			ENCODE_FIELD_UINT8(packet->authen.start.action, attr_tacacs_action);
			ENCODE_FIELD_UINT8(packet->authen.start.priv_lvl, attr_tacacs_privilege_level);
			ENCODE_FIELD_UINT8(packet->authen.start.authen_type, attr_tacacs_authentication_type);
			ENCODE_FIELD_UINT8(packet->authen.start.authen_service, attr_tacacs_authentication_service);

			/*
			 *	Encode 4 mandatory fields.
			 */
			ENCODE_FIELD_STRING8(packet->authen.start.user_len, attr_tacacs_user_name);
			ENCODE_FIELD_STRING8(packet->authen.start.port_len, attr_tacacs_client_port);
			ENCODE_FIELD_STRING8(packet->authen.start.rem_addr_len, attr_tacacs_remote_address);
			ENCODE_FIELD_STRING8(packet->authen.start.data_len, attr_tacacs_data);

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
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->authen.cont));

			/*
			 *	Encode 2 mandatory fields.
			 */
			ENCODE_FIELD_STRING16(packet->authen.cont.user_msg_len, attr_tacacs_user_message);
			ENCODE_FIELD_STRING16(packet->authen.cont.data_len, attr_tacacs_data);

			/*
			 *	Look at the abort flag after encoding the fields.
			 */
			ENCODE_FIELD_UINT8(packet->authen.cont.flags, attr_tacacs_authentication_continue_flags);

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
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->authen.reply));

			ENCODE_FIELD_UINT8(packet->authen.reply.status, attr_tacacs_authentication_status);
			ENCODE_FIELD_UINT8(packet->authen.reply.flags, attr_tacacs_authentication_flags);

			/*
			 *	Encode 2 mandatory fields.
			 */
			ENCODE_FIELD_STRING16(packet->authen.reply.server_msg_len, attr_tacacs_server_message);
			ENCODE_FIELD_STRING16(packet->authen.reply.data_len, attr_tacacs_data);

			goto check_reply;

		} else {
		unknown_packet:
			fr_strerror_printf("decode: Unknown packet type");
			return -1;
		}

		break;

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
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->author.req));

			/*
			 *	Encode 4 octets of various flags.
			 */
			ENCODE_FIELD_UINT8(packet->author.req.authen_method, attr_tacacs_authentication_method);
			ENCODE_FIELD_UINT8(packet->author.req.priv_lvl, attr_tacacs_privilege_level);
			ENCODE_FIELD_UINT8(packet->author.req.authen_type, attr_tacacs_authentication_type);
			ENCODE_FIELD_UINT8(packet->author.req.authen_service, attr_tacacs_authentication_service);

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 */
			packet->author.req.arg_cnt = tacacs_encode_body_arg_n_len(&work_dbuff, vps, attr_tacacs_argument_list);

			/*
			 *	Encode 3 mandatory fields.
			 */
			ENCODE_FIELD_STRING8(packet->author.req.user_len, attr_tacacs_user_name);
			ENCODE_FIELD_STRING8(packet->author.req.port_len, attr_tacacs_client_port);
			ENCODE_FIELD_STRING8(packet->author.req.rem_addr_len, attr_tacacs_remote_address);

			/*
			 *	Append 'args_body' to the end of buffer
			 */
			if (packet->author.req.arg_cnt > 0) {
				if (tacacs_encode_body_arg_n(&work_dbuff, vps, attr_tacacs_argument_list) < 0) goto error;
			}

			goto check_request;

		} else if (packet_is_author_response(packet)) {
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
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->author.res));

			/*
			 * 	Encode 1 mandatory field.
			 */
			ENCODE_FIELD_UINT8(packet->author.res.status, attr_tacacs_authorization_status);

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
			if (!((packet->author.res.status == FR_AUTHORIZATION_STATUS_VALUE_ERROR) ||
			      (packet->author.res.status == FR_AUTHORIZATION_STATUS_VALUE_FOLLOW))) {
				packet->author.res.arg_cnt = tacacs_encode_body_arg_n_len(&work_dbuff, vps, attr_tacacs_argument_list);
			} else {
				packet->author.res.arg_cnt = 0;
			}

			/*
			 *	Encode 2 mandatory fields.
			 */
			ENCODE_FIELD_STRING16(packet->author.res.server_msg_len, attr_tacacs_server_message);
			ENCODE_FIELD_STRING16(packet->author.res.data_len, attr_tacacs_data);

			/*
			 *	Append 'args_body' to the end of buffer
			 */
			if (packet->author.res.arg_cnt > 0) {
				if (tacacs_encode_body_arg_n(&work_dbuff, vps, attr_tacacs_argument_list) < 0) goto error;
			}

			goto check_reply;

		} else {
			goto unknown_packet;
		}

		break;

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
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->acct.req));

			/*
			 *	Encode 5 octets of various flags.
			 */
			ENCODE_FIELD_UINT8(packet->acct.req.flags, attr_tacacs_accounting_flags);
			ENCODE_FIELD_UINT8(packet->acct.req.authen_method, attr_tacacs_authentication_method);
			ENCODE_FIELD_UINT8(packet->acct.req.priv_lvl, attr_tacacs_privilege_level);
			ENCODE_FIELD_UINT8(packet->acct.req.authen_type, attr_tacacs_authentication_type);
			ENCODE_FIELD_UINT8(packet->acct.req.authen_service, attr_tacacs_authentication_service);

			/*
			 *	Encode 'arg_N' arguments (horrible format)
			 */
			packet->acct.req.arg_cnt = tacacs_encode_body_arg_n_len(&work_dbuff, vps, attr_tacacs_argument_list);

			/*
			 *	Encode 3 mandatory fields.
			 */
			ENCODE_FIELD_STRING8(packet->acct.req.user_len, attr_tacacs_user_name);
			ENCODE_FIELD_STRING8(packet->acct.req.port_len, attr_tacacs_client_port);
			ENCODE_FIELD_STRING8(packet->acct.req.rem_addr_len, attr_tacacs_remote_address);

			/*
			 *	Append 'args_body' to the end of buffer
			 */
			if (packet->acct.req.arg_cnt > 0) {
				if (tacacs_encode_body_arg_n(&work_dbuff, vps, attr_tacacs_argument_list) < 0) goto error;
			}

		check_request:
			/*
			 *	Just to avoid malformed packet.
			 */
			if (!fr_dbuff_current(&hdr)[0]) fr_dbuff_current(&hdr)[0] = 0xc1; /* version 12.1 */

			/*
			 *	If the caller didn't set a session ID, use a random one.
			 */
			if (!fr_pair_find_by_da(&vps, attr_tacacs_session_id)) {
				packet->hdr.session_id = fr_rand();
			}

			/*
			 *	Requests have odd sequence numbers.
			 */
			packet->hdr.seq_no |= 0x01;

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
			FR_DBUFF_ADVANCE_RETURN(&work_dbuff, sizeof(packet->acct.reply));

			/*
			 *	Encode 2 mandatory fields.
			 */
			ENCODE_FIELD_STRING16(packet->acct.reply.server_msg_len, attr_tacacs_server_message);
			ENCODE_FIELD_STRING16(packet->acct.reply.data_len, attr_tacacs_data);

			/*
			 *	And also, the status field.
			 */
			ENCODE_FIELD_UINT8(packet->acct.reply.status, attr_tacacs_accounting_status);

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
				if (!fr_dbuff_current(&hdr)[0]) {
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

		} else {
			goto unknown_packet;
		}
		break;

	default:
		fr_strerror_printf("encode: TACACS+ type %u", packet->hdr.type);
		return -1;
	}

	/*
	 *	The packet length we store in the header doesn't
	 *	include the size of the header.  But we tell the
	 *	caller about the total length of the packet.
	 */
	packet_len = fr_dbuff_used(&work_dbuff);
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

	/*
	 *	3.6. Encryption
	 *
	 *	Packets are encrypted if the unencrypted flag is clear.
	 */
	if ((packet->hdr.flags & FR_TAC_PLUS_UNENCRYPTED_FLAG) == 0) {
		fr_assert(secret != NULL);
		fr_assert(secret_len > 0);

		if (!secret || secret_len < 1) {
			fr_strerror_printf("decode: Packet is supposed to be encrypted, but no secret is set.");
			return -1;
		}

		FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), packet_len, "fr_tacacs_packet_t (unencrypted)");

		if (fr_tacacs_body_xor(packet, fr_dbuff_current(&body), body_len, secret, secret_len) != 0) return -1;
	}

	FR_PROTO_HEX_DUMP(fr_dbuff_start(&work_dbuff), packet_len, "fr_tacacs_packet_t (encoded)");

	return fr_dbuff_set(dbuff, &work_dbuff);
}

/*
 *	Test points for protocol encode
 */
static ssize_t fr_tacacs_encode_proto(UNUSED TALLOC_CTX *ctx, fr_pair_t *vps, uint8_t *data, size_t data_len, UNUSED void *proto_ctx)
{
	fr_tacacs_ctx_t	*test_ctx = talloc_get_type_abort(proto_ctx, fr_tacacs_ctx_t);

	return fr_tacacs_encode(&FR_DBUFF_TMP(data, data_len), NULL, test_ctx->secret, (talloc_array_length(test_ctx->secret)-1), vps);
}

static int _encode_test_ctx(fr_tacacs_ctx_t *proto_ctx)
{
	talloc_const_free(proto_ctx->secret);

	fr_tacacs_free();

	return 0;
}

static int encode_test_ctx(void **out, TALLOC_CTX *ctx)
{
	fr_tacacs_ctx_t *test_ctx;

	if (fr_tacacs_init() < 0) return -1;

	test_ctx = talloc_zero(ctx, fr_tacacs_ctx_t);
	if (!test_ctx) return -1;

	test_ctx->secret = talloc_strdup(test_ctx, "testing123");
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
