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
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/net.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/protocol/tacacs/dictionary.h>

#include "tacacs.h"
#include "attrs.h"

fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t libfreeradius_tacacs_dict[];
fr_dict_autoload_t libfreeradius_tacacs_dict[] = {
	{ .out = &dict_tacacs, .proto = "tacacs" },

	{ NULL }
};

fr_dict_attr_t const *attr_tacacs_accounting_flags;
fr_dict_attr_t const *attr_tacacs_accounting_status;
fr_dict_attr_t const *attr_tacacs_action;
fr_dict_attr_t const *attr_tacacs_authentication_flags;
fr_dict_attr_t const *attr_tacacs_authentication_method;
fr_dict_attr_t const *attr_tacacs_authentication_service;
fr_dict_attr_t const *attr_tacacs_authentication_status;
fr_dict_attr_t const *attr_tacacs_authentication_type;
fr_dict_attr_t const *attr_tacacs_authorization_status;
fr_dict_attr_t const *attr_tacacs_client_port;
fr_dict_attr_t const *attr_tacacs_data;
fr_dict_attr_t const *attr_tacacs_packet_type;
fr_dict_attr_t const *attr_tacacs_privilege_level;
fr_dict_attr_t const *attr_tacacs_remote_address;
fr_dict_attr_t const *attr_tacacs_sequence_number;
fr_dict_attr_t const *attr_tacacs_server_message;
fr_dict_attr_t const *attr_tacacs_session_id;
fr_dict_attr_t const *attr_tacacs_user_message;
fr_dict_attr_t const *attr_tacacs_user_name;
fr_dict_attr_t const *attr_tacacs_version_minor;

extern fr_dict_attr_autoload_t libfreeradius_tacacs_dict_attr[];
fr_dict_attr_autoload_t libfreeradius_tacacs_dict_attr[] = {
	{ .out = &attr_tacacs_accounting_flags, .name = "TACACS-Accounting-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_accounting_status, .name = "TACACS-Accounting-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_action, .name = "TACACS-Action", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_flags, .name = "TACACS-Authentication-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_method, .name = "TACACS-Authentication-Method", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_service, .name = "TACACS-Authentication-Service", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_status, .name = "TACACS-Authentication-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_type, .name = "TACACS-Authentication-Type", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authorization_status, .name = "TACACS-Authorization-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_client_port, .name = "TACACS-Client-Port", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_data, .name = "TACACS-Data", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_packet_type, .name = "TACACS-Packet-Type", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_privilege_level, .name = "TACACS-Privilege-Level", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_remote_address, .name = "TACACS-Remote-Address", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_sequence_number, .name = "TACACS-Sequence-Number", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_server_message, .name = "TACACS-Server-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_session_id, .name = "TACACS-Session-Id", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_user_message, .name = "TACACS-User-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_user_name, .name = "TACACS-User-Name", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_version_minor, .name = "TACACS-Version-Minor", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ NULL }
};

tacacs_type_t tacacs_type(RADIUS_PACKET const * const packet)
{
	VALUE_PAIR const *vp;

	vp = fr_pair_find_by_da(packet->vps, attr_tacacs_packet_type, TAG_ANY);
	if (!vp) return TAC_PLUS_INVALID;

	return (tacacs_type_t)vp->vp_uint8;
}

char const *tacacs_packet_code(RADIUS_PACKET const * const packet)
{
	fr_dict_enum_t const *dv;
	tacacs_type_t type;

	type = tacacs_type(packet);

	dv = fr_dict_enum_by_value(attr_tacacs_packet_type, fr_box_uint32(type));
	if (!dv) return NULL;

	return dv->name;
}

uint32_t tacacs_session_id(RADIUS_PACKET const * const packet)
{
	VALUE_PAIR const *vp;

	vp = fr_pair_find_by_da(packet->vps, attr_tacacs_session_id, TAG_ANY);
	if (!vp) return 0;

	return vp->vp_uint32;
}

static bool tacacs_packet_verify(RADIUS_PACKET const * const packet, bool from_client)
{
	fr_tacacs_packet_t *pkt = (fr_tacacs_packet_t *)packet->data;
	size_t hdr_len, len;

	if (pkt->hdr.ver.major != TAC_PLUS_MAJOR_VER || pkt->hdr.ver.minor & 0xe) {	/* minor == {0,1} */
		fr_strerror_printf("Unsupported version %u.%u", pkt->hdr.ver.major, pkt->hdr.ver.minor);
		return false;
	}

	hdr_len = ntohl(pkt->hdr.length);

	switch (pkt->hdr.type) {
	default:
		fr_strerror_printf("Invalid packet type %i", pkt->hdr.type);
		return false;

	case TAC_PLUS_AUTHEN:
		if ((from_client && pkt->hdr.seq_no % 2 != 1) || (!from_client && pkt->hdr.seq_no % 2 != 0)) {
bad_seqno:
			fr_strerror_printf("Invalid sequence number %u (from_client = %s)", pkt->hdr.seq_no, from_client ? "true" : "false");
			return false;
		}
		if (pkt->hdr.seq_no == 255) {
			fr_strerror_printf("client sent seq_no set to 255");
			return false;
		}
		break;

	case TAC_PLUS_AUTHOR:
	case TAC_PLUS_ACCT:
		if ((from_client && pkt->hdr.seq_no != 1) || (!from_client && pkt->hdr.seq_no != 2))
			goto bad_seqno;
		break;
	}

	/* this occurs when we want to indicate we do not support the request */
	if (hdr_len == 0) return true;

	switch (pkt->hdr.type) {
	default:
		fr_assert(0);	/* Should have been caught above */
		return false;

	case TAC_PLUS_AUTHEN:
		switch (pkt->hdr.seq_no) {
		case 1:
			len = pkt->authen.start.user_len +
			      pkt->authen.start.port_len +
			      pkt->authen.start.rem_addr_len +
			      pkt->authen.start.data_len;
			if (len + offsetof(fr_tacacs_packet_authen_start_hdr_t, body) != hdr_len) {
				fr_strerror_printf("Authen START Header/Body size mismatch");
				return false;
			}
			break;
		default:
			if (from_client) {
				len = ntohs(pkt->authen.cont.user_msg_len) + ntohs(pkt->authen.cont.data_len);
				if (len + offsetof(fr_tacacs_packet_authen_cont_hdr_t, body) != hdr_len) {
					fr_strerror_printf("Authen CONTINUE Header/Body size mismatch");
					return false;
				}
			} else {
				len = ntohs(pkt->authen.reply.server_msg_len) + ntohs(pkt->authen.reply.data_len);
				if (len + offsetof(fr_tacacs_packet_authen_reply_hdr_t, body) != hdr_len) {
					fr_strerror_printf("Authen REPLY Header/Body size mismatch");
					return false;
				}
			}
		}
		break;

	case TAC_PLUS_AUTHOR:
		if (from_client) {
			len = pkt->author.req.user_len + pkt->author.req.port_len + pkt->author.req.rem_addr_len + pkt->author.req.arg_cnt;
			for (unsigned int i = 0; i < pkt->author.req.arg_cnt; i++)
				len += pkt->author.req.body[i];
			if (len + offsetof(fr_tacacs_packet_author_req_hdr_t, body) != hdr_len) {
				fr_strerror_printf("Author REQUEST Header/Body size mismatch");
				return false;
			}
		} else {
			len = pkt->author.res.server_msg_len + pkt->author.res.data_len + pkt->author.res.arg_cnt;
			for (unsigned int i = 0; i < pkt->author.res.arg_cnt; i++)
				len += pkt->author.res.body[i];
			if (len + offsetof(fr_tacacs_packet_author_res_hdr_t, body) != hdr_len) {
				fr_strerror_printf("Author RESPONSE Header/Body size mismatch");
				return false;
			}
		}
		break;

	case TAC_PLUS_ACCT:
		if (from_client) {
			uint8_t flags;

			len = pkt->acct.req.user_len +
			      pkt->acct.req.port_len +
			      pkt->acct.req.rem_addr_len +
			      pkt->acct.req.arg_cnt;
			for (unsigned int i = 0; i < pkt->acct.req.arg_cnt; i++)
				len += pkt->acct.req.body[i];
			if (len + offsetof(fr_tacacs_packet_acct_req_hdr_t, body) != hdr_len) {
				fr_strerror_printf("Acct REQUEST Header/Body size mismatch");
				return false;
			}

			flags = pkt->acct.req.flags & 0xe;
			if (flags == 0x0 || flags == 0x6 || flags == 0xc || flags == 0xe) {
				/* FIXME send to client TACACS-Accounting-Status Error */
				fr_strerror_printf("Acct RESPONSE invalid flags set");
				return false;
			}
		} else {
			len = pkt->acct.res.server_msg_len + pkt->acct.res.data_len;
			if (len + offsetof(fr_tacacs_packet_acct_res_hdr_t, body) != hdr_len) {
				fr_strerror_printf("Acct RESPONSE Header/Body size mismatch");
				return false;
			}
		}
		break;
	}

	return true;
}


static int tacacs_xor(RADIUS_PACKET * const packet, char const *secret, size_t secret_len)
{
	fr_tacacs_packet_t *pkt = (fr_tacacs_packet_t *)packet->data;
	uint8_t pad[MD5_DIGEST_LENGTH];
	uint8_t *buf;
	int pad_offset;

	if (!secret) {
		if (pkt->hdr.flags & TAC_PLUS_UNENCRYPTED_FLAG)
			return 0;
		else {
			fr_strerror_printf("Packet is encrypted but no secret for the client is set");
			return -1;
		}
	}

	if (pkt->hdr.flags & TAC_PLUS_UNENCRYPTED_FLAG) {
		fr_strerror_printf("Packet is unencrypted but a secret has been set for the client");
		return -1;
	}

	pad_offset = sizeof(pkt->hdr.session_id) + secret_len + sizeof(pkt->hdr.version) + sizeof(pkt->hdr.seq_no);

	/* MD5_1 = MD5{session_id, key, version, seq_no} */
	/* MD5_n = MD5{session_id, key, version, seq_no, MD5_n-1} */
	buf = talloc_array(NULL, uint8_t, pad_offset + MD5_DIGEST_LENGTH);

	memcpy(&buf[0], &pkt->hdr.session_id, sizeof(pkt->hdr.session_id));
	memcpy(&buf[sizeof(pkt->hdr.session_id)], secret, secret_len);
	memcpy(&buf[sizeof(pkt->hdr.session_id) + secret_len], &pkt->hdr.version, sizeof(pkt->hdr.version));
	memcpy(&buf[sizeof(pkt->hdr.session_id) + secret_len + sizeof(pkt->hdr.version)], &pkt->hdr.seq_no, sizeof(pkt->hdr.seq_no));
	fr_md5_calc(pad, buf, pad_offset);

	size_t pos = sizeof(fr_tacacs_packet_hdr_t);
	do {
		for (size_t i = 0; i < MD5_DIGEST_LENGTH && pos < packet->data_len; i++, pos++)
			packet->data[pos] ^= pad[i];

		if (pos == packet->data_len)
			break;

		memcpy(&buf[pad_offset], pad, MD5_DIGEST_LENGTH);
		fr_md5_calc(pad, buf, pad_offset + MD5_DIGEST_LENGTH);
	} while (1);

	talloc_free(buf);

	return 0;
}

/*
 *	Receives a packet, assuming that the RADIUS_PACKET structure
 *	has been filled out already.
 *
 *	This ASSUMES that the packet is allocated && fields
 *	initialized.
 *
 *	This ASSUMES that the socket is marked as O_NONBLOCK, which
 *	the function above does set, if your system supports it.
 *
 *	Calling this function MAY change sockfd,
 *	if src_ipaddr.af == AF_UNSPEC.
 */
int fr_tacacs_packet_recv(RADIUS_PACKET * const packet, char const * const secret, size_t secret_len)
{
	ssize_t len;

	/*
	 *	No data allocated.  Read the 12-byte header into
	 *	a temporary buffer.
	 */
	if (!packet->data) {
		fr_tacacs_packet_hdr_t *hdr;
		size_t packet_len;

		/* borrow vector to bring in the header for later talloc */
		fr_assert(sizeof(fr_tacacs_packet_hdr_t) <= RADIUS_AUTH_VECTOR_LENGTH);

		/*
		 *	Only read enough data to get the TACACS+ header.
		 */
		 len = recv(packet->sockfd, packet->vector + packet->data_len,
			   sizeof(fr_tacacs_packet_hdr_t) - packet->data_len, 0);
		if (len == 0) return -2; /* clean close */

#ifdef ECONNRESET
		if ((len < 0) && (errno == ECONNRESET)) { /* forced */
			return -2;
		}
#endif

		if (len < 0) {
			fr_strerror_printf("Error receiving packet: %s", fr_syserror(errno));
			return -1;
		}

		packet->data_len += len;
		if (packet->data_len < sizeof(fr_tacacs_packet_hdr_t)) { /* want more data */
			return 0;
		}

		fr_assert(packet->data_len == sizeof(fr_tacacs_packet_hdr_t));

		/*
		 *	We now have the full packet header.  Let's go
		 *	check it.
		 */
		hdr = (fr_tacacs_packet_hdr_t *)packet->vector;

		packet_len = ntohl(hdr->length);

#ifdef __COVERITY__
		if (!packet_len) {
			fr_strerror_printf("Discarding packet: It contains no data");
			return -1;
		}
#endif

		if (packet_len + sizeof(fr_tacacs_packet_hdr_t) > TACACS_MAX_PACKET_SIZE) {
			fr_strerror_printf("Discarding packet: Larger than limitation of " STRINGIFY(MAX_PACKET_LEN) " bytes");
			return -1;
		}

		packet_len += sizeof(fr_tacacs_packet_hdr_t);

		packet->data = talloc_array(packet, uint8_t, packet_len);
		if (!packet->data) {
			fr_strerror_printf("Out of memory");
			return -1;
		}

		/*
		 *	We have room for a full packet, but we've only
		 *	read in the header so far.
		 */
		packet->data_len = packet_len;
		packet->partial = sizeof(fr_tacacs_packet_hdr_t);
		memcpy(packet->data, packet->vector, sizeof(fr_tacacs_packet_hdr_t));
	}

	/*
	 *	Try to read more data.
	 */
	len = recv(packet->sockfd, packet->data + packet->partial,
		   packet->data_len - packet->partial, 0);
	if (len == 0) return -2; /* clean close */

#ifdef ECONNRESET
	if ((len < 0) && (errno == ECONNRESET)) { /* forced */
		return -2;
	}
#endif

	if (len < 0) {
		fr_strerror_printf("Error receiving packet: %s", fr_syserror(errno));
		return -1;
	}

	packet->partial += len;

	if (packet->partial < packet->data_len) {
		return 0;
	}

	if (tacacs_xor(packet, secret, secret_len) < 0) {
		fr_strerror_printf("Failed decryption of TACACS request: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	See if it's a well-formed TACACS packet.
	 */
	if (!tacacs_packet_verify(packet, true)) {
		return -1;
	}

	/*
	 *	Explicitly set the VP list to empty.
	 */
	packet->vps = NULL;

	if (fr_debug_lvl) {
		char ip_buf[INET6_ADDRSTRLEN], buffer[256];

		if (packet->src_ipaddr.af != AF_UNSPEC) {
			inet_ntop(packet->src_ipaddr.af,
				  &packet->src_ipaddr.addr,
				  ip_buf, sizeof(ip_buf));
			snprintf(buffer, sizeof(buffer), "host %s port %d",
				 ip_buf, packet->src_port);
		} else {
			snprintf(buffer, sizeof(buffer), "socket %d",
				 packet->sockfd);
		}

	}

	packet->timestamp = fr_time();

	return 1;	/* done reading the packet */
}

int fr_tacacs_packet_send(RADIUS_PACKET * const packet, RADIUS_PACKET const * const original, char const * const secret, size_t secret_len)
{
	uint8_t			vminor;
	tacacs_type_t		type;
	uint8_t			seq_no;
	VALUE_PAIR 		*vp;

	vp = fr_pair_find_by_da(original->vps, attr_tacacs_version_minor, TAG_ANY);
	if (!vp) {
		fr_strerror_printf("Missing %s", attr_tacacs_version_minor->name);
		return -1;
	}
	vminor = vp->vp_uint8;

	vp = fr_pair_find_by_da(original->vps, attr_tacacs_sequence_number, TAG_ANY);
	if (!vp) {
		fr_strerror_printf("Missing %s", attr_tacacs_sequence_number->name);
		return -1;
	}
	seq_no = vp->vp_uint8 + 1;	/* we catch client 255 on ingress */

	vp = fr_pair_afrom_da(packet, vp->da);
	if (!vp) {
	oom:
		fr_strerror_printf("Out of memory");
		return -1;
	}
	vp->vp_uint8 = vminor;
	fr_pair_add(&packet->vps, vp);

	type = tacacs_type(original);

	vp = fr_pair_afrom_da(packet, attr_tacacs_packet_type);
	if (!vp) goto oom;
	vp->vp_uint8 = type;
	fr_pair_add(&packet->vps, vp);

	vp = fr_pair_afrom_da(packet, attr_tacacs_sequence_number);
	if (!vp) goto oom;
	vp->vp_uint8 = seq_no;
	fr_pair_add(&packet->vps, vp);

	vp = fr_pair_afrom_da(packet, attr_tacacs_session_id);
	if (!vp) goto oom;
	vp->vp_uint32 = tacacs_session_id(original);
	fr_pair_add(&packet->vps, vp);

	if (fr_tacacs_packet_encode(packet, secret, secret_len) < 0) {
		fr_strerror_printf("Failed encoding TACACS reply: %s", fr_syserror(errno));
		return -1;
	}

	fr_assert(tacacs_packet_verify(packet, false) == true);

	if (tacacs_xor(packet, secret, secret_len) < 0) {
		fr_strerror_printf("Failed encryption of TACACS reply: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	@fixme: EINTR and retry
	 */
	return write(packet->sockfd, packet->data, packet->data_len);
}

int fr_tacacs_init(void)
{
	if (fr_dict_autoload(libfreeradius_tacacs_dict) < 0) return -1;
	if (fr_dict_attr_autoload(libfreeradius_tacacs_dict_attr) < 0) return -1;

	return 0;
}

void fr_tacacs_free(void)
{
	fr_dict_autofree(libfreeradius_tacacs_dict);
}
