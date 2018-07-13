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
 * @file proto_dhcpv4/proto_dhcpv4_base.c
 * @brief Base DORA, etc. DHCPV4 processing.
 *
 * @copyright 2018 The Freeradius server project.
 * @copyright 2018 Alan DeKok (aland@deployingradius.com)
 */
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/dhcpv4.h>

static fr_dict_t *dict_dhcpv4;

extern fr_dict_autoload_t proto_dhcpv4_dict[];
fr_dict_autoload_t proto_dhcpv4_dict[] = {
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

static fr_dict_attr_t const *attr_message_type;
static fr_dict_attr_t const *attr_yiaddr;

extern fr_dict_attr_autoload_t proto_dhcpv4_base_dict_attr[];
fr_dict_attr_autoload_t proto_dhcpv4_base_dict_attr[] = {
	{ .out = &attr_message_type, .name = "DHCP-Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4},
	{ .out = &attr_yiaddr, .name = "DHCP-Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4},
	{ NULL }
};

static int reply_ok[FR_DHCP_INFORM + 1] = {
	[0]			= FR_DHCP_MESSAGE_TYPE_VALUE_DHCP_DO_NOT_RESPOND,
	[FR_DHCP_DISCOVER]	= FR_DHCP_OFFER,
	[FR_DHCP_OFFER]		= FR_DHCP_OFFER,
	[FR_DHCP_REQUEST]	= FR_DHCP_ACK,
	[FR_DHCP_DECLINE]	= 0,
	[FR_DHCP_ACK]		= FR_DHCP_ACK,
	[FR_DHCP_NAK]		= FR_DHCP_NAK,
	[FR_DHCP_RELEASE]	= 0,
	[FR_DHCP_INFORM]	= FR_DHCP_ACK,
};

static int reply_fail[FR_DHCP_INFORM + 1] = {
	[0]			= FR_DHCP_MESSAGE_TYPE_VALUE_DHCP_DO_NOT_RESPOND,
	[FR_DHCP_DISCOVER]	= 0,
	[FR_DHCP_OFFER]		= FR_DHCP_NAK,
	[FR_DHCP_REQUEST]	= FR_DHCP_NAK,
	[FR_DHCP_DECLINE]	= 0,
	[FR_DHCP_ACK]		= FR_DHCP_NAK,
	[FR_DHCP_NAK]		= FR_DHCP_NAK,
	[FR_DHCP_RELEASE]	= 0,
	[FR_DHCP_INFORM]	= FR_DHCP_MESSAGE_TYPE_VALUE_DHCP_DO_NOT_RESPOND,
};

static fr_io_final_t mod_process(UNUSED void const *instance, REQUEST *request, UNUSED fr_io_action_t action)
{
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv;
	fr_dict_attr_t const *da = NULL;
	VALUE_PAIR *vp;

	REQUEST_VERIFY(request);
	rad_assert(request->packet->code > 0);
	rad_assert(request->packet->code <= FR_DHCP_INFORM);

	switch (request->request_state) {
	case REQUEST_INIT:
		RDEBUG("Received %s ID %08x", dhcp_message_types[request->packet->code], request->packet->id);
		log_request_proto_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->component = "dhcpv4";

		dv = fr_dict_enum_by_value(attr_message_type, fr_box_uint8(request->packet->code));
		if (!dv) {
			REDEBUG("Failed to find value for &request:DHCP-Message-Type");
			return FR_IO_FAIL;
		}

		unlang = cf_section_find(request->server_cs, "recv", dv->alias);
		if (!unlang) {
			RWDEBUG("Failed to find 'recv %s' section", dv->alias);
			request->reply->code = FR_DHCP_MESSAGE_TYPE_VALUE_DHCP_DO_NOT_RESPOND;
			goto send_reply;
		}

		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_RECV;
		/* FALL-THROUGH */

	case REQUEST_RECV:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

		rad_assert(request->log.unlang_indent == 0);

		/*
		 *	Allow the admin to explicitly set the reply
		 *	type.
		 */
		vp = fr_pair_find_by_da(request->reply->vps, attr_message_type, TAG_ANY);
		if (vp) {
			request->reply->code = vp->vp_uint8;
		} else switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = reply_ok[request->packet->code];
			break;

		default:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_FAIL:
			request->reply->code = reply_fail[request->packet->code];
			break;

		case RLM_MODULE_HANDLED:
			if (!request->reply->code) request->reply->code = FR_DHCP_MESSAGE_TYPE_VALUE_DHCP_DO_NOT_RESPOND;
			break;
		}

		/*
		 *	DHCP-Release / Decline doesn't send a reply, and doesn't run "send DHCP-Do-Not-Respond"
		 */
		if (!request->reply->code) {
			return FR_IO_DONE;
		}

		/*
		 *	Offer and ACK MUST have YIADDR.
		 */
		if ((request->reply->code == FR_DHCP_OFFER) || (request->reply->code == FR_DHCP_ACK)) {
			vp = fr_pair_find_by_da(request->reply->vps, attr_yiaddr, TAG_ANY);
			if (!vp) {
				REDEBUG("%s packet does not have YIADDR.  The client will not receive an IP address.",
					dhcp_message_types[request->reply->code]);
			}
		}

		dv = fr_dict_enum_by_value(da, fr_box_uint8(request->reply->code));
		unlang = NULL;
		if (dv) unlang = cf_section_find(request->server_cs, "send", dv->alias);

		if (!unlang) goto send_reply;

	rerun_nak:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_SEND;
		/* FALL-THROUGH */

	case REQUEST_SEND:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

		rad_assert(request->log.unlang_indent == 0);

		switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
		case RLM_MODULE_HANDLED:
			/* reply is already set */
			break;

		default:
			/*
			 *	If we over-ride an ACK with a NAK, run
			 *	the NAK section.
			 */
			if (request->reply->code != FR_DHCP_MESSAGE_TYPE_VALUE_DHCP_DO_NOT_RESPOND) {
				dv = fr_dict_enum_by_value(attr_message_type, fr_box_uint8(request->reply->code));
				RWDEBUG("Failed running 'send %s', trying 'send Do-Not-Respond'", dv->alias);

				request->reply->code = FR_DHCP_MESSAGE_TYPE_VALUE_DHCP_DO_NOT_RESPOND;

				dv = fr_dict_enum_by_value(da, fr_box_uint8(request->reply->code));
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_section_find(request->server_cs, "send", dv->alias);
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'send %s' section as it does not exist", dv->alias);
			}
			break;
		}

	send_reply:
		/*
		 *	Check for "do not respond".
		 */
		if (request->reply->code == FR_DHCP_MESSAGE_TYPE_VALUE_DHCP_DO_NOT_RESPOND) {
			RDEBUG("Not sending reply to client");
			return FR_IO_DONE;
		}

		if (RDEBUG_ENABLED) common_packet_debug(request, request->reply, false);
		break;

	default:
		return FR_IO_FAIL;
	}

	return FR_IO_REPLY;
}


extern fr_app_worker_t proto_dhcpv4_base;
fr_app_worker_t proto_dhcpv4_base = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dhcpv4_base",
	.entry_point	= mod_process,
};
