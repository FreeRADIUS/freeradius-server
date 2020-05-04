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
 * @file proto_arp/proto_arp_process.c
 * @brief ARP processing.
 *
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/arp/arp.h>
#include <freeradius-devel/protocol/arp/rfc826.h>

static fr_dict_t const *dict_arp;

extern fr_dict_autoload_t proto_arp_process_dict[];
fr_dict_autoload_t proto_arp_process_dict[] = {
	{ .out = &dict_arp, .proto = "arp" },
	{ NULL }
};

static fr_dict_attr_t const *attr_arp_operation;

extern fr_dict_attr_autoload_t proto_arp_process_dict_attr[];
fr_dict_attr_autoload_t proto_arp_process_dict_attr[] = {
	{ .out = &attr_arp_operation, .name = "ARP-Operation", .type = FR_TYPE_UINT8, .dict = &dict_arp},
	{ NULL }
};

static int reply_ok[UINT8_MAX + 1] = {
	[FR_ARP_OPERATION_VALUE_REQUEST]	= FR_ARP_OPERATION_VALUE_REPLY,
	[FR_ARP_OPERATION_VALUE_REVERSE_REQUEST]  = FR_ARP_OPERATION_VALUE_REVERSE_REPLY,
};

static int reply_fail[UINT8_MAX + 1] = {
	[FR_ARP_OPERATION_VALUE_REQUEST]	= FR_CODE_DO_NOT_RESPOND,
	[FR_ARP_OPERATION_VALUE_REVERSE_REQUEST]  = FR_CODE_DO_NOT_RESPOND,
};

static rlm_rcode_t mod_process(UNUSED void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv;
	fr_dict_attr_t const *da = NULL;
	VALUE_PAIR *vp;

	REQUEST_VERIFY(request);
	fr_assert(request->packet->code > 0);

	switch (request->request_state) {
	case REQUEST_INIT:
		if (request->parent && RDEBUG_ENABLED) {
			RDEBUG("Received ARP %d", request->packet->code);
			log_request_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");
		}

		request->component = "arp";

		dv = fr_dict_enum_by_value(attr_arp_operation, fr_box_uint8(request->packet->code));
		if (!dv) {
			REDEBUG("Failed to find value for &request:ARP-Operation");
			return RLM_MODULE_FAIL;
		}

		unlang = cf_section_find(request->server_cs, "recv", dv->name);
		if (!unlang) {
			RWDEBUG("Failed to find 'recv %s' section", dv->name);
			request->reply->code = FR_CODE_DO_NOT_RESPOND;
			goto send_reply;
		}

		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_RECV;
		/* FALL-THROUGH */

	case REQUEST_RECV:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

		fr_assert(request->log.unlang_indent == 0);

		/*
		 *	Allow the admin to explicitly set the reply
		 *	type.
		 */
		vp = fr_pair_find_by_da(request->reply->vps, attr_arp_operation, TAG_ANY);
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
			if (!request->reply->code) request->reply->code = FR_CODE_DO_NOT_RESPOND;
			break;
		}

		/*
		 *	Some types don't send a reply, and don't run "send Do-Not-Respond"
		 */
		if (!request->reply->code) {
			return RLM_MODULE_HANDLED;
		}

		dv = fr_dict_enum_by_value(da, fr_box_uint8(request->reply->code));
		unlang = NULL;
		if (dv) unlang = cf_section_find(request->server_cs, "send", dv->name);

		if (!unlang) goto send_reply;

	rerun_nak:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_SEND;
		/* FALL-THROUGH */

	case REQUEST_SEND:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

		fr_assert(request->log.unlang_indent == 0);

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
			if (request->reply->code != FR_CODE_DO_NOT_RESPOND) {
				dv = fr_dict_enum_by_value(attr_arp_operation, fr_box_uint8(request->reply->code));
				RWDEBUG("Failed running 'send %s', trying 'send Do-Not-Respond'", dv->name);

				request->reply->code = FR_CODE_DO_NOT_RESPOND;

				dv = fr_dict_enum_by_value(da, fr_box_uint8(request->reply->code));
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_section_find(request->server_cs, "send", dv->name);
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'send %s' section as it does not exist", dv->name);
			}
			break;
		}

	send_reply:
		/*
		 *	Check for "do not respond".
		 */
		if (request->reply->code == FR_CODE_DO_NOT_RESPOND) {
			RDEBUG("Not sending reply to client");
			return RLM_MODULE_HANDLED;
		}

		if (request->parent && RDEBUG_ENABLED) {
			RDEBUG("Sending %d", request->reply->code, request->reply->id);
			log_request_pair_list(L_DBG_LVL_1, request, request->reply->vps, "");
		}
		break;

	default:
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}


static virtual_server_compile_t compile_list[] = {
	{
		.name = "recv",
		.name2 = "Request",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Reply",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "recv",
		.name2 = "Reverse-Request",
		.component = MOD_POST_AUTH,
	},

	{
		.name = "send",
		.name2 = "Reverse-Reply",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
	},

	COMPILE_TERMINATOR
};


extern fr_app_worker_t proto_arp_process;
fr_app_worker_t proto_arp_process = {
	.magic		= RLM_MODULE_INIT,
	.name		= "arp_process",
	.entry_point	= mod_process,
	.compile_list	= compile_list,
};
