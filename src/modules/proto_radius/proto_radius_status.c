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
 * @file proto_radius_status.c
 * @brief RADIUS Status-Server processing.
 *
 * @copyright 2016 The FreeRADIUS server project.
 * @copyright 2016 Alan DeKok (aland@deployingradius.com)
 */
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t proto_radius_status_dict[];
fr_dict_autoload_t proto_radius_status_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_radius_status_dict_attr[];
fr_dict_attr_autoload_t proto_radius_status_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ NULL }
};

static rlm_rcode_t mod_process(UNUSED void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv;
	VALUE_PAIR *vp;

	REQUEST_VERIFY(request);

	switch (request->request_state) {
	case REQUEST_INIT:
		if (request->parent && RDEBUG_ENABLED) {
			RDEBUG("Received %s ID %i", fr_packet_codes[request->packet->code], request->packet->id);
			log_request_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");
		}

		request->component = "radius";

		unlang = cf_section_find(request->server_cs, "recv", "Status-Server");
		if (!unlang) {
			RWDEBUG("Failed to find 'recv Status-Server' section");
			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto send_reply;
		}

		RDEBUG("Running 'recv Status-Server' from file %s", cf_filename(unlang));
		unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_RECV;
		/* FALL-THROUGH */

	case REQUEST_RECV:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

		rad_assert(request->log.unlang_indent == 0);

		switch (rcode) {
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = FR_CODE_ACCESS_ACCEPT;
			break;

		case RLM_MODULE_FAIL:
		case RLM_MODULE_HANDLED:
			request->reply->code = 0; /* don't reply */
			break;

		default:
		case RLM_MODULE_REJECT:
			request->reply->code = FR_CODE_ACCESS_REJECT;
			break;
		}

		/*
		 *	Allow for over-ride of reply code.
		 */
		vp = fr_pair_find_by_da(request->reply->vps, attr_packet_type, TAG_ANY);
		if (vp) request->reply->code = vp->vp_uint32;

		dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
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
			if (request->reply->code != FR_CODE_ACCESS_REJECT) {
				dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
				if (dv) RWDEBUG("Failed running 'send %s', trying 'send Access-Reject'", dv->name);

				request->reply->code = FR_CODE_ACCESS_REJECT;

				dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_section_find(request->server_cs, "send", dv->name);
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'send %s' section as it does not exist", dv->name);
			}
			break;
		}

	send_reply:
		request->reply->timestamp = fr_time();

		/*
		 *	Check for "do not respond".
		 */
		if (request->reply->code == FR_CODE_DO_NOT_RESPOND) {
			RDEBUG("Not sending reply to client.");
			break;
		}

		if (request->parent && RDEBUG_ENABLED) {
			RDEBUG("Sending %s ID %i", fr_packet_codes[request->reply->code], request->reply->id);
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
		.name2 = "Status-Server",
		.component = MOD_AUTHORIZE,
	},
	{
		.name = "send",
		.name2 = "Access-Accept",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Access-Reject",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Protocol-Error",
		.component = MOD_POST_AUTH,
	},

	COMPILE_TERMINATOR
};


extern fr_app_worker_t proto_radius_status;
fr_app_worker_t proto_radius_status = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_status",
	.entry_point	= mod_process,
	.compile_list	= compile_list,
};
