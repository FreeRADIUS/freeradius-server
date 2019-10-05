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
 * @file proto_radius_coa.c
 * @brief RADIUS CoA processing.
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

static fr_dict_t *dict_radius;

extern fr_dict_autoload_t proto_radius_coa_dict[];
fr_dict_autoload_t proto_radius_coa_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_service_type;
static fr_dict_attr_t const *attr_state;

extern fr_dict_attr_autoload_t proto_radius_coa_dict_attr[];
fr_dict_attr_autoload_t proto_radius_coa_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_service_type, .name = "Service-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ NULL }
};

static rlm_rcode_t mod_process(UNUSED void const *instance, REQUEST *request)
{
	VALUE_PAIR *vp;
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv;

	REQUEST_VERIFY(request);

	switch (request->request_state) {
	case REQUEST_INIT:
		if (request->parent && RDEBUG_ENABLED) {
			RDEBUG("Received %s ID %i", fr_packet_codes[request->packet->code], request->packet->id);
			log_request_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");
		}

		request->component = "radius";

		/*
		 *	We can run CoA-Request or Disconnect-Request sections here
		 */
		dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->packet->code));
		if (!dv) {
			REDEBUG("Failed to find value for &request:Packet-Type");
			return RLM_MODULE_FAIL;
		}

		/*
		 *	We require a State attribute for
		 *	re-authorization requests.
		 */
		if (request->packet->code == FR_CODE_COA_REQUEST) {
			vp = fr_pair_find_by_da(request->reply->vps, attr_service_type, TAG_ANY);
			if (vp && !fr_pair_find_by_da(request->reply->vps, attr_state, TAG_ANY)) {
				REDEBUG("CoA-Request with Service-Type = Authorize-Only MUST contain a State attribute");
				request->reply->code = FR_CODE_COA_NAK;
				goto nak;
			}
		}

		unlang = cf_section_find(request->server_cs, "recv", dv->alias);
		if (!unlang) {
			REDEBUG("Failed to find 'recv %s' section", dv->alias);
			return RLM_MODULE_FAIL;
		}

		RDEBUG("Running 'recv %s' from file %s", dv->alias, cf_filename(unlang));
		unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_RECV;
		/* FALL-THROUGH */

	case REQUEST_RECV:
		rcode = unlang_interpret_resume(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

		rad_assert(request->log.unlang_indent == 0);

		switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = request->packet->code + 1; /* ACK */
			break;

		case RLM_MODULE_HANDLED:
			break;


		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_DISALLOW:
		default:
			request->reply->code = request->packet->code + 2; /* NAK */
			break;
		}

		/*
		 *	Allow for over-ride of reply code.
		 */
		vp = fr_pair_find_by_da(request->reply->vps, attr_packet_type, TAG_ANY);
		if (vp) request->reply->code = vp->vp_uint32;

	nak:
		dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
		unlang = NULL;
		if (dv) unlang = cf_section_find(request->server_cs, "send", dv->alias);

		if (!unlang) goto send_reply;

		/*
		 *	Note that for NAKs, we do NOT use
		 *	reject_delay.  This is because we're acting as
		 *	a NAS, and we want to respond to the RADIUS
		 *	server as quickly as possible.
		 */
	rerun_nak:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);
		rad_assert(request->log.unlang_indent == 0);

		request->request_state = REQUEST_SEND;
		/* FALL-THROUGH */

	case REQUEST_SEND:
		rcode = unlang_interpret_resume(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

		rad_assert(request->log.unlang_indent == 0);

		switch (rcode) {
			/*
			 *	We need to send CoA-NAK back if Service-Type
			 *	is Authorize-Only.  Rely on the user's policy
			 *	to do that.  We're not a real NAS, so this
			 *	restriction doesn't (ahem) apply to us.
			 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_DISALLOW:
		default:
			/*
			 *	If we over-ride an ACK with a NAK, run
			 *	the NAK section.
			 */
			if (request->reply->code == request->packet->code + 1) {
				dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
				RWDEBUG("Failed running 'send %s', trying corresponding NAK section.", dv->alias);

				request->reply->code = request->packet->code + 2;

				dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_section_find(request->server_cs, "send", dv->alias);
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'send %s' section as it does not exist", dv->alias);
			}
			/*
			 *	Else it was already a NAK or something else.
			 */
			break;

		case RLM_MODULE_HANDLED:
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			/* reply code is already set */
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
		.name2 = "CoA-Request",\
		.component = MOD_RECV_COA,
	},
	{
		.name = "send",
		.name2 = "CoA-ACK",
		.component = MOD_SEND_COA,
	},
	{
		.name = "send",.name2 = "CoA-NAK",
		.component = MOD_SEND_COA,
	},
	{
		.name = "recv",
		.name2 = "Disconnect-Request",
		.component = MOD_RECV_COA,
	},
	{
		.name = "send",
		.name2 = "Disconnect-ACK",
		.component = MOD_SEND_COA,
	},
	{
		.name = "send",
		.name2 = "Disconnect-NAK",
		.component = MOD_SEND_COA,
	},
	{
		.name = "send",
		.name2 = "Protocol-Error",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
	},

	COMPILE_TERMINATOR
};


extern fr_app_worker_t proto_radius_coa;
fr_app_worker_t proto_radius_coa = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_coa",
	.entry_point	= mod_process,
	.compile_list	= compile_list,
};
