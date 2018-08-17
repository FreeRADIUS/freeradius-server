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
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/server/rad_assert.h>

static fr_dict_t *dict_freeradius;

extern fr_dict_autoload_t proto_radius_coa_dict[];
fr_dict_autoload_t proto_radius_coa_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_radius_coa_dict_attr[];
fr_dict_attr_autoload_t proto_radius_coa_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ NULL }
};

static fr_io_final_t mod_process(UNUSED void const *instance, REQUEST *request, fr_io_action_t action)
{
	VALUE_PAIR *vp;
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv;

	REQUEST_VERIFY(request);

	/*
	 *	Pass this through asynchronously to the module which
	 *	is waiting for something to happen.
	 */
	if (action != FR_IO_ACTION_RUN) {
		unlang_signal(request, (fr_state_signal_t) action);
		return FR_IO_DONE;
	}

	switch (request->request_state) {
	case REQUEST_INIT:
		RDEBUG("Received %s ID %i", fr_packet_codes[request->packet->code], request->packet->id);
		log_request_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->component = "radius";

		/*
		 *	We can run CoA-Request or Disconnect-Request sections here
		 */
		dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->packet->code));
		if (!dv) {
			REDEBUG("Failed to find value for &request:Packet-Type");
			return FR_IO_FAIL;
		}

		unlang = cf_section_find(request->server_cs, "recv", dv->alias);
		if (!unlang) {
			REDEBUG("Failed to find 'recv %s' section", dv->alias);
			return FR_IO_FAIL;
		}

		RDEBUG("Running 'recv %s' from file %s", dv->alias, cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_RECV;
		/* FALL-THROUGH */

	case REQUEST_RECV:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

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
		case RLM_MODULE_USERLOCK:
		default:
			request->reply->code = request->packet->code + 2; /* NAK */
			break;
		}

		/*
		 *	Allow for over-ride of reply code.
		 */
		vp = fr_pair_find_by_da(request->reply->vps, attr_packet_type, TAG_ANY);
		if (vp) request->reply->code = vp->vp_uint32;

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
		unlang_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);
		rad_assert(request->log.unlang_indent == 0);

		request->request_state = REQUEST_SEND;
		/* FALL-THROUGH */

	case REQUEST_SEND:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

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
		case RLM_MODULE_USERLOCK:
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
		/*
		 *	Check for "do not respond".
		 */
		if (request->reply->code == FR_CODE_DO_NOT_RESPOND) {
			RDEBUG("Not sending reply to client.");
			return FR_IO_DONE;
		}

		/*
		 *	This is an internally generated request.  Don't print IP addresses.
		 */
		if (request->parent) {
			RDEBUG("Sent %s ID %i", fr_packet_codes[request->reply->code], request->reply->id);
			log_request_pair_list(L_DBG_LVL_1, request, request->reply->vps, "");
			return FR_IO_DONE;
		}

		if (RDEBUG_ENABLED) common_packet_debug(request, request->reply, false);
		break;

	default:
		return FR_IO_FAIL;
	}

	return FR_IO_REPLY;
}


extern fr_app_worker_t proto_radius_coa;
fr_app_worker_t proto_radius_coa = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_coa",
	.entry_point	= mod_process,
};
