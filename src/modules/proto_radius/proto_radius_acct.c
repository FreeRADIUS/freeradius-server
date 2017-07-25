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
 * @file proto_radius_acct.c
 * @brief RADIUS accounting processing.
 *
 * @copyright 2016 The FreeRADIUS server project.
 * @copyright 2016 Alan DeKok (aland@deployingradius.com)
 */
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/dict.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/rad_assert.h>

static fr_io_final_t mod_process(REQUEST *request, fr_io_action_t action)
{
	VALUE_PAIR *vp;
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv;
	fr_dict_attr_t const *da = NULL;

	VERIFY_REQUEST(request);

	/*
	 *	Pass this through asynchronously to the module which
	 *	is waiting for something to happen.
	 */
	if (action != FR_IO_ACTION_RUN) {
		unlang_signal(request, FR_ACTION_DONE);
		return FR_IO_DONE;
	}

	switch (request->request_state) {
	case REQUEST_INIT:
		radlog_request(L_DBG, L_DBG_LVL_1, request, "Received %s ID %i",
			       fr_packet_codes[request->packet->code], request->packet->id);
		rdebug_proto_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->component = "radius";

		unlang = cf_section_find(request->server_cs, "recv", "Accounting-Request");
		if (!unlang) {
			REDEBUG("Failed to find 'recv Accounting-Request' section");
			return FR_IO_FAIL;
		}

		RDEBUG("Running 'recv Accounting-Request' from file %s", cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP);

		request->request_state = REQUEST_RECV;
		/* FALL-THROUGH */

	case REQUEST_RECV:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

		rad_assert(request->log.unlang_indent == 0);

		switch (rcode) {
		/*
		 *	The module has a number of OK return codes.
		 */
		case RLM_MODULE_NOOP:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = FR_CODE_ACCOUNTING_RESPONSE;
			break;

		case RLM_MODULE_HANDLED:
			break;

		/*
		 *	The module failed, or said the request is
		 *	invalid, therefore we stop here.
		 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			return FR_IO_FAIL;
		}

		/*
		 *	Allow for over-ride of reply code.
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 0, FR_PACKET_TYPE, TAG_ANY);
		if (vp) request->reply->code = vp->vp_uint32;

		if (!da) da = fr_dict_attr_by_num(NULL, 0, FR_PACKET_TYPE);
		rad_assert(da != NULL);

		dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->reply->code));
		unlang = NULL;
		if (dv) unlang = cf_section_find(request->server_cs, "send", dv->alias);

		if (!unlang) goto send_reply;

		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP);

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
			request->reply->code = 0;
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
			radlog_request(L_DBG, L_DBG_LVL_1, request, "Sent %s ID %i",
				       fr_packet_codes[request->reply->code], request->reply->id);
			rdebug_proto_pair_list(L_DBG_LVL_1, request, request->reply->vps, "");
			return FR_IO_DONE;
		}

#ifdef WITH_UDPFROMTO
		/*
		 *	Overwrite the src ip address on the outbound packet
		 *	with the one specified by the client.
		 *	This is useful to work around broken DSR implementations
		 *	and other routing issues.
		 */
		if (request->client->src_ipaddr.af != AF_UNSPEC) {
			request->reply->src_ipaddr = request->client->src_ipaddr;
		}
#endif

		if (RDEBUG_ENABLED) common_packet_debug(request, request->reply, false);
		break;

	default:
		return FR_IO_FAIL;
	}

	return FR_IO_REPLY;
}


static int mod_instantiate(UNUSED void *instance, CONF_SECTION *listen_cs)
{
	int rcode;
	CONF_SECTION *server_cs;

	rad_assert(listen_cs);

	server_cs = cf_item_to_section(cf_parent(listen_cs));
	rad_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	rcode = unlang_compile_subsection(server_cs, "recv", "Accounting-Request", MOD_PREACCT);
	if (rcode < 0) return rcode;
	if (rcode == 0) {
		cf_log_err(server_cs, "Failed finding 'recv Accounting-Request { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	rcode = unlang_compile_subsection(server_cs, "send", "Accounting-Response", MOD_ACCOUNTING);
	if (rcode < 0) return rcode;

	rcode = unlang_compile_subsection(server_cs, "send", "Do-Not-Respond", MOD_POST_AUTH);
	if (rcode < 0) return rcode;

	rcode = unlang_compile_subsection(server_cs, "send", "Protocol-Error", MOD_POST_AUTH);
	if (rcode < 0) return rcode;

	return 0;
}

extern fr_app_process_t proto_radius_acct;
fr_app_process_t proto_radius_acct = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_coa",
	.instantiate	= mod_instantiate,
	.process	= mod_process,
};
