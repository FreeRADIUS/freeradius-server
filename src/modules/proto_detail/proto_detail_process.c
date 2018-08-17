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
 * @file proto_detail_process.c
 * @brief Detail file processing
 *
 * @copyright 2017 The FreeRADIUS server project.
 * @copyright 2017 Alan DeKok (aland@deployingradius.com)
 */
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/rad_assert.h>
#include "proto_detail.h"

static fr_dict_t *dict_freeradius;

extern fr_dict_autoload_t proto_detail_process_dict[];
fr_dict_autoload_t proto_detail_process_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },

	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t proto_detail_process_dict_attr[];
fr_dict_attr_autoload_t proto_detail_process_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ NULL }
};

static fr_io_final_t mod_process(UNUSED void const *instance, REQUEST *request, fr_io_action_t action)
{
	VALUE_PAIR		*vp;
	rlm_rcode_t		rcode;
	CONF_SECTION		*unlang;

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
		RDEBUG("Received %s ID %i",
		       fr_dict_enum_alias_by_value(attr_packet_type, fr_box_uint32(request->reply->code)),
		       request->packet->id);
		log_request_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->component = "radius";

		unlang = cf_section_find(request->server_cs, "recv", NULL);
		if (!unlang) {
			REDEBUG("Failed to find 'recv' section");
			return FR_IO_FAIL;
		}

		RDEBUG("Running 'recv' from file %s", cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

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
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			switch (request->packet->code) {
			case FR_CODE_ACCOUNTING_REQUEST:
				request->reply->code = FR_CODE_ACCOUNTING_RESPONSE;
				break;

			case FR_CODE_COA_REQUEST:
				request->reply->code = FR_CODE_COA_ACK;
				break;

			case FR_CODE_DISCONNECT_REQUEST:
				request->reply->code = FR_CODE_DISCONNECT_ACK;
				break;

			default:
				request->reply->code = 0;
				break;
			}
			break;

		case RLM_MODULE_HANDLED:
			break;

		/*
		 *	The module failed, or said the request is
		 *	invalid, therefore we stop here.
		 */
		case RLM_MODULE_NOOP:
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			request->reply->code = 0;
			break;
		}

		/*
		 *	Allow for over-ride of reply code.
		 */
		vp = fr_pair_find_by_da(request->reply->vps, attr_packet_type, TAG_ANY);
		if (vp) request->reply->code = vp->vp_uint32;

		if (request->reply->code == FR_CODE_DO_NOT_RESPOND) {
			RWARN("Ignoring 'do_not_respond' as it does not apply to detail files");
		}

		unlang = cf_section_find(request->server_cs, "send", "ok");
		if (!unlang) goto send_reply;

		RDEBUG("Running 'send %s { ... }' from file %s", cf_section_name2(unlang), cf_filename(unlang));
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
			request->reply->code = 0;
			break;
		}

	send_reply:
		/*
		 *	Failed, but we still reply with a magic code,
		 *	so that the reader can retransmit.
		 */
		if (!request->reply->code) {
			REDEBUG("Failed ID %i", request->reply->id);
		} else {
			RDEBUG("Sent %s ID %i",
			       fr_dict_enum_alias_by_value(attr_packet_type, fr_box_uint32(request->reply->code)),
			       request->reply->id);
		}

		log_request_proto_pair_list(L_DBG_LVL_1, request, request->reply->vps, "");
		break;

	default:
		return FR_IO_FAIL;
	}

	return FR_IO_REPLY;
}


static int mod_instantiate(void *instance, CONF_SECTION *listen_cs)
{
	int rcode;
	CONF_SECTION *server_cs;
	proto_detail_process_t *inst = talloc_get_type_abort(instance, proto_detail_process_t);
	vp_tmpl_rules_t		parse_rules;

	memset(&parse_rules, 0, sizeof(parse_rules));
	parse_rules.dict_def = dict_freeradius;

	rad_assert(listen_cs);

	server_cs = cf_item_to_section(cf_parent(listen_cs));
	rad_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	rcode = unlang_compile_subsection(server_cs, "recv", NULL, inst->recv_type, &parse_rules);
	if (rcode < 0) return rcode;
	if (rcode == 0) {
		cf_log_err(server_cs, "Failed finding 'recv { ... }' section of virtual server %s",
			   cf_section_name2(server_cs));
		return -1;
	}

	rcode = unlang_compile_subsection(server_cs, "send", "ok", inst->send_type, &parse_rules);
	if (rcode < 0) return rcode;

	rcode = unlang_compile_subsection(server_cs, "send", "fail", inst->send_type, &parse_rules);
	if (rcode < 0) return rcode;

	return 0;
}

extern fr_app_worker_t proto_detail_process;
fr_app_worker_t proto_detail_process = {
	.magic		= RLM_MODULE_INIT,
	.name		= "detail_process",
	.inst_size	= sizeof(proto_detail_process_t),
	.instantiate	= mod_instantiate,
	.entry_point	= mod_process,
};
