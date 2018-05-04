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
 * @file proto_vmps_dynamic_client.c
 * @brief VMPS dynamic clients
 *
 * @copyright 2018 The FreeRADIUS server project.
 * @copyright 2018 Alan DeKok (aland@deployingradius.com)
 */
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/unlang.h>
#include <freeradius-devel/dict.h>
#include <freeradius-devel/rad_assert.h>
#include "vqp.h"

#define CLIENT_ADD	(1)
#define CLIENT_NAK	(257)

static fr_io_final_t mod_process(REQUEST *request, fr_io_action_t action)
{
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;

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
		RDEBUG("Received %s ID %i", fr_vmps_codes[request->packet->code], request->packet->id);
		rdebug_proto_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->component = "vmps";

		unlang = cf_section_find(request->server_cs, "new", "client");
		if (!unlang) {
			RWDEBUG("Failed to find 'new client' section");
			request->reply->code = CLIENT_NAK;
			goto send_reply;
		}

		RDEBUG("Running 'new client' from file %s", cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_RECV;
		/* FALL-THROUGH */

	case REQUEST_RECV:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

		rad_assert(request->log.unlang_indent == 0);

		switch (rcode) {
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = CLIENT_ADD;
			break;

		case RLM_MODULE_FAIL:
		case RLM_MODULE_HANDLED:
			request->reply->code = 0; /* don't reply */
			break;

		default:
		case RLM_MODULE_REJECT:
			request->reply->code = CLIENT_NAK;
			break;
		}

		unlang = cf_section_find(request->server_cs, "add", "client");
		if (!unlang) goto send_reply;

	rerun_nak:
		RDEBUG("Running '%s client' from file %s", cf_section_name1(unlang), cf_filename(unlang));
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
			if (request->reply->code != 257) {
				RWDEBUG("Failed running 'add client', trying 'deny client'.");

			deny:
				request->reply->code = CLIENT_NAK;

				unlang = cf_section_find(request->server_cs, "deny", "client");
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'deny client' section as it does not exist");
			}
			break;
		}

		if (request->reply->code == CLIENT_ADD) {
			VALUE_PAIR *vp;

			vp = fr_pair_find_by_num(request->control, 0, FR_FREERADIUS_CLIENT_IP_ADDRESS, TAG_ANY);
			if (!vp) fr_pair_find_by_num(request->control, 0, FR_FREERADIUS_CLIENT_IPV6_ADDRESS, TAG_ANY);
			if (!vp) fr_pair_find_by_num(request->control, 0, FR_FREERADIUS_CLIENT_IP_PREFIX, TAG_ANY);
			if (!vp) fr_pair_find_by_num(request->control, 0, FR_FREERADIUS_CLIENT_IPV6_PREFIX, TAG_ANY);
			if (!vp) {
				ERROR("The 'control' list MUST contain a FreeRADIUS-Client.. IP address attribute");
				goto deny;
			}
		}

	send_reply:
		/*
		 *	This is an internally generated request.  Don't print IP addresses.
		 */
		if (request->reply->code == CLIENT_ADD) {
			RDEBUG("Adding client");
		} else {
			RDEBUG("Denying client");
		}
		if (RDEBUG_ENABLED) rdebug_pair_list(L_DBG_LVL_1, request, request->reply->vps, NULL);
		break;

	default:
		return FR_IO_FAIL;
	}

	return FR_IO_REPLY;
}


/*
 *	Ensure that the unlang sections are compiled.
 */
static int mod_instantiate(UNUSED void *instance, CONF_SECTION *listen_cs)
{
	int rcode;
	CONF_SECTION *server_cs;

	rad_assert(listen_cs);

	server_cs = cf_item_to_section(cf_parent(listen_cs));
	rad_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	rcode = unlang_compile_subsection(server_cs, "new", "client", MOD_AUTHORIZE);
	if (rcode < 0) return rcode;
	if (rcode == 0) {
		cf_log_err(server_cs, "Failed finding 'new client { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	rcode = unlang_compile_subsection(server_cs, "add", "client", MOD_POST_AUTH);
	if (rcode < 0) return rcode;

	rcode = unlang_compile_subsection(server_cs, "deny", "client", MOD_POST_AUTH);
	if (rcode < 0) return rcode;

	return 0;
}

extern fr_app_process_t proto_vmps_dynamic_client;
fr_app_process_t proto_vmps_dynamic_client = {
	.magic		= RLM_MODULE_INIT,
	.name		= "vmps_dynamic_client",
	.instantiate	= mod_instantiate,
	.process	= mod_process,
};
