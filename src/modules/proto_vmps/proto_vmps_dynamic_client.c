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
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/vqp/vqp.h>

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_vmps;

extern fr_dict_autoload_t proto_vmps_dynamic_client_dict[];
fr_dict_autoload_t proto_vmps_dynamic_client_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_vmps, .proto = "vmps" },
	{ NULL }
};

static fr_dict_attr_t const *attr_freeradius_client_ip_address;
static fr_dict_attr_t const *attr_freeradius_client_ip_prefix;
static fr_dict_attr_t const *attr_freeradius_client_ipv6_address;
static fr_dict_attr_t const *attr_freeradius_client_ipv6_prefix;

extern fr_dict_attr_autoload_t proto_vmps_dynamic_client_dict_attr[];
fr_dict_attr_autoload_t proto_vmps_dynamic_client_dict_attr[] = {
	{ .out = &attr_freeradius_client_ip_address, .name = "FreeRADIUS-Client-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_freeradius_client_ip_prefix, .name = "FreeRADIUS-Client-IP-Prefix", .type = FR_TYPE_IPV4_PREFIX, .dict = &dict_freeradius },
	{ .out = &attr_freeradius_client_ipv6_address, .name = "FreeRADIUS-Client-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_freeradius_client_ipv6_prefix, .name = "FreeRADIUS-Client-IPv6-Prefix", .type = FR_TYPE_IPV6_PREFIX, .dict = &dict_freeradius },
	{ NULL }
};

#define CLIENT_ADD	(1)
#define CLIENT_NAK	(257)

static rlm_rcode_t mod_process(UNUSED void const *instance, REQUEST *request)
{
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;

	REQUEST_VERIFY(request);

	switch (request->request_state) {
	case REQUEST_INIT:
		RDEBUG("Received %s ID %i", fr_vmps_codes[request->packet->code], request->packet->id);
		log_request_proto_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->component = "vmps";

		unlang = cf_section_find(request->server_cs, "new", "client");
		if (!unlang) {
			RWDEBUG("Failed to find 'new client' section");
			request->reply->code = CLIENT_NAK;
			goto send_reply;
		}

		RDEBUG("Running 'new client' from file %s", cf_filename(unlang));
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

			vp = fr_pair_find_by_da(request->control, attr_freeradius_client_ip_address, TAG_ANY);
			if (!vp) fr_pair_find_by_da(request->control, attr_freeradius_client_ipv6_address, TAG_ANY);
			if (!vp) fr_pair_find_by_da(request->control, attr_freeradius_client_ip_prefix, TAG_ANY);
			if (!vp) fr_pair_find_by_da(request->control, attr_freeradius_client_ipv6_prefix, TAG_ANY);
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
		if (RDEBUG_ENABLED) log_request_pair_list(L_DBG_LVL_1, request, request->reply->vps, NULL);
		break;

	default:
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}


static virtual_server_compile_t compile_list[] = {
	{
		.name = "new",
		.name2 = "client",
		.component = MOD_AUTHORIZE,
	},
	{
		.name = "add",
		.name2 = "client",
		.component = MOD_POST_AUTH,
	},
	{
		.name = "deny",
		.name2 = "client",
		.component = MOD_POST_AUTH,
	},

	COMPILE_TERMINATOR
};

extern fr_app_worker_t proto_vmps_dynamic_client;
fr_app_worker_t proto_vmps_dynamic_client = {
	.magic		= RLM_MODULE_INIT,
	.name		= "vmps_dynamic_client",
	.entry_point	= mod_process,
	.compile_list	= compile_list,
};
