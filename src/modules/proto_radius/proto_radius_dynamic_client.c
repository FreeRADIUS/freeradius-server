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
 * @file proto_radius_dynamic_client.c
 * @brief RADIUS Status-Server processing.
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

extern fr_dict_autoload_t proto_radius_dynamic_client_dict[];
fr_dict_autoload_t proto_radius_dynamic_client_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_freeradius_client_ip_address;
static fr_dict_attr_t const *attr_freeradius_client_ip_prefix;
static fr_dict_attr_t const *attr_freeradius_client_ipv6_address;
static fr_dict_attr_t const *attr_freeradius_client_ipv6_prefix;
static fr_dict_attr_t const *attr_freeradius_client_secret;

extern fr_dict_attr_autoload_t proto_radius_dynamic_client_dict_attr[];
fr_dict_attr_autoload_t proto_radius_dynamic_client_dict_attr[] = {
	{ .out = &attr_freeradius_client_ip_address, .name = "FreeRADIUS-Client-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_freeradius_client_ip_prefix, .name = "FreeRADIUS-Client-IP-Prefix", .type = FR_TYPE_IPV4_PREFIX, .dict = &dict_freeradius },
	{ .out = &attr_freeradius_client_ipv6_address, .name = "FreeRADIUS-Client-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_freeradius_client_ipv6_prefix, .name = "FreeRADIUS-Client-IPv6-Prefix", .type = FR_TYPE_IPV6_PREFIX, .dict = &dict_freeradius },
	{ .out = &attr_freeradius_client_secret, .name = "FreeRADIUS-Client-Secret", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL }
};

static fr_io_final_t mod_process(UNUSED void const *instance, REQUEST *request, fr_io_action_t action)
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
		RDEBUG("Received %s ID %i", fr_packet_codes[request->packet->code], request->packet->id);
		log_request_proto_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->component = "radius";

		unlang = cf_section_find(request->server_cs, "new", "client");
		if (!unlang) {
			RWDEBUG("Failed to find 'new client' section");
			request->reply->code = FR_CODE_ACCESS_REJECT;
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
			if (request->reply->code != FR_CODE_ACCESS_REJECT) {
				RWDEBUG("Failed running 'add client', trying 'deny client'.");

			deny:
				request->reply->code = FR_CODE_ACCESS_REJECT;

				unlang = cf_section_find(request->server_cs, "deny", "client");
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'deny client' section as it does not exist");
			}
			break;
		}

		if (request->reply->code == FR_CODE_ACCESS_ACCEPT) {
			VALUE_PAIR *vp;

			vp = fr_pair_find_by_da(request->control, attr_freeradius_client_ip_address, TAG_ANY);
			if (!vp) fr_pair_find_by_da(request->control, attr_freeradius_client_ipv6_address, TAG_ANY);
			if (!vp) fr_pair_find_by_da(request->control, attr_freeradius_client_ip_prefix, TAG_ANY);
			if (!vp) fr_pair_find_by_da(request->control, attr_freeradius_client_ipv6_prefix, TAG_ANY);
			if (!vp) {
				ERROR("The 'control' list MUST contain a FreeRADIUS-Client.. IP address attribute");
				goto deny;
			}

			vp = fr_pair_find_by_da(request->control, attr_freeradius_client_secret, TAG_ANY);
			if (!vp) {
				ERROR("The 'control' list MUST contain a FreeRADIUS-Client-Secret attribute");
				goto deny;
			}

			/*
			 *	Else we're flexible.
			 */
		}

	send_reply:
		/*
		 *	This is an internally generated request.  Don't print IP addresses.
		 */
		if (request->reply->code == FR_CODE_ACCESS_ACCEPT) {
			RDEBUG("Adding client");
		} else {
			RDEBUG("Denying client");
		}
		if (RDEBUG_ENABLED) log_request_pair_list(L_DBG_LVL_1, request, request->reply->vps, NULL);
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
	vp_tmpl_rules_t		parse_rules;

	memset(&parse_rules, 0, sizeof(parse_rules));
	parse_rules.dict_def = dict_freeradius;

	rad_assert(listen_cs);

	server_cs = cf_item_to_section(cf_parent(listen_cs));
	rad_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	rcode = unlang_compile_subsection(server_cs, "new", "client", MOD_AUTHORIZE, &parse_rules);
	if (rcode < 0) return rcode;
	if (rcode == 0) {
		cf_log_err(server_cs, "Failed finding 'new client { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	rcode = unlang_compile_subsection(server_cs, "add", "client", MOD_POST_AUTH, &parse_rules);
	if (rcode < 0) return rcode;

	rcode = unlang_compile_subsection(server_cs, "deny", "client", MOD_POST_AUTH, &parse_rules);
	if (rcode < 0) return rcode;

	return 0;
}

extern fr_app_worker_t proto_radius_dynamic_client;
fr_app_worker_t proto_radius_dynamic_client = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_dynamic_client",
	.instantiate	= mod_instantiate,
	.entry_point	= mod_process,
};
