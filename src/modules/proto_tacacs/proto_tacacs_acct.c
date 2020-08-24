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
 * @file proto_tacacs_acct.c
 * @brief TACACS+ accounting handler.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/tacacs/tacacs.h>
#include "proto_tacacs.h"

typedef struct {
	CONF_SECTION	*recv_request;
	void		*unlang_request;

	CONF_SECTION	*send_reply;
	void		*unlang_reply;
} proto_tacacs_acct_t;

static fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t proto_tacacs_acct_dict[];
fr_dict_autoload_t proto_tacacs_acct_dict[] = {
	{ .out = &dict_tacacs, .proto = "tacacs" },
	{ NULL }
};

static fr_dict_attr_t const *attr_tacacs_accounting_status;
static fr_dict_attr_t const *attr_tacacs_data;
static fr_dict_attr_t const *attr_tacacs_server_message;

extern fr_dict_attr_autoload_t proto_tacacs_acct_dict_attr[];
fr_dict_attr_autoload_t proto_tacacs_acct_dict_attr[] = {
	{ .out = &attr_tacacs_accounting_status, .name = "TACACS-Accounting-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_data, .name = "TACACS-Data", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_server_message, .name = "TACACS-Server-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },

	{ NULL }
};

static void accounting_failed(REQUEST *request, char const *msg)
{
	VALUE_PAIR	*vp;

	RPEDEBUG("%s", msg);

	/*
	 *	Set the server reply message.
	 */
	if (!fr_pair_find_by_da(request->reply->vps, attr_tacacs_server_message, TAG_ANY)) {
		MEM(pair_update_reply(&vp, attr_tacacs_server_message) >= 0);
		fr_pair_value_strdup(vp, "Accounting failed");
	}

	/*
	 *	Set the status.
	 */
	MEM(pair_update_reply(&vp, attr_tacacs_accounting_status) >= 0);
	vp->vp_uint8 = FR_TACACS_ACCOUNTING_STATUS_VALUE_ERROR;
}

static rlm_rcode_t mod_process(module_ctx_t const *mctx, REQUEST *request)
{
	proto_tacacs_acct_t const	*inst = talloc_get_type_abort_const(mctx->instance, proto_tacacs_acct_t);
	rlm_rcode_t			rcode;
	fr_tacacs_packet_t const	*pkt = (fr_tacacs_packet_t const *) request->packet->data;
	VALUE_PAIR			*vp;

	REQUEST_VERIFY(request);

	switch (request->request_state) {
	case REQUEST_INIT:
		request->component = "tacacs";

		/*
		 *	We always reply, unless specifically set to "Do not respond"
		 */
		request->reply->code = FR_PACKET_TYPE_VALUE_ACCOUNTING_REPLY;

		/*
		 *	Push the conf section into the unlang stack.
		 */
		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(inst->recv_request), cf_filename(inst->recv_request));
		unlang_interpret_push_instruction(request, inst->unlang_request, RLM_MODULE_REJECT, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_RECV;
		FALL_THROUGH;

	case REQUEST_RECV:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

		switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			break;

		case RLM_MODULE_HANDLED:
			break;

		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_DISALLOW:
		default:
			accounting_failed(request, "Failed to process the accounting packet");
			break;
		}

		RDEBUG("Running 'send %s' from file %s", cf_section_name2(inst->send_reply), cf_filename(inst->send_reply));
		unlang_interpret_push_instruction(request, inst->unlang_reply, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_SEND;
		FALL_THROUGH;

	case REQUEST_SEND:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

		fr_assert(request->log.unlang_indent == 0);

		switch (rcode) {
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_DISALLOW:
		default:
			break;

		case RLM_MODULE_HANDLED:
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			/* reply code is already set */
			break;
		}

		request->reply->timestamp = fr_time();

		/*
		 *	Check for "do not respond".
		 */
		if (request->reply->code == FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND) {
			RDEBUG("Not sending reply to client.");
			break;
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
		.name2 = "Accounting-Request",
		.component = MOD_ACCOUNTING,
		.offset = offsetof(proto_tacacs_acct_t, recv_request),
		.instruction = offsetof(proto_tacacs_acct_t, unlang_request),
	},
	{
		.name = "send",
		.name2 = "Accounting-Reply",
		.component = MOD_POST_AUTH,
		.offset = offsetof(proto_tacacs_acct_t, send_reply),
		.instruction = offsetof(proto_tacacs_acct_t, unlang_reply),
	},

	COMPILE_TERMINATOR
};

extern fr_app_worker_t proto_tacacs_acct;
fr_app_worker_t proto_tacacs_acct = {
	.magic		= RLM_MODULE_INIT,
	.name		= "tacacs_acct",
	.inst_size	= sizeof(proto_tacacs_acct_t),

	.entry_point	= mod_process,
	.compile_list	= compile_list,
};
