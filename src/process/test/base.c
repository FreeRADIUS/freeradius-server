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
 * @file src/process/test/base.c
 * @brief Test state machine, which only does request and reply.
 *
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/debug.h>

static fr_dict_t const *dict_test;

extern fr_dict_autoload_t process_test_dict[];
fr_dict_autoload_t process_test_dict[] = {
	{ .out = &dict_test, .proto = "test" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t process_test_dict_attr[];
fr_dict_attr_autoload_t process_test_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_test},
	DICT_AUTOLOAD_TERMINATOR
};

typedef struct {
	uint64_t	nothing;		// so that the next field isn't at offset 0

	CONF_SECTION	*recv_request;
	CONF_SECTION	*send_reply;
} process_test_sections_t;

typedef struct {
	bool		test;

	process_test_sections_t	sections;
} process_test_t;

typedef enum {
	FR_TEST_INVALID = 0,
	FR_TEST_REQUEST,
	FR_TEST_REPLY,
} fr_test_packet_code_t;
#define FR_TEST_CODE_MAX (3)

#define FR_TEST_PACKET_CODE_VALID(_code) ((_code == FR_TEST_REQUEST) || (_code == FR_TEST_REPLY))

#define PROCESS_PACKET_TYPE		fr_test_packet_code_t
#define PROCESS_CODE_MAX		FR_TEST_CODE_MAX
#define PROCESS_PACKET_CODE_VALID	FR_TEST_PACKET_CODE_VALID
#define PROCESS_INST			process_test_t
#include <freeradius-devel/server/process.h>

static fr_process_state_t const process_state[] = {
	[ FR_TEST_REQUEST ] = {
		.default_reply = FR_TEST_REPLY,
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_test_sections_t, recv_request),
	},
	[ FR_TEST_REPLY ] = {
		.default_reply = FR_TEST_REPLY,
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_test_sections_t, send_reply),
	},
};

static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->mi->data, process_test_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "test";
	request->module = NULL;
	fr_assert(request->proto_dict == dict_test);

	UPDATE_STATE(packet);

	return state->recv(p_result, mctx, request);
}

static const virtual_server_compile_t compile_list[] = {
	{
		.section = SECTION_NAME("recv", "Request"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(recv_request),
	},
	{
		.section = SECTION_NAME("send", "Reply"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(send_reply),
	},

	COMPILE_TERMINATOR
};


extern fr_process_module_t process_test;
fr_process_module_t process_test = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "test",
		MODULE_INST(process_test_t),
		MODULE_RCTX(process_rctx_t)
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_test,
	.packet_type	= &attr_packet_type,
};
