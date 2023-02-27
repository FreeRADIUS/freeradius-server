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
 * @file src/process/bfd/base.c
 * @brief BFD processing.
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/debug.h>

static fr_dict_t const *dict_bfd;

extern fr_dict_autoload_t process_bfd_dict[];
fr_dict_autoload_t process_bfd_dict[] = {
	{ .out = &dict_bfd, .proto = "bfd" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t process_bfd_dict_attr[];
fr_dict_attr_autoload_t process_bfd_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_bfd},
	{ NULL }
};

#define SECTION(_x) \
	CONF_SECTION *recv_ ## _x; \
	CONF_SECTION *send_ ## _x

typedef struct {
	uint64_t	nothing;		// so that the next field isn't at offset 0

	SECTION(admin_down);
	SECTION(down);
	SECTION(init);
	SECTION(up);
} process_bfd_sections_t;

typedef struct {
	bool		unused;

	process_bfd_sections_t	sections;
} process_bfd_t;

typedef enum {
	FR_BFD_ADMIN_DOWN,
	FR_BFD_DOWN,
	FR_BFD_INIT,
	FR_BFD_UP,
} fr_bfd_packet_code_t;
#define FR_BFD_CODE_MAX (4)

#define FR_BFD_PACKET_CODE_VALID(_code) (_code < FR_BFD_CODE_MAX)

#define PROCESS_PACKET_TYPE		fr_bfd_packet_code_t
#define PROCESS_CODE_MAX		FR_BFD_CODE_MAX
#define PROCESS_PACKET_CODE_VALID	FR_BFD_PACKET_CODE_VALID
#define PROCESS_INST			process_bfd_t

#define PROCESS_SEND_RECV		(1)

#include <freeradius-devel/server/process.h>

/*
 *	recv FOO
 */
static fr_process_state_t const process_state_packet[] = {
	[ FR_BFD_ADMIN_DOWN ] = {
		.default_reply = FR_BFD_DOWN,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_bfd_sections_t, recv_admin_down),
	},

	[ FR_BFD_DOWN ] = {
		.default_reply = FR_BFD_DOWN,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_bfd_sections_t, recv_down),
	},

	[ FR_BFD_INIT ] = {
		.default_reply = FR_BFD_UP,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_bfd_sections_t, recv_init),
	},

	[ FR_BFD_UP ] = {
		.default_reply = FR_BFD_UP,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_bfd_sections_t, recv_up),
	},
};

/*
 *	send FOO
 */
static fr_process_state_t const process_state_reply[] = {
	[ FR_BFD_ADMIN_DOWN ] = {
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_bfd_sections_t, send_admin_down),
	},

	[ FR_BFD_DOWN ] = {
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_bfd_sections_t, send_down),
	},

	[ FR_BFD_INIT ] = {
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_bfd_sections_t, send_init),
	},

	[ FR_BFD_UP ] = {
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_bfd_sections_t, send_up),
	},
};

static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->inst->data, process_bfd_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "bfd";
	request->module = NULL;
	fr_assert(request->dict == dict_bfd);

	UPDATE_STATE(packet);

	return state->recv(p_result, mctx, request);
}

/*
 *	We send and receive the same packet types.
 */
#define SEND_RECV(_x, _y) \
	{ \
		.name = "recv", \
		.name2 = _x, \
		.component = MOD_POST_AUTH, \
		.offset = PROCESS_CONF_OFFSET(recv_ ## _y), \
	}, \
	{ \
		.name = "send", \
		.name2 = _x, \
		.component = MOD_POST_AUTH, \
		.offset = PROCESS_CONF_OFFSET(send_ ## _y), \
	}

static const virtual_server_compile_t compile_list[] = {
	SEND_RECV("Admin-Down", admin_down),
	SEND_RECV("Down", down),
	SEND_RECV("Init", init),
	SEND_RECV("Up", up),

	COMPILE_TERMINATOR
};


extern fr_process_module_t process_bfd;
fr_process_module_t process_bfd = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "bfd",
		.inst_size	= sizeof(process_bfd_t),
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_bfd,
};
