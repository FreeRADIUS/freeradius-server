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
 * @file src/process/ldap_sync/base.c
 * @brief LDAP sync process module
 *
 * @copyright 2022 NetworkRADIUS SARL (legal@networkradius.com)
 */
#define LOG_PREFIX "process_ldap_sync"

#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/ldap/sync.h>

static fr_dict_t const *dict_ldap_sync;

extern fr_dict_autoload_t process_ldap_sync_dict[];
fr_dict_autoload_t process_ldap_sync_dict[] = {
	{ .out = &dict_ldap_sync, .proto = "ldap" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t process_ldap_sync_dict_attr[];
fr_dict_attr_autoload_t process_ldap_sync_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type= FR_TYPE_UINT32, .dict = &dict_ldap_sync },

	{ NULL }
};

static char const *ldap_sync_message_types[FR_LDAP_SYNC_CODE_MAX] = {
	"",					//!< 0
	"Present",
	"Add",
	"Modify",
	"Delete",
	"Entry-Response",
	"Cookie-Load",
	"Cookie-Load-Response",
	"Cookie-Store",
	"Cookie-Store-Response",
};

static void ldap_sync_packet_debug(request_t *request, fr_radius_packet_t *packet, fr_pair_list_t *list, bool received)
{

	if (!packet) return;
	if (!RDEBUG_ENABLED) return;

	log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, "%s %s",
			received ? "Received" : "Sending",
			ldap_sync_message_types[packet->code]
			);

	if (received) {
		log_request_pair_list(L_DBG_LVL_1, request, NULL, list, NULL);
	} else {
	/*
	 *	At higher debug levels, log returned data as well.
	 */
		log_request_pair_list(L_DBG_LVL_2, request, NULL, list, NULL);
	}

}

typedef struct {
	uint64_t	nothing;		// so that the next field isn't at offset 0

	CONF_SECTION	*load_cookie;
	CONF_SECTION	*store_cookie;
	CONF_SECTION	*recv_add;
	CONF_SECTION	*recv_present;
	CONF_SECTION	*recv_delete;
	CONF_SECTION	*recv_modify;
} process_ldap_sync_sections_t;

typedef struct {
	process_ldap_sync_sections_t	sections;
} process_ldap_sync_t;

#define PROCESS_PACKET_TYPE		fr_ldap_sync_packet_code_t
#define PROCESS_CODE_MAX		FR_LDAP_SYNC_CODE_MAX
#define PROCESS_PACKET_CODE_VALID	FR_LDAP_SYNC_PACKET_CODE_VALID
#define PROCESS_INST			process_ldap_sync_t
#include <freeradius-devel/server/process.h>


static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const	*state;

	(void) talloc_get_type_abort_const(mctx->inst->data, process_ldap_sync_t);

	PROCESS_TRACE;

	fr_assert(FR_LDAP_SYNC_PACKET_CODE_VALID(request->packet->code));

	request->component = "ldap_sync";
	request->module = NULL;
	fr_assert(request->dict == dict_ldap_sync);

	UPDATE_STATE(packet);

	ldap_sync_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}

static fr_process_state_t const process_state[] = {
	[ FR_LDAP_SYNC_CODE_PRESENT ] = {
		.default_reply = FR_LDAP_SYNC_CODE_ENTRY_RESPONSE,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_ldap_sync_sections_t, recv_present),
	},
	[ FR_LDAP_SYNC_CODE_ADD ] = {
		.default_reply = FR_LDAP_SYNC_CODE_ENTRY_RESPONSE,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_ldap_sync_sections_t, recv_add)
	},
	[ FR_LDAP_SYNC_CODE_DELETE ] = {
		.default_reply = FR_LDAP_SYNC_CODE_ENTRY_RESPONSE,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_ldap_sync_sections_t, recv_delete),
	},
	[ FR_LDAP_SYNC_CODE_MODIFY ] = {
		.default_reply = FR_LDAP_SYNC_CODE_ENTRY_RESPONSE,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_ldap_sync_sections_t, recv_modify),
	},
	[ FR_LDAP_SYNC_CODE_ENTRY_RESPONSE ] = {
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
	},
	[ FR_LDAP_SYNC_CODE_COOKIE_LOAD ] = {
		.default_reply = FR_LDAP_SYNC_CODE_COOKIE_LOAD_RESPONSE,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_ldap_sync_sections_t, load_cookie),
	},
	[ FR_LDAP_SYNC_CODE_COOKIE_LOAD_RESPONSE ] = {
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
	},
	[ FR_LDAP_SYNC_CODE_COOKIE_STORE ] = {
		.default_reply = FR_LDAP_SYNC_CODE_COOKIE_STORE_RESPONSE,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_ldap_sync_sections_t, store_cookie),
	},
	[ FR_LDAP_SYNC_CODE_COOKIE_STORE_RESPONSE ] = {
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
	}
};

static virtual_server_compile_t const compile_list[] = {
	{
		.name = "load",
		.name2 = "Cookie",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(load_cookie)
	},
	{
		.name = "store",
		.name2 = "Cookie",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(store_cookie)
	},
	{
		.name = "recv",
		.name2 = "Add",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(recv_add)
	},
	{
		.name = "recv",
		.name2 = "Present",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(recv_present)
	},
	{
		.name = "recv",
		.name2 = "Delete",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(recv_delete)
	},
	{
		.name = "recv",
		.name2 = "Modify",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(recv_modify)
	},

	COMPILE_TERMINATOR
};

extern fr_process_module_t process_ldap_sync;
fr_process_module_t process_ldap_sync = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "process_ldap_sync",
		.inst_size	= sizeof(process_ldap_sync_t),
	},

	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_ldap_sync,
};
