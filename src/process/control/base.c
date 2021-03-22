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
 * @file src/process/control/base.c
 * @brief CONTROL processing.
 *
 * @copyright 2020 Network RADIUS SARL <legal@networkradius.com>
 */
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/process.h>
#include <freeradius-devel/util/debug.h>

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t process_control_dict[];
fr_dict_autoload_t process_control_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_module_failure_message;
static fr_dict_attr_t const *attr_module_success_message;

extern fr_dict_attr_autoload_t process_control_dict_attr[];
fr_dict_attr_autoload_t process_control_dict_attr[] = {
	{ .out = &attr_module_failure_message, .name = "Module-Failure-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_module_success_message, .name = "Module-Success-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ NULL }
};

static unlang_action_t mod_process(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx, UNUSED request_t *request)
{
	RETURN_MODULE_FAIL;
}

extern fr_process_module_t process_control;
fr_process_module_t process_control = {
	.magic		= RLM_MODULE_INIT,
	.name		= "process_control",
	.process	= mod_process,
	.dict		= &dict_freeradius,
};
