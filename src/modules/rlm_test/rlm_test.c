/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_test.c
 * @brief test module code.
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 your name (email@example.org)
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->mi->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/unlang/xlat_func.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	tmpl_t		*tmpl;
	tmpl_t		**tmpl_m;
	char const	*string;
	char const	**string_m;

	bool		boolean;
	bool		*boolean_m;

	uint32_t	integer;
	uint32_t	*integer_m;

	fr_ipaddr_t	ipv4_addr;
	fr_ipaddr_t	ipv4_prefix;

	fr_ipaddr_t	ipv6_addr;
	fr_ipaddr_t	ipv6_prefix;

	fr_ipaddr_t	combo_ipaddr;

	fr_ipaddr_t	*ipv4_addr_m;
	fr_ipaddr_t	*ipv4_prefix_m;

	fr_ipaddr_t	*ipv6_addr_m;
	fr_ipaddr_t	*ipv6_prefix_m;

	fr_ipaddr_t	*combo_ipaddr_m;

	fr_ipaddr_t	ipaddr;

	fr_time_t	date;
	fr_time_t	*date_m;

	uint8_t const	*octets;
	uint8_t const	**octets_m;

	uint8_t		byte;
	uint8_t		*byte_m;

	fr_ifid_t	ifid;
	/*
	 *	clang correctly performs type compatibility checks between
	 *	arrays with a specific length, but for pointers to pointers
	 *	to arrays of specific length
	 *	(which is what FR_TYPE_CONF_CHECK receives) the check doesn't
	 *	seem to work.
	 *
	 *	So the "multi" variants of ethernet and ifid buffers, must
	 *	be a **.
	 */
	fr_ifid_t	*ifid_m;
	uint16_t	shortint;
	uint16_t	*shortint_m;

	fr_ethernet_t	ethernet;
	/*
	 *	See above...
	 */
	fr_ethernet_t	*ethernet_m;

	int32_t		int32;
	int32_t		*int32_m;

	uint64_t	uint64;
	uint64_t	*uint64_m;

	fr_time_delta_t	time_delta;
	fr_time_delta_t	*time_delta_m;
} rlm_test_t;

typedef struct {
	rlm_test_t	*inst;
	pthread_t	value;
} rlm_test_thread_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("tmpl", rlm_test_t, tmpl), .dflt = "Tmp-String-0", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("tmpl_m", rlm_test_t, tmpl_m), .dflt = "Tmp-String-0", .quote = T_DOUBLE_QUOTED_STRING },

	{ FR_CONF_OFFSET("string", rlm_test_t, string) },
	{ FR_CONF_OFFSET("string_m", rlm_test_t, string_m) },

	{ FR_CONF_OFFSET("boolean", rlm_test_t, boolean), .dflt = "no" },
	{ FR_CONF_OFFSET("boolean_m", rlm_test_t, boolean_m), .dflt = "no" },

	{ FR_CONF_OFFSET("integer", rlm_test_t, integer), .dflt = "1" },
	{ FR_CONF_OFFSET_FLAGS("integer_m" , CONF_FLAG_MULTI, rlm_test_t, integer_m), .dflt = "2" },

	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4_addr", FR_TYPE_IPV4_ADDR, 0, rlm_test_t, ipv4_addr), .dflt = "*" },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4_addr_m", FR_TYPE_IPV4_ADDR, CONF_FLAG_MULTI, rlm_test_t, ipv4_addr_m), .dflt = "*" },

	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4_prefix", FR_TYPE_IPV4_PREFIX, 0, rlm_test_t, ipv4_addr), .dflt = "192.168.0.1/24" },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4_prefix_m", FR_TYPE_IPV4_PREFIX, CONF_FLAG_MULTI, rlm_test_t, ipv4_addr_m), .dflt = "192.168.0.1/24" },

	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6_addr", FR_TYPE_IPV6_ADDR, 0, rlm_test_t, ipv6_addr), .dflt = "*" },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6_addr_m", FR_TYPE_IPV6_ADDR, CONF_FLAG_MULTI, rlm_test_t, ipv6_addr_m), .dflt = "*" },

	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6_prefix", FR_TYPE_IPV6_PREFIX, 0, rlm_test_t, ipv6_prefix), .dflt = "::1/128" },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6_prefix_m", FR_TYPE_IPV6_PREFIX, CONF_FLAG_MULTI, rlm_test_t, ipv6_prefix_m), .dflt = "::1/128" },

	{ FR_CONF_OFFSET_TYPE_FLAGS("combo", FR_TYPE_COMBO_IP_ADDR, 0, rlm_test_t, combo_ipaddr), .dflt = "::1/128" },
	{ FR_CONF_OFFSET_TYPE_FLAGS("combo_m", FR_TYPE_COMBO_IP_ADDR, CONF_FLAG_MULTI, rlm_test_t, combo_ipaddr_m), .dflt = "::1/128" },

	{ FR_CONF_OFFSET("date", rlm_test_t, date) },
	{ FR_CONF_OFFSET("date_m", rlm_test_t, date_m) },

	{ FR_CONF_OFFSET("octets", rlm_test_t, octets) },
	{ FR_CONF_OFFSET("octets_m", rlm_test_t, octets_m) },

	{ FR_CONF_OFFSET("bytes", rlm_test_t, byte) },
	{ FR_CONF_OFFSET("bytes_m", rlm_test_t, byte_m) },

	{ FR_CONF_OFFSET("ifid", rlm_test_t, ifid) },
	{ FR_CONF_OFFSET("ifid_m", rlm_test_t, ifid_m) },

	{ FR_CONF_OFFSET("short", rlm_test_t, shortint) },
	{ FR_CONF_OFFSET("short_m", rlm_test_t, shortint_m) },

	{ FR_CONF_OFFSET("ethernet", rlm_test_t, ethernet) },
	{ FR_CONF_OFFSET("ethernet_m", rlm_test_t, ethernet_m) },

	{ FR_CONF_OFFSET("signed", rlm_test_t, int32) },
	{ FR_CONF_OFFSET("signed_m", rlm_test_t, int32_m) },

	{ FR_CONF_OFFSET("uint64", rlm_test_t, uint64) },
	{ FR_CONF_OFFSET("uint64_m", rlm_test_t, uint64_m) },

	{ FR_CONF_OFFSET("time_delta", rlm_test_t, time_delta) },
	{ FR_CONF_OFFSET("time_delta_t", rlm_test_t, time_delta_m) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_test_dict[];
fr_dict_autoload_t rlm_test_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_user_name;

extern fr_dict_attr_autoload_t rlm_test_dict_attr[];
fr_dict_attr_autoload_t rlm_test_dict_attr[] = {
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	DICT_AUTOLOAD_TERMINATOR
};

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_test_thread_t *t = mctx->thread;

	RINFO("RINFO message");
	RDEBUG("RDEBUG message");
	RDEBUG2("RDEBUG2 message");

	RWARN("RWARN message");
	RWDEBUG("RWDEBUG message");
	RWDEBUG("RWDEBUG2 message");

	/*
	 *	 Should appear wavy
	 */
	RERROR("RERROR error message");
	RINDENT();
	REDEBUG("RDEBUG error message");
	REXDENT();
	REDEBUG2("RDEBUG2 error message");
	RINDENT();
	REDEBUG3("RDEBUG3 error message");
	REXDENT();
	REDEBUG4("RDEBUG4 error message");

	if (!fr_cond_assert(t->value == pthread_self())) RETURN_UNLANG_FAIL;

	RETURN_UNLANG_OK;
}

/*
 *	Authenticate the user with the given password.
 */
static unlang_action_t CC_HINT(nonnull) mod_authenticate(unlang_result_t *p_result, module_ctx_t const *mctx, UNUSED request_t *request)
{
	rlm_test_thread_t *t = mctx->thread;

	if (!fr_cond_assert(t->value == pthread_self())) RETURN_UNLANG_FAIL;

	RETURN_UNLANG_OK;
}

/*
 *	Massage the request before recording it or proxying it
 */
static unlang_action_t CC_HINT(nonnull) mod_preacct(unlang_result_t *p_result, module_ctx_t const *mctx, UNUSED request_t *request)
{
	rlm_test_thread_t *t = mctx->thread;

	if (!fr_cond_assert(t->value == pthread_self())) RETURN_UNLANG_FAIL;

	RETURN_UNLANG_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static unlang_action_t CC_HINT(nonnull) mod_accounting(unlang_result_t *p_result, module_ctx_t const *mctx, UNUSED request_t *request)
{
	rlm_test_thread_t *t = mctx->thread;

	if (!fr_cond_assert(t->value == pthread_self())) RETURN_UNLANG_FAIL;

	RETURN_UNLANG_OK;
}

/*
 *	Write accounting information to this modules database.
 */
static unlang_action_t CC_HINT(nonnull) mod_return(unlang_result_t *p_result, UNUSED module_ctx_t const *mctx, UNUSED request_t *request)
{
	RETURN_UNLANG_OK;
}

static void mod_retry_signal(module_ctx_t const *mctx, request_t *request, fr_signal_t action);

/** Continue after marked runnable
 *
 */
static unlang_action_t mod_retry_resume(unlang_result_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	RDEBUG("Test called main retry handler - that's a failure");

	RETURN_UNLANG_FAIL;
}

/** Continue after FR_SIGNAL_RETRY
 *
 */
static unlang_action_t mod_retry_resume_retry(UNUSED unlang_result_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	RDEBUG("Test retry");

	return unlang_module_yield(request, mod_retry_resume, mod_retry_signal, 0, NULL);
}

/** Continue after FR_SIGNAL_TIMEOUT
 *
 */
static unlang_action_t mod_retry_resume_timeout(unlang_result_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	RDEBUG("Test timed out as expected");

	RETURN_UNLANG_OK;
}

static void mod_retry_signal(UNUSED module_ctx_t const *mctx, request_t *request, fr_signal_t action)
{
	switch (action) {
	case FR_SIGNAL_RETRY:
		RDEBUG("Test retry");
		unlang_module_set_resume(request, mod_retry_resume_retry);
		unlang_interpret_mark_runnable(request);
		break;

	case FR_SIGNAL_TIMEOUT:
		RDEBUG("Test timeout");
		unlang_module_set_resume(request, mod_retry_resume_timeout);
		unlang_interpret_mark_runnable(request);
		break;

	/*
	 *	Ignore all other signals.
	 */
	default:
		break;
	}

}

/*
 *	Test retries
 */
static unlang_action_t CC_HINT(nonnull) mod_retry(UNUSED unlang_result_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	return unlang_module_yield(request, mod_retry_resume, mod_retry_signal, 0, NULL);
}


static xlat_arg_parser_t const trigger_test_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};


/** Run a trigger (useful for testing)
 *
 */
static xlat_action_t trigger_test_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				       UNUSED xlat_ctx_t const *xctx, request_t *request,
				       fr_value_box_list_t *in)
{
	fr_value_box_t	*in_head = fr_value_box_list_head(in);
	fr_value_box_t	*vb;

	if (trigger(unlang_interpret_get(request), NULL, NULL, in_head->vb_strvalue, false, NULL) < 0) {
		RPEDEBUG("Running trigger failed");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));
	fr_dcursor_append(out, vb);
	vb->vb_bool = true;

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const test_xlat_passthrough_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};


/** Run a generic xlat (useful for testing)
 *
 * This just copies the input to the output.
 */
static xlat_action_t test_xlat_passthrough(TALLOC_CTX *ctx, fr_dcursor_t *out,
			                   UNUSED xlat_ctx_t const *xctx, UNUSED request_t *request,
			                   fr_value_box_list_t *in)
{
	fr_value_box_t	*vb;

	fr_value_box_list_foreach(in, vb_p) {
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_STRING, NULL));

		if (unlikely(fr_value_box_copy(vb, vb, vb_p) < 0)) {
			talloc_free(vb);
			return XLAT_ACTION_FAIL;
		}

		fr_dcursor_append(out, vb);
	}

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const test_xlat_fail_args[] = {
	{ .required = false, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};


/** Always return XLAT_ACTION_FAIL
 */
static xlat_action_t test_xlat_fail(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx, UNUSED request_t *request,
				    UNUSED fr_value_box_list_t *in)
{
	return XLAT_ACTION_FAIL;
}


/** Always return a NULL value-box
 */
static xlat_action_t test_xlat_null(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    UNUSED xlat_ctx_t const *xctx, UNUSED request_t *request,
				    UNUSED fr_value_box_list_t *in)
{
	fr_value_box_t	*vb;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_NULL, NULL));
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_test_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_test_t);
	rlm_test_thread_t *t = talloc_get_type_abort(mctx->thread, rlm_test_thread_t);

	t->inst = inst;
	t->value = pthread_self();
	INFO("Performing instantiation for thread %p (ctx %p)", (void *)t->value, t);

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_test_thread_t *t = talloc_get_type_abort(mctx->thread, rlm_test_thread_t);

	INFO("Performing detach for thread %p", (void *)t->value);

	if (!fr_cond_assert(t->value == pthread_self())) return -1;

	return 0;
}

/*
 *	Do any per-module bootstrapping that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_test_t const *inst = talloc_get_type_abort(mctx->mi->data, rlm_test_t);
	xlat_t *xlat;

	/*
	 *	Log some messages
	 */
	INFO("Informational message");
	WARN("Warning message");
	ERROR("Error message");
	DEBUG("Debug message");
	DEBUG2("Debug2 message");
	DEBUG3("Debug3 message");
	DEBUG4("Debug4 message");

	/*
	 *	Output parsed tmpls
	 */
	if (inst->tmpl) {
		INFO("%s", inst->tmpl->name);
	} else {
		INFO("inst->tmpl is NULL");
	}

	if (inst->tmpl_m) {
		talloc_foreach(inst->tmpl_m,  item) INFO("%s", item->name);
	} else {
		INFO("inst->tmpl_m is NULL");
	}

	if (!(xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "passthrough", test_xlat_passthrough, FR_TYPE_VOID))) return -1;
	xlat_func_args_set(xlat, test_xlat_passthrough_args);

	if (!(xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "fail", test_xlat_fail, FR_TYPE_VOID))) return -1;
	xlat_func_args_set(xlat, test_xlat_fail_args);

	if (!module_rlm_xlat_register(mctx->mi->boot, mctx, "null", test_xlat_null, FR_TYPE_VOID)) return -1;

	return 0;
}

static int mod_load(void)
{
	xlat_t	*xlat;

	if (!(xlat = xlat_func_register(NULL, "test_trigger", trigger_test_xlat, FR_TYPE_BOOL))) return -1;
	xlat_func_args_set(xlat, trigger_test_xlat_args);

	return 0;
}

static void mod_unload(void)
{
	xlat_func_unregister("test_trigger");
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_test;
module_rlm_t rlm_test = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "test",
		.flags			= MODULE_TYPE_RETRY,
		.inst_size		= sizeof(rlm_test_t),
		.thread_inst_size	= sizeof(rlm_test_thread_t),
		.config			= module_config,
		.bootstrap		= mod_bootstrap,
		.onload			= mod_load,
		.unload			= mod_unload,
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("accounting", CF_IDENT_ANY),		.method = mod_accounting },
			{ .section = SECTION_NAME("authenticate", CF_IDENT_ANY),	.method = mod_authenticate },
			{ .section = SECTION_NAME("authorize", CF_IDENT_ANY),		.method = mod_authorize },

			{ .section = SECTION_NAME("name1_null", NULL),			.method = mod_return },

			{ .section = SECTION_NAME("recv", "Access-Challenge"),		.method = mod_return },
			{ .section = SECTION_NAME("recv", "Accounting-Request"),	.method = mod_preacct },
			{ .section = SECTION_NAME("recv", CF_IDENT_ANY),		.method = mod_authorize },

			{ .section = SECTION_NAME("retry", NULL),			.method = mod_retry },
			{ .section = SECTION_NAME("send", CF_IDENT_ANY),		.method = mod_return },

			MODULE_BINDING_TERMINATOR
		}
	}
};
