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
 * @file rlm_unbound.c
 * @brief DNS services via libunbound.
 *
 * @copyright 2013 The FreeRADIUS server project
 * @copyright 2013 Brian S. Julin (bjulin@clarku.edu)
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_unbound - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/log.h>
#include <fcntl.h>

#include "io.h"
#include "log.h"

typedef struct {
	char const	*name;

	uint32_t	timeout;

	char const	*filename;
} rlm_unbound_t;

typedef struct {
	struct ub_ctx		*ub;		/* this must come first.  Do not move */
	rlm_unbound_t		*inst;		/* Instance data */
	unbound_log_t		*u_log;
} unbound_xlat_thread_inst_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_unbound_t, filename), .dflt = "${modconfdir}/unbound/default.conf" },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, rlm_unbound_t, timeout), .dflt = "3000" },
	CONF_PARSER_TERMINATOR
};

/*
 *	Callback sent to libunbound for xlat functions.  Simply links the
 *	new ub_result via a pointer that has been allocated from the heap.
 *	This pointer has been pre-initialized to a magic value.
 */
static void link_ubres(void *my_arg, int err, struct ub_result *result)
{
	struct ub_result **ubres = (struct ub_result **)my_arg;

	/*
	 *	Note that while result will be NULL on error, we are explicit
	 *	here because that is actually a behavior that is suboptimal
	 *	and only documented in the examples.  It could change.
	 */
	if (err) {
		ERROR("%s", ub_strerror(err));
		*ubres = NULL;
	} else {
		*ubres = result;
	}
}

/*
 *	Convert labels as found in a DNS result to a NULL terminated string.
 *
 *	Result is written to memory pointed to by "out" but no result will
 *	be written unless it and its terminating NULL character fit in "left"
 *	bytes.  Returns the number of bytes written excluding the terminating
 *	NULL, or -1 if nothing was written because it would not fit or due
 *	to a violation in the labels format.
 */
static int rrlabels_tostr(char *out, char *rr, size_t left)
{
	int offset = 0;

	/*
	 * TODO: verify that unbound results (will) always use this label
	 * format, and review the specs on this label format for nuances.
	 */

	if (!left) {
		return -1;
	}
	if (left > 253) {
		left = 253; /* DNS length limit */
	}
	/* As a whole this should be "NULL terminated" by the 0-length label */
	if (strnlen(rr, left) > left - 1) {
		return -1;
	}

	/* It will fit, but does it it look well formed? */
	while (1) {
		size_t count;

		count = *((unsigned char *)(rr + offset));
		if (!count) break;

		offset++;
		if (count > 63 || strlen(rr + offset) < count) {
			return -1;
		}
		offset += count;
	}

	/* Data is valid and fits.  Copy it. */
	offset = 0;
	while (1) {
		int count;

		count = *((unsigned char *)(rr));
		if (!count) break;

		if (offset) {
			*(out + offset) = '.';
			offset++;
		}

		rr++;
		memcpy(out + offset, rr, count);
		rr += count;
		offset += count;
	}

	*(out + offset) = '\0';
	return offset;
}

static int ub_common_wait(unbound_xlat_thread_inst_t const *xt, request_t *request,
			  char const *name, struct ub_result **ub, int async_id)
{
	useconds_t iv, waited;

	iv = xt->inst->timeout > 64 ? 64000 : xt->inst->timeout * 1000;
	ub_process(xt->ub);
	for (waited = 0; (void const *)*ub == (void const *)xt; waited += iv, iv *= 2) {

		if (waited + iv > (useconds_t)xt->inst->timeout * 1000) {
			usleep(xt->inst->timeout * 1000 - waited);
			ub_process(xt->ub);
			break;
		}

		usleep(iv);

		/* Check if already handled by event loop */
		if ((void const *)*ub != (void const *)xt) {
			break;
		}

		/* In case we are running single threaded */
		ub_process(xt->ub);
	}

	if ((void const *)*ub == (void const *)xt) {
		int res;

		REDEBUG2("%s - DNS took too long", name);

		res = ub_cancel(xt->ub, async_id);
		if (res) {
			REDEBUG("%s - ub_cancel: %s", name, ub_strerror(res));
		}
		return -1;
	}

	return 0;
}

static int ub_common_fail(request_t *request, char const *name, struct ub_result *ub)
{
	if (ub->bogus) {
		RWDEBUG("%s - Bogus DNS response", name);
		return -1;
	}

	if (ub->nxdomain) {
		RDEBUG2("%s - NXDOMAIN", name);
		return -1;
	}

	if (!ub->havedata) {
		RDEBUG2("%s - Empty result", name);
		return -1;
	}

	return 0;
}

typedef struct {
	struct ub_result	*result;	//!< The result from the previous operation.
} dns_resume_ctx_t;

/*
static xlat_action_t xlat_ptr(TALLOC_CTX *ctx, fr_cursor_t *out,
			      request_t *request, void const *xlat_inst, void *xlat_thread_inst,
			      fr_value_box_t **in)
{
	if (!*in) return XLAT_ACTION_DONE;

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		RPEDEBUG("Failed concatenating input string for attribute reference");
		return XLAT_ACTION_FAIL;
	}

	yield_to

}
*/


static xlat_arg_parser_t const xlat_unbound_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Perform a DNS lookup using libunbound
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_unbound(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
			      UNUSED void const *xlat_inst, void *xlat_thread_inst,
			      fr_value_box_list_t *in)
{
	fr_value_box_t			*host_vb = fr_dlist_head(in);
	fr_value_box_t			*query_vb = fr_dlist_next(in, host_vb);
	struct ub_result		**ubres;
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(xlat_thread_inst, unbound_xlat_thread_inst_t);
	int				async_id;
	fr_type_t			return_type;
	fr_value_box_t			*vb;

	if (host_vb->length == 0) {
		REDEBUG("Can't resolve zero length host");
		return XLAT_ACTION_FAIL;
	}

	/* This has to be on the heap, because of threads */
	ubres = talloc(xt, struct ub_result *);

	/*
	 *	When a result is parsed, ubres points at the new result
	 *	This is used to mark that the processing is incomplete
	 *	- see ub_common_wait
	 */
	memcpy(ubres, &xt, sizeof(*ubres));

	if (strcmp(query_vb->vb_strvalue, "A") == 0) {
		ub_resolve_async(xt->ub, host_vb->vb_strvalue, 1, 1, ubres, link_ubres, &async_id);
		return_type = FR_TYPE_IPV4_ADDR;
	} else if (strcmp(query_vb->vb_strvalue, "AAAA") == 0) {
		ub_resolve_async(xt->ub, host_vb->vb_strvalue, 28, 1, ubres, link_ubres, &async_id);
		return_type = FR_TYPE_IPV6_ADDR;
	} else if (strcmp(query_vb->vb_strvalue, "PTR") == 0) {
		ub_resolve_async(xt->ub, host_vb->vb_strvalue, 12, 1, ubres, link_ubres, &async_id);
		return_type = FR_TYPE_STRING;
	} else {
		REDEBUG("Invalid DNS query type");
		return XLAT_ACTION_FAIL;
	}

	if (ub_common_wait(xt, request, xt->inst->name, ubres, async_id)) {
	error0:
		talloc_free(ubres);
		return XLAT_ACTION_FAIL;
	}

	if (!(*ubres)) {
		RWDEBUG("%s - No result", xt->inst->name);
		goto error0;
	}

	if (ub_common_fail(request, xt->inst->name, *ubres)) {
	error1:
		ub_resolve_free(*ubres);
		goto error0;
	}

	vb = fr_value_box_alloc_null(ctx);
	switch (return_type) {
	case FR_TYPE_IPV4_ADDR:
	case FR_TYPE_IPV6_ADDR:
		if (fr_value_box_from_network(ctx, vb, return_type, NULL, (uint8_t *)(*ubres)->data[0], (*ubres)->len[0], true) < 0) {
		error2:
			talloc_free(vb);
			goto error1;
		}
		break;
	case FR_TYPE_STRING:
		if (rrlabels_tovb(vb, (*ubres)->data[0]) == XLAT_ACTION_FAIL) goto error2;
		break;
	default:
		goto error2;
	}

	ub_resolve_free(*ubres);
	talloc_free(ubres);

	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

static int mod_xlat_thread_instantiate(UNUSED void *xlat_inst, void *xlat_thread_inst,
				       UNUSED xlat_exp_t const *exp, void *uctx)
{
	rlm_unbound_t			*inst = talloc_get_type_abort(uctx, rlm_unbound_t);
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(xlat_thread_inst, unbound_xlat_thread_inst_t);
	int				res;

	xt->inst = inst;

	xt->ub = ub_ctx_create();
	if (!xt->ub) {
		ERROR("ub_ctx_create failed");
		return -1;
	}

	/*
	 *	Note unbound threads WILL happen with -s option, if it matters.
	 *	We cannot tell from here whether that option is in effect.
	 */
	res = ub_ctx_async(xt->ub, 1);
	if (res) {
	error:
		ERROR("%s", ub_strerror(res));
		return -1;
	}

	/* Now load the config file, which can override gleaned settings. */
	res = ub_ctx_config(xt->ub, UNCONST(char *, inst->filename));
	if (res) goto error;
	if (unbound_log_init(xt, &xt->u_log, xt->ub) < 0) goto error;

	/*
	 *  Now we need to finalize the context.
	 *
	 *  There's no clean API to just finalize the context made public
	 *  in libunbound.  But we can trick it by trying to delete data
	 *  which as it happens fails quickly and quietly even though the
	 *  data did not exist.
	 */
	ub_ctx_data_remove(xt->ub, "notar33lsite.foo123.nottld A 127.0.0.1");
	return 0;
}

static int mod_xlat_thread_detach(void *xlat_thread_inst, UNUSED void *uctx)
{
	unbound_xlat_thread_inst_t	*xt = talloc_get_type_abort(xlat_thread_inst, unbound_xlat_thread_inst_t);

	ub_process(xt->ub);
	talloc_free(xt->u_log);
	ub_ctx_delete(xt->ub);
	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_unbound_t	*inst = instance;
	xlat_t		*xlat;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	if (inst->timeout > 10000) {
		cf_log_err(conf, "timeout must be 0 to 10000");
		return -1;
	}

	if(!(xlat = xlat_register(NULL, inst->name, xlat_unbound, false))) return -1;
	xlat_func_args(xlat, xlat_unbound_args);
	xlat_async_thread_instantiate_set(xlat, mod_xlat_thread_instantiate, unbound_xlat_thread_inst_t, mod_xlat_thread_detach, inst);

	return 0;
}

extern module_t rlm_unbound;
module_t rlm_unbound = {
	.magic			= RLM_MODULE_INIT,
	.name			= "unbound",
	.type			= RLM_TYPE_THREAD_SAFE,
	.inst_size		= sizeof(rlm_unbound_t),
	.config			= module_config,
	.bootstrap		= mod_bootstrap,
};
