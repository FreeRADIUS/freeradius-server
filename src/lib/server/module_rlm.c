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
 *
 * @file src/lib/server/module_rlm.c
 * @brief Defines functions for rlm module (re-)initialisation.
 *
 * @copyright 2003,2006,2016 The FreeRADIUS server project
 * @copyright 2016,2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2000 Alan Curry (pacman@world.std.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/cf_file.h>

#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/pair.h>

#include <freeradius-devel/util/atexit.h>

#include <freeradius-devel/unlang/compile.h>

#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/xlat_redundant.h>


/** Lookup virtual module by name
 */
static fr_rb_tree_t *module_rlm_virtual_name_tree;

typedef struct {
	fr_rb_node_t			name_node;	//!< Entry in the name tree.
	char const			*name;		//!< module name
	CONF_SECTION			*cs;		//!< CONF_SECTION where it is defined
	bool				all_same;
} module_rlm_virtual_t;

/** Compare virtual modules by name
 */
static int8_t module_rlm_virtual_name_cmp(void const *one, void const *two)
{
	module_rlm_virtual_t const *a = one;
	module_rlm_virtual_t const *b = two;
	int ret;

	ret = strcmp(a->name, b->name);
	return CMP(ret, 0);
}

/** Global module list for all backend modules
 *
 */
static module_list_t *rlm_modules_static;

/** Runtime instantiated list
 *
 */
static module_list_t *rlm_modules_dynamic;

/** Print information on all loaded modules
 *
 */
void module_rlm_list_debug(void)
{
	module_list_debug(rlm_modules_static);
}

/** Initialise a module specific exfile handle
 *
 * @see exfile_init
 *
 * @param[in] ctx		to bind the lifetime of the exfile handle to.
 * @param[in] module		section.
 * @param[in] max_entries	Max file descriptors to cache, and manage locks for.
 * @param[in] max_idle		Maximum time a file descriptor can be idle before it's closed.
 * @param[in] locking		Whether	or not to lock the files.
 * @param[in] triggers		Should triggers be enabled.
 * @param[in] trigger_prefix	if NULL will be set automatically from the module CONF_SECTION.
 * @param[in] trigger_args	to make available in any triggers executed by the connection pool.
 * @return
 *	- New connection pool.
 *	- NULL on error.
 */
exfile_t *module_rlm_exfile_init(TALLOC_CTX *ctx,
				 CONF_SECTION *module,
				 uint32_t max_entries,
				 fr_time_delta_t max_idle,
				 bool locking,
				 bool triggers,
				 char const *trigger_prefix,
				 fr_pair_list_t *trigger_args)
{
	char		trigger_prefix_buff[128];
	bool		prefix_set = trigger_prefix ? true : false;
	exfile_t	*handle;

	if (!trigger_prefix) {
		snprintf(trigger_prefix_buff, sizeof(trigger_prefix_buff), "modules.%s.file", cf_section_name1(module));
		trigger_prefix = trigger_prefix_buff;
	}

	handle = exfile_init(ctx, max_entries, max_idle, locking);
	if (!handle) return NULL;

	if (triggers) exfile_enable_triggers(handle, prefix_set ? module : cf_section_find(module, "file", NULL),
					     trigger_prefix, trigger_args);

	return handle;
}

/** Resolve polymorphic item's from a module's #CONF_SECTION to a subsection in another module
 *
 * This allows certain module sections to reference module sections in other instances
 * of the same module and share #CONF_DATA associated with them.
 *
 * @verbatim
   example {
   	data {
   		...
   	}
   }

   example inst {
   	data = example
   }
 * @endverbatim
 *
 * @param[out] out where to write the pointer to a module's config section.  May be NULL on success,
 *	indicating the config item was not found within the module #CONF_SECTION
 *	or the chain of module references was followed and the module at the end of the chain
 *	did not a subsection.
 * @param[in] module #CONF_SECTION.
 * @param[in] name of the polymorphic sub-section.
 * @return
 *	- 0 on success with referenced section.
 *	- 1 on success with local section.
 *	- -1 on failure.
 */
int module_rlm_sibling_section_find(CONF_SECTION **out, CONF_SECTION *module, char const *name)
{
	CONF_PAIR		*cp;
	CONF_SECTION		*cs;
	CONF_DATA const		*cd;


	module_instance_t	*mi;
	char const		*inst_name;

#define FIND_SIBLING_CF_KEY "find_sibling"

	*out = NULL;

	/*
	 *	Is a real section (not referencing sibling module).
	 */
	cs = cf_section_find(module, name, NULL);
	if (cs) {
		*out = cs;

		return 0;
	}

	/*
	 *	Item omitted completely from module config.
	 */
	cp = cf_pair_find(module, name);
	if (!cp) return 0;

	if (cf_data_find(module, CONF_SECTION, FIND_SIBLING_CF_KEY)) {
		cf_log_err(cp, "Module reference loop found");

		return -1;
	}
	cd = cf_data_add(module, module, FIND_SIBLING_CF_KEY, false);

	/*
	 *	Item found, resolve it to a module instance.
	 *	This triggers module loading, so we don't have
	 *	instantiation order issues.
	 */
	inst_name = cf_pair_value(cp);
	mi = module_instance_by_name(rlm_modules_static, NULL, inst_name);
	if (!mi) {
		cf_log_err(cp, "Unknown module instance \"%s\"", inst_name);

		return -1;
	}

	if (mi->state != MODULE_INSTANCE_INSTANTIATED) {
		CONF_SECTION *parent = module;

		/*
		 *	Find the root of the config...
		 */
		do {
			CONF_SECTION *tmp;

			tmp = cf_item_to_section(cf_parent(parent));
			if (!tmp) break;

			parent = tmp;
		} while (true);

		if (unlikely(module_instantiate(module_instance_by_name(rlm_modules_static, NULL, inst_name)) < 0)) return -1;
	}

	/*
	 *	Remove the config data we added for loop
	 *	detection.
	 */
	cf_data_remove_by_data(module, cd);

	/*
	 *	Check the module instances are of the same type.
	 */
	if (strcmp(cf_section_name1(mi->conf), cf_section_name1(module)) != 0) {
		cf_log_err(cp, "Referenced module is a rlm_%s instance, must be a rlm_%s instance",
			      cf_section_name1(mi->conf), cf_section_name1(module));

		return -1;
	}

	*out = cf_section_find(mi->conf, name, NULL);

	return 1;
}

xlat_t *module_rlm_xlat_register(TALLOC_CTX *ctx, module_inst_ctx_t const *mctx,
				 char const *name, xlat_func_t func, fr_type_t return_type)
{
	module_instance_t	*mi = mctx->mi;
	module_rlm_instance_t	*mri = talloc_get_type_abort(mi->uctx, module_rlm_instance_t);
	module_rlm_xlat_t	*mrx;
	xlat_t			*x;
	char 			inst_name[256];

	fr_assert_msg(name != mctx->mi->name, "`name` must not be the same as the module "
		      "instance name.  Pass a NULL `name` arg if this is required");

	if (!name) {
		name = mctx->mi->name;
	} else {
		if ((size_t)snprintf(inst_name, sizeof(inst_name), "%s.%s", mctx->mi->name, name) >= sizeof(inst_name)) {
			ERROR("%s: Instance name too long", __FUNCTION__);
			return NULL;
		}
		name = inst_name;
	}

	x = xlat_func_register(ctx, name, func, return_type);
	if (unlikely(x == NULL)) return NULL;

	xlat_mctx_set(x, mctx);

	MEM(mrx = talloc(mi, module_rlm_xlat_t));
	mrx->xlat = x;
	mrx->mi = mi;

	fr_dlist_insert_tail(&mri->xlats, mrx);

	return x;
}

/** Initialise a module specific connection pool
 *
 * @see fr_pool_init
 *
 * @param[in] module		section.
 * @param[in] opaque		data pointer to pass to callbacks.
 * @param[in] c			Callback to create new connections.
 * @param[in] a			Callback to check the status of connections.
 * @param[in] log_prefix	override, if NULL will be set automatically from the module CONF_SECTION.
 * @param[in] trigger_prefix	if NULL will be set automatically from the module CONF_SECTION.
 * @param[in] trigger_args	to make available in any triggers executed by the connection pool.
 * @return
 *	- New connection pool.
 *	- NULL on error.
 */
fr_pool_t *module_rlm_connection_pool_init(CONF_SECTION *module,
					   void *opaque,
					   fr_pool_connection_create_t c,
					   fr_pool_connection_alive_t a,
					   char const *log_prefix,
					   char const *trigger_prefix,
					   fr_pair_list_t *trigger_args)
{
	CONF_SECTION *cs, *mycs;
	char log_prefix_buff[128];
	char trigger_prefix_buff[128];

	fr_pool_t *pool;
	char const *cs_name1, *cs_name2;

	int ret;

#define parent_name(_x) cf_section_name(cf_item_to_section(cf_parent(_x)))

	cs_name1 = cf_section_name1(module);
	cs_name2 = cf_section_name2(module);
	if (!cs_name2) cs_name2 = cs_name1;

	if (!trigger_prefix) {
		snprintf(trigger_prefix_buff, sizeof(trigger_prefix_buff), "modules.%s.pool", cs_name1);
		trigger_prefix = trigger_prefix_buff;
	}

	if (!log_prefix) {
		snprintf(log_prefix_buff, sizeof(log_prefix_buff), "rlm_%s (%s)", cs_name1, cs_name2);
		log_prefix = log_prefix_buff;
	}

	/*
	 *	Get sibling's pool config section
	 */
	ret = module_rlm_sibling_section_find(&cs, module, "pool");
	switch (ret) {
	case -1:
		return NULL;

	case 1:
		DEBUG4("%s: Using pool section from \"%s\"", log_prefix, parent_name(cs));
		break;

	case 0:
		DEBUG4("%s: Using local pool section", log_prefix);
		break;
	}

	/*
	 *	Get our pool config section
	 */
	mycs = cf_section_find(module, "pool", NULL);
	if (!mycs) {
		DEBUG4("%s: Adding pool section to config item \"%s\" to store pool references", log_prefix,
		       cf_section_name(module));

		mycs = cf_section_alloc(module, module, "pool", NULL);
	}

	/*
	 *	Sibling didn't have a pool config section
	 *	Use our own local pool.
	 */
	if (!cs) {
		DEBUG4("%s: \"%s.pool\" section not found, using \"%s.pool\"", log_prefix,
		       parent_name(cs), parent_name(mycs));
		cs = mycs;
	}

	/*
	 *	If fr_pool_init has already been called
	 *	for this config section, reuse the previous instance.
	 *
	 *	This allows modules to pass in the config sections
	 *	they would like to use the connection pool from.
	 */
	pool = cf_data_value(cf_data_find(cs, fr_pool_t, NULL));
	if (!pool) {
		DEBUG4("%s: No pool reference found for config item \"%s.pool\"", log_prefix, parent_name(cs));
		pool = fr_pool_init(cs, cs, opaque, c, a, log_prefix);
		if (!pool) return NULL;

		fr_pool_enable_triggers(pool, trigger_prefix, trigger_args);

		if (fr_pool_start(pool) < 0) {
			ERROR("%s: Starting initial connections failed", log_prefix);
			return NULL;
		}

		DEBUG4("%s: Adding pool reference %p to config item \"%s.pool\"", log_prefix, pool, parent_name(cs));
		cf_data_add(cs, pool, NULL, false);
		return pool;
	}
	fr_pool_ref(pool);

	DEBUG4("%s: Found pool reference %p in config item \"%s.pool\"", log_prefix, pool, parent_name(cs));

	/*
	 *	We're reusing pool data add it to our local config
	 *	section. This allows other modules to transitively
	 *	reuse a pool through this module.
	 */
	if (mycs != cs) {
		DEBUG4("%s: Copying pool reference %p from config item \"%s.pool\" to config item \"%s.pool\"",
		       log_prefix, pool, parent_name(cs), parent_name(mycs));
		cf_data_add(mycs, pool, NULL, false);
	}

	return pool;
}

/** Set the next section type if it's not already set
 *
 * @param[in] request		The current request.
 * @param[in] type_da		to use.  Usually attr_auth_type.
 * @param[in] enumv		Enumeration value of the specified type_da.
 */
bool module_rlm_section_type_set(request_t *request, fr_dict_attr_t const *type_da, fr_dict_enum_value_t const *enumv)
{
	fr_pair_t *vp;

	switch (pair_update_control(&vp, type_da)) {
	case 0:
		if (unlikely(fr_value_box_copy(vp, &vp->data, enumv->value) < 0)) {
			fr_strerror_printf("Failed to set control.%pP to %s", vp, enumv->name);
			return false;
		}
		vp->data.enumv = vp->da;	/* So we get the correct string alias */
		RDEBUG2("Setting control.%pP", vp);
		return true;

	case 1:
		RDEBUG2("control.%s already set.  Not setting to %s", vp->da->name, enumv->name);
		return false;

	default:
		return false;
	}
}

/** Iterate over an array of named module methods, looking for matches
 *
 * @param[in] mmg		A structure containing a terminated array of
 *				module method bindings. pre-sorted using #section_name_cmp
 *				with name2 sublists populated.
 * @param[in] section		name1 of the method being called can be one of the following:
 *				- An itenfier.
 *				- CF_IDENT_ANY if the method is a wildcard.
 *				name2 of the method being called can be one of the following:
 *				- An itenfier.
 *				- NULL to match section names with only a name1.
 *				- CF_IDENT_ANY if the method is a wildcard.
 * @return
 *	- The module_method_name_t on success.
 *	- NULL on not found.
 */
static CC_HINT(nonnull)
module_method_binding_t const *module_binding_find(module_method_group_t const *mmg, section_name_t const *section)
{
	module_method_group_t const *mmg_p = mmg;
	module_method_binding_t const *p;

	while (mmg_p) {
		/*
		 *	This could potentially be improved by using a binary search
		 *	but given the small number of items, reduced branches and
		 *	sequential access just scanning the list, it's probably not
		 *	worth it.
		 */
		for (p = mmg_p->bindings; p->section; p++) {
			switch (section_name_match(p->section, section)) {
			case 1:		/* match */
				return p;

			case -1:	/* name1 didn't match, skip to the end of the sub-list */
				p = fr_dlist_tail(&p->same_name1);
				break;

			case 0:		/* name1 did match - see if we can find a matching name2 */
			{
				fr_dlist_head_t const *same_name1 = &p->same_name1;

				while ((p = fr_dlist_next(same_name1, p))) {
					if (section_name2_match(p->section, section)) return p;
				}
				p = fr_dlist_tail(same_name1);
			}
				break;
			}
#ifdef __clang_analyzer__
			/* Will never be NULL, worse case, p doesn't change*/
			if (!p) break;
#endif
		}

		/*
		 *	Failed to match, search the next deepest group in the chain.
		 */
		mmg_p = mmg_p->next;
	}

	return NULL;
}

/** Dump the available bindings for the module into the strerror stack
 *
 * @note Methods from _all_ linked module method groups will be pushed onto the error stack.
 *
 * @param[in] mmg	module method group to evaluate.
 */
static void module_rlm_methods_to_strerror(module_method_group_t const *mmg)
{
	module_method_group_t const	*mmg_p = mmg;
	module_method_binding_t const	*mmb_p;
	bool				first = true;

	while (mmg_p) {
		mmb_p = mmg_p->bindings;

		if (!mmb_p || !mmb_p[0].section) goto next;

		if (first) {
			fr_strerror_const_push("Available methods are:");
			first = false;
		}

		for (; mmb_p->section; mmb_p++) {
			char const *name1 = section_name_str(mmb_p->section->name1);
			char const *name2 = section_name_str(mmb_p->section->name2);

			fr_strerror_printf_push("  %s%s%s",
						name1, name2 ? "." : "", name2 ? name2 : "");
		}
	next:
		mmg_p = mmg_p->next;
	}

	if (first) {
		fr_strerror_const_push("No methods available");
	}
}

/** Find an existing module instance and verify it implements the specified method
 *
 * Extracts the method from the module name where the format is @verbatim <module>[.<method1>[.<method2>]] @endverbatim
 * and ensures the module implements the specified method.
 *
 * @param[in] ctx		to allocate the dynamic module key tmpl from.
 * @param[out] mmc_out		the result from resolving the module method,
 *				plus the key tmpl for dynamic modules.
 *				This is not allocated from the ctx to save the runtime
 *				dereference.
 * @param[in] vs		Virtual server to search for alternative module names in.
 * @param[in] section		Section name containing the module call.
 * @param[in] name 		The module method call i.e. module[<key>][.<method>]
 * @param[in] t_rules		for resolving the dynamic module key.
 * @return
 *	- The module instance on success.
 *	- NULL on not found
 *
 *  If the module exists but the method doesn't exist, then `method` is set to NULL.
 */
fr_slen_t module_rlm_by_name_and_method(TALLOC_CTX *ctx, module_method_call_t *mmc_out,
				        virtual_server_t const *vs, section_name_t const *section, fr_sbuff_t *name,
					tmpl_rules_t const *t_rules)
{
	fr_sbuff_term_t const		*dyn_tt = &FR_SBUFF_TERMS(
						L(""),
						L("\t"),
						L("\n"),
						L(" "),
						L("[")
					);

	fr_sbuff_term_t const		*elem_tt = &FR_SBUFF_TERMS(
						L(""),
						L("\t"),
						L("\n"),
						L(" "),
						L(".")
					);

	fr_sbuff_t			*elem1;
	module_method_call_t		*mmc;
	module_method_call_t		mmc_tmp;
	module_method_binding_t const	*mmb;

	fr_sbuff_marker_t		meth_start;
	bool				softfail;

	fr_slen_t			slen;
	fr_sbuff_t 			our_name = FR_SBUFF(name);

	mmc = mmc_out ? mmc_out : &mmc_tmp;
	if (mmc_out) *mmc_out = (module_method_call_t) {};

	softfail = fr_sbuff_next_if_char(&our_name, '-');

	/*
	 *	Advance until the start of the dynamic selector
	 *	(if it exists).
	 */
	if (fr_sbuff_adv_until(&our_name, SIZE_MAX, dyn_tt, '\0') == 0) {
		fr_strerror_printf("Invalid module method name");
		return fr_sbuff_error(&our_name);
	}

	FR_SBUFF_TALLOC_THREAD_LOCAL(&elem1, MODULE_INSTANCE_LEN_MAX, (MODULE_INSTANCE_LEN_MAX + 1) * 10);

	/*
	 *	If the method string contains a '['
	 *
	 *	Search for a dynamic module method, e.g. `elem1[<key>]`.
	 */
	if (fr_sbuff_is_char(&our_name, '[')) {
		fr_sbuff_marker_t end, s_end;
		fr_sbuff_marker(&end, &our_name);

		slen = tmpl_afrom_substr(ctx, &mmc->key, &our_name, T_BARE_WORD, NULL, t_rules);
		if (slen < 0) {
			fr_strerror_const_push("Invalid dynamic module selector expression");
			talloc_free(mmc);
			return slen;
		}

		if (!fr_sbuff_is_char(&our_name, ']')) {
			fr_strerror_const_push("Missing terminating ']' for dynamic module selector");
		error:
			talloc_free(mmc);
			return fr_sbuff_error(&our_name);
		}
		fr_sbuff_marker(&s_end, &our_name);

		fr_sbuff_set_to_start(&our_name);
		slen = fr_sbuff_out_bstrncpy(elem1, &our_name, fr_sbuff_ahead(&end));
		if (slen < 0) {
			fr_strerror_const("Module method string too long");
			goto error;
		}
		mmc->mi = module_instance_by_name(rlm_modules_dynamic, NULL, elem1->start);
		if (!mmc->mi) {
			fr_strerror_printf("No such dynamic module '%s'", elem1->start);
			goto error;
		}
		mmc->rlm = module_rlm_from_module(mmc->mi->exported);

		fr_sbuff_set(&our_name, &s_end);
		fr_sbuff_advance(&our_name, 1);	/* Skip the ']' */
	/*
	 *	With elem1.elem2.elem3
	 *
	 *	Search for a static module matching one of the following:
	 *
	 *	- elem1.elem2.elem3
	 *	- elem1.elem2
	 *	- elem1
	 */
	} else {
		char *p;

		fr_sbuff_set_to_start(&our_name);

		slen = fr_sbuff_out_bstrncpy_until(elem1, &our_name, SIZE_MAX, dyn_tt, NULL);
		if (slen == 0) {
			fr_strerror_const("Invalid module name");
			goto error;
		}
		if (slen < 0) {
			fr_strerror_const("Module method string too long");
			goto error;
		}

		/*
		 *	Now we have a mutable buffer, we can start chopping
		 *	it up to find the module.
		 */
		for (;;) {
			mmc->mi = (module_instance_t *)module_rlm_static_by_name(NULL, elem1->start);
			if (mmc->mi) {
				mmc->rlm = module_rlm_from_module(mmc->mi->exported);
				break;	/* Done */
			}

			p = strrchr(elem1->start, '.');
			if (!p) break;	/* No more '.' */
			*p = '\0';	/* Chop off the last '.' */
		}

		if (!mmc->mi) {
			if (softfail) return fr_sbuff_set(name, &our_name);

			fr_strerror_printf("No such module '%pV'", fr_box_strvalue_len(our_name.start, slen));
			return -1;
		}

		fr_sbuff_set_to_start(&our_name);
		fr_sbuff_advance(&our_name, strlen(elem1->start));	/* Advance past the module name */
		if (fr_sbuff_is_char(&our_name, '.')) {
			fr_sbuff_advance(&our_name, 1);			/* Static module method, search directly */
		} else {
			fr_sbuff_marker(&meth_start, &our_name);	/* for the errors... */
			goto by_section;				/* Get the method dynamically from the section*/
		}
	}

	/*
	 *	For both cases, the buffer should be pointing
	 *	at the start of the method string.
	 */
	fr_sbuff_marker(&meth_start, &our_name);

	/*
	 *	If a module method was provided, search for it in the named
	 *	methods provided by the module.
	 *
	 *	The method name should be either:
	 *
	 *	- name1
	 *	- name1.name2
	 */
	{
		section_name_t	method;
		fr_sbuff_t	*elem2;

		fr_sbuff_set_to_start(elem1);	/* May have used this already for module lookups */

		slen = fr_sbuff_out_bstrncpy_until(elem1, &our_name, SIZE_MAX, elem_tt, NULL);
		if (slen < 0) {
			fr_strerror_const("Module method string too long");
			return fr_sbuff_error(&our_name);
		}
		if (slen == 0) goto by_section;	/* This works for both dynamic and static modules */

		FR_SBUFF_TALLOC_THREAD_LOCAL(&elem2, MODULE_INSTANCE_LEN_MAX, MODULE_INSTANCE_LEN_MAX);

		if (fr_sbuff_is_char(&our_name, '.')) {
			fr_sbuff_advance(&our_name, 1);
			if (fr_sbuff_out_bstrncpy_until(elem2, &our_name, SIZE_MAX,
							elem_tt, NULL) == MODULE_INSTANCE_LEN_MAX) {
				fr_strerror_const("Module method string too long");
				goto error;
			}
		}

		method = (section_name_t) {
			.name1 = elem1->start,
			.name2 = fr_sbuff_used(elem2) ? elem2->start : NULL
		};

		mmb = module_binding_find(&mmc->rlm->method_group, &method);
		if (!mmb) {
			fr_strerror_printf("Module \"%s\" does not have method %s%s%s",
					   mmc->mi->name,
					   method.name1,
					   method.name2 ? "." : "",
					   method.name2 ? method.name2 : ""
					   );

			module_rlm_methods_to_strerror(&mmc->rlm->method_group);
			return fr_sbuff_error(&meth_start);
		}
		mmc->mmb = *mmb;	/* For locality of reference and fewer derefs */
		if (mmc_out) section_name_dup(ctx, &mmc->asked, &method);

		return fr_sbuff_set(name, &our_name);
	}

by_section:
	/*
	 *	First look for the section name in the module's
	 *	bindings.  If that fails, look for the alt
	 *	section names from the virtual server section.
	 *
	 *	If that fails, we're done.
	 */
	mmb = module_binding_find(&mmc->rlm->method_group, section);
	if (!mmb) {
		section_name_t const **alt_p = virtual_server_section_methods(vs, section);
		if (alt_p) {
			for (; *alt_p; alt_p++) {
				mmb = module_binding_find(&mmc->rlm->method_group, *alt_p);
				if (mmb) {
					if (mmc_out) section_name_dup(ctx, &mmc->asked, *alt_p);
					break;
				}
			}
		}
	} else {
		if (mmc_out) section_name_dup(ctx, &mmc->asked, section);
	}
	if (!mmb) {
		fr_strerror_printf("Module \"%s\" has no method for section %s %s { ... }, i.e. %s%s%s",
				   mmc->mi->name,
				   section->name1,
				   section->name2 ? section->name2 : "",
				   section->name1,
				   section->name2 ? "." : "",
				   section->name2 ? section->name2 : ""
				   );
		module_rlm_methods_to_strerror(&mmc->rlm->method_group);

		return fr_sbuff_error(&meth_start);
	}
	mmc->mmb = *mmb;	/* For locality of reference and fewer derefs */

	return fr_sbuff_set(name, &our_name);
}

CONF_SECTION *module_rlm_virtual_by_name(char const *asked_name)
{
	module_rlm_virtual_t *inst;

	inst = fr_rb_find(module_rlm_virtual_name_tree,
			  &(module_rlm_virtual_t){
				.name = asked_name,
			  });
	if (!inst) return NULL;

	return inst->cs;
}

module_instance_t *module_rlm_dynamic_by_name(module_instance_t const *parent, char const *asked_name)
{
	return module_instance_by_name(rlm_modules_dynamic, parent, asked_name);
}

module_instance_t *module_rlm_static_by_name(module_instance_t const *parent, char const *asked_name)
{
	return module_instance_by_name(rlm_modules_static, parent, asked_name);
}

/** Create a virtual module.
 *
 * @param[in] cs	that defines the virtual module.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int module_rlm_bootstrap_virtual(CONF_SECTION *cs)
{
	char const		*name;
	bool			all_same;
	CONF_ITEM 		*sub_ci = NULL;
	CONF_PAIR		*cp;
	module_instance_t	*mi;
	module_rlm_virtual_t	*inst;

	name = cf_section_name1(cs);

	/*
	 *	Groups, etc. must have a name.
	 */
	if ((strcmp(name, "group") == 0) ||
	    (strcmp(name, "redundant") == 0) ||
	    (strcmp(name, "redundant-load-balance") == 0) ||
	    (strcmp(name, "load-balance") == 0)) {
		name = cf_section_name2(cs);
		if (!name) {
			cf_log_err(cs, "Keyword module must have a second name");
			return -1;
		}

		/*
		 *	name2 was already checked in modules_rlm_bootstrap()
		 */
		fr_assert(!unlang_compile_is_keyword(name));
	} else {
		cf_log_err(cs, "Module names cannot be unlang keywords '%s'", name);
		return -1;
	}

	/*
	 *	Ensure that the module doesn't exist.
	 */
	mi = module_instance_by_name(rlm_modules_static, NULL, name);
	if (mi) {
		ERROR("Duplicate module \"%s\" in file %s[%d] and file %s[%d]",
		      name,
		      cf_filename(cs),
		      cf_lineno(cs),
		      cf_filename(mi->conf),
		      cf_lineno(mi->conf));
		return -1;
	}

	/*
	 *	Don't bother registering redundant xlats for a simple "group".
	 */
	all_same = (strcmp(cf_section_name1(cs), "group") != 0);

	{
		module_t const 		*last = NULL;

		/*
		*	Ensure that the modules we reference here exist.
		*/
		while ((sub_ci = cf_item_next(cs, sub_ci))) {
			if (cf_item_is_pair(sub_ci)) {
				cp = cf_item_to_pair(sub_ci);
				if (cf_pair_value(cp)) {
					cf_log_err(sub_ci, "Cannot set return codes in a %s block", cf_section_name1(cs));
					return -1;
				}

				mi = module_rlm_static_by_name(NULL, cf_pair_attr(cp));
				if (!mi) {
					cf_log_perr(sub_ci, "Failed resolving module reference '%s' in %s block",
						    cf_pair_attr(cp), cf_section_name1(cs));
					return -1;
				}

				if (all_same) {
					if (!last) {
						last = mi->exported;
					} else if (last != mi->exported) {
						last = NULL;
						all_same = false;
					}
				}
			} else {
				all_same = false;
			}

			/*
			*	Don't check subsections for now.  That check
			*	happens later in the unlang compiler.
			*/
		} /* loop over things in a virtual module section */
	}

	inst = talloc_zero(cs, module_rlm_virtual_t);
	if (!inst) return -1;

	inst->cs = cs;
	MEM(inst->name = talloc_strdup(inst, name));
	inst->all_same = all_same;

	if (!fr_cond_assert(fr_rb_insert(module_rlm_virtual_name_tree, inst))) {
		talloc_free(inst);
		return -1;
	}

	return 0;
}

/** Generic conf_parser_t func for loading drivers
 *
 */
int module_rlm_submodule_parse(TALLOC_CTX *ctx, void *out, void *parent,
			       CONF_ITEM *ci, conf_parser_t const *rule)
{
	conf_parser_t our_rule = *rule;

	our_rule.uctx = &rlm_modules_static;

	return module_submodule_parse(ctx, out, parent, ci, &our_rule);
}

/** Frees thread-specific data for all registered backend modules
 *
 */
void modules_rlm_thread_detach(void)
{
	modules_thread_detach(rlm_modules_static);
}

/** Allocates thread-specific data for all registered backend modules
 *
 * @param[in] ctx	To allocate any thread-specific data in.
 * @param[in] el	to register events.
 * @return
 *	- 0 if all modules were instantiated successfully.
 *	- -1 if a module failed instantiation.
 */
int modules_rlm_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el)
{
	return modules_thread_instantiate(ctx, rlm_modules_static, el);
}

/** Performs the instantiation phase for all backend modules
 *
 * @return
 *	- 0 if all modules were instantiated successfully.
 *	- -1 if a module failed instantiation.
 */
int modules_rlm_instantiate(void)
{
	return modules_instantiate(rlm_modules_static);
}

/** Compare the section names of two module_method_binding_t structures
 */
static int8_t binding_name_cmp(void const *one, void const *two)
{
	module_method_binding_t const *a = one;
	module_method_binding_t const *b = two;

	return section_name_cmp(a->section, b->section);
}

static int module_method_group_validate(module_method_group_t *group)
{
	module_method_binding_t *p, *srt_p;
	fr_dlist_head_t		bindings;
	bool			in_order = true;

	/*
	 *	Not all modules export module method bindings
	 */
	if (!group || !group->bindings || group->validated) return 0;

	fr_dlist_init(&bindings, module_method_binding_t, entry);

	for (p = group->bindings; p->section; p++) {
		if (!fr_cond_assert_msg(p->section->name1,
					"First section identifier can't be NULL")) return -1;
		if (!fr_cond_assert_msg(p->section->name1 || p->section->name2,
					"Section identifiers can't both be null")) return -1;

		/*
		 *	All the bindings go in a list so we can sort them
		 *	and produce the list in the correct order.
		 */
		fr_dlist_insert_tail(&bindings, p);
	}

	fr_dlist_sort(&bindings, binding_name_cmp);

	/*
	 *	Iterate over the sorted list of bindings,
	 *	and the original list, to ensure they're
	 *	in the correct order.
	 */
	for (srt_p = fr_dlist_head(&bindings), p = group->bindings;
	     srt_p;
	     srt_p = fr_dlist_next(&bindings, srt_p), p++) {
		if (p != srt_p) {
			in_order = false;
			break;
		}
	}

	/*
	 *	Rebuild the binding list in the correct order.
	 */
	if (!in_order) {
		module_method_binding_t *ordered;

		MEM(ordered = talloc_array(NULL, module_method_binding_t, fr_dlist_num_elements(&bindings)));
		for (srt_p = fr_dlist_head(&bindings), p = ordered;
		     srt_p;
		     srt_p = fr_dlist_next(&bindings, srt_p), p++) {
			*p = *srt_p;
		}
		memcpy(group->bindings, ordered, fr_dlist_num_elements(&bindings) * sizeof(*ordered));
		talloc_free(ordered);
	}

	/*
	 *	Build the "skip" list of name1 entries
	 */
	{
		module_method_binding_t *last_binding = NULL;

		for (p = group->bindings; p->section; p++) {
			if (!last_binding ||
				(
					(last_binding->section->name1 != p->section->name1) &&
					(
						(last_binding->section->name1 == CF_IDENT_ANY) ||
						(p->section->name1 == CF_IDENT_ANY) ||
						(strcmp(last_binding->section->name1, p->section->name1) != 0)
					)
				)
			) {
				fr_dlist_init(&p->same_name1, module_method_binding_t, entry);
				last_binding = p;
			}
			fr_dlist_insert_tail(&last_binding->same_name1, p);
		}
	}
	group->validated = true;

	return module_method_group_validate(group->next);
}

static int module_method_validate(module_instance_t *mi)
{
	module_rlm_t *mrlm = module_rlm_from_module(mi->exported);

	return module_method_group_validate(&mrlm->method_group);
}

/** Allocate a rlm module instance
 *
 * These have extra space allocated to hold the dlist of associated xlats.
 *
 * @param[in] ml		Module list to allocate from.
 * @param[in] parent		Parent module instance.
 * @param[in] type		Type of module instance.
 * @param[in] mod_name		Name of the module.
 * @param[in] inst_name		Name of the instance.
 * @param[in] init_state	Initial state of the module instance.
 * @return
 *	- The allocated module instance on success.
 *	- NULL on failure.
 */
static inline CC_HINT(always_inline)
module_instance_t *module_rlm_instance_alloc(module_list_t *ml,
					     module_instance_t const *parent,
					     dl_module_type_t type, char const *mod_name, char const *inst_name,
					     module_instance_state_t init_state)
{
	module_instance_t *mi;
	module_rlm_instance_t *mri;

	mi = module_instance_alloc(ml, parent, type, mod_name, inst_name, init_state);
	if (unlikely(mi == NULL)) return NULL;

	MEM(mri = talloc(mi, module_rlm_instance_t));
	module_instance_uctx_set(mi, mri);

	fr_dlist_talloc_init(&mri->xlats, module_rlm_xlat_t, entry);

	return mi;
}

static int module_conf_parse(module_list_t *ml, CONF_SECTION *mod_conf)
{
	char const		*name;
	char const		*inst_name;
	module_instance_t	*mi = NULL;
	CONF_SECTION		*actions;

	/*
	 *	name2 can't be a keyword
	 */
	name = cf_section_name2(mod_conf);
	if (name && unlang_compile_is_keyword(name)) {
	invalid_name:
		cf_log_err(mod_conf, "Module names cannot be unlang keywords '%s'", name);
		return -1;
	}

	name = cf_section_name1(mod_conf);

	/*
	 *	For now, ignore name1 which is a keyword.
	 */
	if (unlang_compile_is_keyword(name)) {
		if (!cf_section_name2(mod_conf)) {
			cf_log_err(mod_conf, "Missing second name at '%s'", name);
			return -1;
		}
		if (module_rlm_bootstrap_virtual(mod_conf) < 0) return -1;
		return 0;
	}

	/*
	 *	Skip inline templates, and disallow "template { ... }"
	 */
	if (strcmp(name, "template") == 0) {
		if (!cf_section_name2(mod_conf)) goto invalid_name;
		return 0;
	}

	if (module_instance_name_from_conf(&inst_name, mod_conf) < 0) goto invalid_name;

	mi = module_rlm_instance_alloc(ml, NULL, DL_MODULE_TYPE_MODULE, name, inst_name, 0);
	if (unlikely(mi == NULL)) {
		cf_log_perr(mod_conf, "Failed loading module");
		return -1;
	}

	/*
	 *	First time we've loaded the dl module, so we need to
	 *	check the module methods to make sure they're ordered
	 *	correctly, and to add the "skip list" style name2
	 *	entries.
	 */
	if ((mi->module->refs == 1) && (module_method_validate(mi) < 0)) {
		talloc_free(mi);
		return -1;
	}

	if (module_instance_conf_parse(mi, mod_conf) < 0) {
		cf_log_perr(mod_conf, "Failed parsing module config");
		talloc_free(mi);
		return -1;
	}

	/*
	 *	Compile the default "actions" subsection, which includes retries.
	 */
	actions = cf_section_find(mod_conf, "actions", NULL);
	if (actions && unlang_compile_actions(&mi->actions, actions, (mi->exported->flags & MODULE_TYPE_RETRY) != 0)) {
		talloc_free(mi);
		return -1;
	}

	return 0;
}

/** Bootstrap modules and virtual modules
 *
 * Parse the module config sections, and load and call each module's init() function.
 *
 * @param[in] root of the server configuration.
 * @return
 *	- 0 if all modules were bootstrapped successfully.
 *	- -1 if a module/virtual module failed to bootstrap.
 */
int modules_rlm_bootstrap(CONF_SECTION *root)
{
	CONF_SECTION		*cs, *modules, *static_cs, *dynamic_cs;
	module_rlm_virtual_t	*vm;
	fr_rb_iter_inorder_t	iter;

	/*
	 *	Ensure any libraries the modules depend on are instantiated
	 */
	global_lib_instantiate();

	/*
	 *	Remember where the modules were stored.
	 */
	modules = cf_section_find(root, "modules", NULL);
	if (!modules) {
		WARN("Cannot find a \"modules\" section in the configuration file!");
		return 0;
	}

	static_cs = cf_section_find(modules, "static", NULL);
	if (!static_cs) {
		static_cs = cf_section_alloc(modules, NULL, "static", NULL);
		cf_section_foreach(modules, mod_cs) {
			CONF_ITEM *prev;
			char const *name1 = cf_section_name1(mod_cs);

			/*
			 *	Skip over the dynamic section
			 */
			if ((strcmp(name1, "dynamic") == 0) && !cf_section_name2(mod_cs)) continue;

			/*
			 *	Ignore this section if it is commented out with a magic name.
			 */
			if (*name1 == '-') continue;

			/*
			 *	Move all modules which are not in
			 *	the dynamic section into the static
			 *	section for backwards compatibility.
			 */
			prev = cf_item_remove(modules, mod_cs);
			cf_item_add(static_cs, mod_cs);

			/*
			 *	Find the previous item that's a section
			 */
			while (prev && !cf_item_is_section(prev)) prev = cf_item_prev(modules, prev);

			/*
			 *	Resume iterating from that item
			 */
			mod_cs = cf_item_to_section(prev);
		}
		cf_item_add(modules, static_cs);
	}
	DEBUG2("#### Bootstrapping static modules ####");
	cf_log_debug(modules, " modules {");
	cf_log_debug(modules, "    static {");
	cf_section_foreach(static_cs, mod_conf) {
		if (module_conf_parse(rlm_modules_static, mod_conf) < 0) return -1;
	}
	cf_log_debug(modules, "    } # static");

	/*
	 *	Now we have a module tree, run bootstrap on all the modules.
	 *	This will bootstrap modules and then submodules.
	 */
	if (unlikely(modules_bootstrap(rlm_modules_static) < 0)) return -1;

	if (fr_command_register_hook(NULL, NULL, static_cs, module_cmd_list_table) < 0) {
		PERROR("Failed registering radmin commands for modules");
		return -1;
	}

	/*
	 *	Build the configuration and parse dynamic modules
	 */
	dynamic_cs = cf_section_find(modules, "dynamic", NULL);
	if (dynamic_cs) {
		DEBUG2("#### Bootstrapping dynamic modules ####");
		/*
		*	Parse and then instantiate any dynamic modules configure
		*/
		cf_log_debug(modules, "    dynamic {");
		cf_section_foreach(dynamic_cs, mod_conf) {
			if (unlikely(module_conf_parse(rlm_modules_dynamic, mod_conf) < 0)) return -1;
		}
		cf_log_debug(modules, "    } # dynamic");
		if (unlikely(modules_bootstrap(rlm_modules_dynamic) < 0)) return -1;
		cf_log_debug(modules, " } # modules");
	}

	/*
	 *	Check for duplicate policies.  They're treated as
	 *	modules, so we might as well check them here.
	 */
	cs = cf_section_find(root, "policy", NULL);
	if (cs) {
		cf_section_foreach(cs, policy_cs) {
			CONF_SECTION	*problemcs;
			char const	*name1 = cf_section_name1(policy_cs);

			if (unlang_compile_is_keyword(name1)) {
				cf_log_err(policy_cs, "Policy name '%s' cannot be an unlang keyword", name1);
				return -1;
			}

			if (cf_section_name2(policy_cs)) {
				cf_log_err(policy_cs, "Policies cannot have two names");
				return -1;
			}

			problemcs = cf_section_find_next(cs, policy_cs, name1, CF_IDENT_ANY);
			if (!problemcs) continue;

			cf_log_err(problemcs, "Duplicate policy '%s' is forbidden.",
				   cf_section_name1(policy_cs));
			return -1;
		}
	}

	/*
	 *	Now that all of the xlat things have been registered,
	 *	register our redundant xlats.  But only when all of
	 *	the items in such a section are the same.
	 */
	for (vm = fr_rb_iter_init_inorder(module_rlm_virtual_name_tree, &iter);
	     vm;
	     vm = fr_rb_iter_next_inorder(module_rlm_virtual_name_tree, &iter)) {
		if (!vm->all_same) continue;

		if (xlat_register_redundant(vm->cs) < 0) return -1;
	}

	return 0;
}

/** Cleanup all global structures
 *
 * Automatically called on exit.
 */
int modules_rlm_free(void)
{
	if (talloc_free(rlm_modules_static) < 0) return -1;
	rlm_modules_static = NULL;
	if (talloc_free(module_rlm_virtual_name_tree) < 0) return -1;
	module_rlm_virtual_name_tree = NULL;

	return 0;
}

static int _modules_rlm_free_atexit(UNUSED void *uctx)
{
	return modules_rlm_free();
}

/** Initialise the module list structure
 *
 */
int modules_rlm_init(void)
{
	MEM(rlm_modules_static = module_list_alloc(NULL, &module_list_type_global, "rlm", true));
	MEM(rlm_modules_dynamic = module_list_alloc(NULL, &module_list_type_thread_local, "rlm", true));
	module_list_mask_set(rlm_modules_dynamic, MODULE_INSTANCE_INSTANTIATED);	/* Ensure we never instantiate dynamic modules */

	MEM(module_rlm_virtual_name_tree = fr_rb_inline_alloc(NULL, module_rlm_virtual_t, name_node,
							      module_rlm_virtual_name_cmp, NULL));
	fr_atexit_global(_modules_rlm_free_atexit, NULL);

	return 0;
}
