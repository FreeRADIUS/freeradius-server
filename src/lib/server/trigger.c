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

/*
 * $Id$
 *
 * @file trigger.c
 * @brief Execute scripts when a server event occurs.
 *
 * @copyright 2015 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/debug.h>
#include <sys/wait.h>

/** Whether triggers are enabled globally
 *
 */
static bool			triggers_init;
static CONF_SECTION const	*trigger_exec_main, *trigger_exec_subcs;
static fr_rb_tree_t			*trigger_last_fired_tree;
static pthread_mutex_t		*trigger_mutex;

#define REQUEST_INDEX_TRIGGER_NAME	1
#define REQUEST_INDEX_TRIGGER_ARGS	2

/** Describes a rate limiting entry for a trigger
 *
 */
typedef struct {
	fr_rb_node_t	node;		//!< Entry in the trigger last fired tree.
	CONF_ITEM	*ci;		//!< Config item this rate limit counter is associated with.
	time_t		last_fired;	//!< When this trigger last fired.
} trigger_last_fired_t;

/** Retrieve attributes from a special trigger list
 *
 */
xlat_action_t trigger_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, request_t *request,
			   UNUSED void const *xlat_inst, UNUSED void *xlat_thread_inst,
			   fr_value_box_list_t *in)
{
	fr_pair_list_t		*head = NULL;
	fr_dict_attr_t const	*da;
	fr_pair_t		*vp;
	fr_value_box_t		*in_head = fr_dlist_head(in);
	fr_value_box_t		*vb;

	if (!triggers_init) {
		ERROR("Triggers are not enabled");
		return XLAT_ACTION_FAIL;
	}

	if (!request_data_reference(request, &trigger_exec_main, REQUEST_INDEX_TRIGGER_NAME)) {
		ERROR("trigger xlat may only be used in a trigger command");
		return XLAT_ACTION_FAIL;
	}

	head = request_data_reference(request, &trigger_exec_main, REQUEST_INDEX_TRIGGER_ARGS);

	da = fr_dict_attr_by_name(NULL, fr_dict_root(request->dict), in_head->vb_strvalue);
	if (!da) {
		ERROR("Unknown attribute \"%pV\"", in_head);
		return XLAT_ACTION_FAIL;
	}

	vp = fr_pair_find_by_da(head, da);
	if (!vp) {
		ERROR("Attribute \"%pV\" is not valid for this trigger", in_head);
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_copy(ctx, vb, &vp->data);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

static int _mutex_free(pthread_mutex_t *mutex)
{
	pthread_mutex_destroy(mutex);
	return 0;
}

static void _trigger_last_fired_free(void *data)
{
	talloc_free(data);
}

/** Compares two last fired structures
 *
 * @param one first pointer to compare.
 * @param two second pointer to compare.
 * @return CMP(one, two)
 */
static int8_t _trigger_last_fired_cmp(void const *one, void const *two)
{
	trigger_last_fired_t const *a = one, *b = two;

	return CMP(a->ci, b->ci);
}

/** Set the global trigger section trigger_exec will search in, and register xlats
 *
 * This function exists because triggers are used by the connection pool, which
 * is used in the server library which may not have the mainconfig available.
 * Additionally, utilities may want to set their own root config sections.
 *
 * We don't register the trigger xlat here, as we may inadvertently initialise
 * the xlat code, which is annoying when this is called from a utility.
 *
 * @param[in] cs	to use as global trigger section.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int trigger_exec_init(CONF_SECTION const *cs)
{
	if (!cs) {
		ERROR("%s - Pointer to main_config was NULL", __FUNCTION__);
		return -1;
	}

	trigger_exec_main = cs;
	trigger_exec_subcs = cf_section_find(cs, "trigger", NULL);

	if (!trigger_exec_subcs) {
		WARN("trigger { ... } subsection not found, triggers will be disabled");
		return 0;
	}

	MEM(trigger_last_fired_tree = fr_rb_inline_talloc_alloc(talloc_null_ctx(),
								trigger_last_fired_t, node,
								_trigger_last_fired_cmp, _trigger_last_fired_free));

	trigger_mutex = talloc(talloc_null_ctx(), pthread_mutex_t);
	pthread_mutex_init(trigger_mutex, 0);
	talloc_set_destructor(trigger_mutex, _mutex_free);
	triggers_init = true;

	return 0;
}

/** Free trigger resources
 *
 */
void trigger_exec_free(void)
{
	TALLOC_FREE(trigger_last_fired_tree);
	TALLOC_FREE(trigger_mutex);
}

/** Return whether triggers are enabled
 *
 */
bool trigger_enabled(void)
{
	return triggers_init;
}

typedef struct {
	char			*name;
	xlat_exp_t		*xlat;
	fr_value_box_list_t	args;
	bool			synchronous;
	pid_t			pid;	//!< for synchronous execution.
} fr_trigger_t;


static unlang_action_t trigger_resume(rlm_rcode_t *p_result, UNUSED int *priority,
				      request_t *request, void *rctx)
{
	fr_trigger_t	*trigger = talloc_get_type_abort(rctx, fr_trigger_t);

	if (fr_dlist_empty(&trigger->args)) {
		RERROR("Failed trigger %s - did not expand to anything", trigger->name);
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Execute the program and wait for it to finish before
	 *      continuing. This blocks the executing thread.
	 */
	if (trigger->synchronous) {
		if (fr_exec_wait_start(&trigger->pid, NULL, NULL, NULL, request, &trigger->args, NULL) < 0) {
			RPERROR("Failed running trigger %s", trigger->name);
			RETURN_MODULE_FAIL;
		}
		/*
		 *      Wait for the trigger to finish
		 *
		 *      FIXME - We really need to log stdout/stderr
		 */
		waitpid(trigger->pid, NULL, 0);
	/*
	 *	Execute the program without waiting for the result.
	 */
	} else {
		if (fr_exec_nowait(request, &trigger->args, NULL) < 0) {
			RPERROR("Failed running trigger %s", trigger->name);
			RETURN_MODULE_FAIL;
		}
	}

	RETURN_MODULE_OK;
}

static unlang_action_t trigger_run(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	fr_trigger_t	*trigger = talloc_get_type_abort(uctx, fr_trigger_t);

	RDEBUG("Running trigger %s", trigger->name);

	if (unlang_xlat_push(request, &trigger->args, request,
			     trigger->xlat, UNLANG_SUB_FRAME) < 0) RETURN_MODULE_FAIL;

	return UNLANG_ACTION_PUSHED_CHILD;
}


/** Execute a trigger - call an executable to process an event
 *
 * @note Calls to this function will be ignored if #trigger_exec_init has not been called.
 *
 * @param[in] intp		Interpreter to run the trigger with.  If this is NULL the
 *				trigger will be executed synchronously.
 *
 * @param[in] request		The current request.
 * @param[in] cs			to search for triggers in.
 *				If cs is not NULL, the portion after the last '.' in name is used for the trigger.
 *				If cs is NULL, the entire name is used to find the trigger in the global trigger
 *				section.
 * @param[in] name		the path relative to the global trigger section ending in the trigger name
 *				e.g. module.ldap.pool.start.
 * @param[in] rate_limit	whether to rate limit triggers.
 * @param[in] args		to make available via the @verbatim %(trigger:<arg>) @endverbatim xlat.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int trigger_exec(unlang_interpret_t *intp, request_t *request,
		 CONF_SECTION const *cs, char const *name, bool rate_limit, fr_pair_list_t *args)
{
	CONF_SECTION const	*subcs;

	CONF_ITEM		*ci;
	CONF_PAIR		*cp;

	char const		*attr;
	char const		*value;

	request_t		*child;
	fr_trigger_t		*trigger;
	ssize_t			slen;

	/*
	 *	noop if trigger_exec_init was never called
	 */
	if (!triggers_init) return 0;

	/*
	 *	Use global "trigger" section if no local config is given.
	 */
	if (!cs) {
		cs = trigger_exec_main;
		attr = name;
	} else {
		/*
		 *	Try to use pair name, rather than reference.
		 */
		attr = strrchr(name, '.');
		if (attr) {
			attr++;
		} else {
			attr = name;
		}
	}

	/*
	 *	Find local "trigger" subsection.  If it isn't found,
	 *	try using the global "trigger" section, and reset the
	 *	reference to the full path, rather than the sub-path.
	 */
	subcs = cf_section_find(cs, "trigger", NULL);
	if (!subcs && trigger_exec_main && (cs != trigger_exec_main)) {
		subcs = trigger_exec_subcs;
		attr = name;
	}
	if (!subcs) return -1;

	ci = cf_reference_item(subcs, trigger_exec_main, attr);
	if (!ci) {
		ROPTIONAL(RDEBUG2, DEBUG2, "No trigger configured for: %s", attr);
		return -1;
	}

	if (!cf_item_is_pair(ci)) {
		ROPTIONAL(RERROR, ERROR, "Trigger is not a configuration variable: %s", attr);
		return -1;
	}

	cp = cf_item_to_pair(ci);
	if (!cp) return -1;

	value = cf_pair_value(cp);
	if (!value) {
		ROPTIONAL(RERROR, ERROR, "Trigger has no value: %s", name);
		return -1;
	}

	/*
	 *	Don't do any real work if we're checking the
	 *	configuration.  i.e. don't run "start" or "stop"
	 *	triggers on "radiusd -XC".
	 */
	if (check_config) return 0;

	/*
	 *	Perform periodic rate_limiting.
	 */
	if (rate_limit) {
		trigger_last_fired_t	find, *found;
		time_t			now = time(NULL);

		find.ci = ci;

		pthread_mutex_lock(trigger_mutex);

		found = fr_rb_find(trigger_last_fired_tree, &find);
		if (!found) {
			MEM(found = talloc(NULL, trigger_last_fired_t));
			found->ci = ci;
			found->last_fired = 0;

			fr_rb_insert(trigger_last_fired_tree, found);
		}

		pthread_mutex_unlock(trigger_mutex);

		/*
		 *	Send the rate_limited traps at most once per second.
		 */
		if (found->last_fired == now) return -1;
		found->last_fired = now;
	}

	/*
	 *	radius_exec_program always needs a request.
	 */
	child = request_alloc_internal(NULL, (&(request_init_args_t){ .parent = request, .detachable = true }));

	/*
	 *	Add the args to the request data, so they can be picked up by the
	 *	trigger_xlat function.
	 */
	if (args && (request_data_add(child, &trigger_exec_main, REQUEST_INDEX_TRIGGER_ARGS, args,
				      false, false, false) < 0)) {
		talloc_free(child);
		return -1;
	}

	{
		void *name_tmp;

		memcpy(&name_tmp, &name, sizeof(name_tmp));

		if (request_data_add(child, &trigger_exec_main, REQUEST_INDEX_TRIGGER_NAME,
				     name_tmp, false, false, false) < 0) {
			talloc_free(child);
			return -1;
		}
	}

	MEM(trigger = talloc_zero(child, fr_trigger_t));
	fr_value_box_list_init(&trigger->args);
	trigger->name = talloc_strdup(trigger, value);

	/*
	 *	Automatically populate the trigger's
	 *	request list from the parent's.
	 */
	if (request && !fr_pair_list_empty(&request->request_pairs)) {
		(void) fr_pair_list_copy(child->request_ctx, &child->request_pairs, &request->request_pairs);
	}

	slen = xlat_tokenize_argv(trigger, &trigger->xlat, NULL,
				  &FR_SBUFF_IN(trigger->name, talloc_array_length(trigger->name) - 1), NULL, NULL);
	if (slen <= 0) {
		char *spaces, *text;

		fr_canonicalize_error(trigger, &spaces, &text, slen, fr_strerror());

		cf_log_err(cp, "Syntax error");
		cf_log_err(cp, "%s", trigger->name);
		cf_log_err(cp, "%s^ %s", spaces, text);

		talloc_free(child);
		talloc_free(spaces);
		talloc_free(text);
		return -1;
	}

	/*
	 *	If we're not running it locally use the default
	 *	interpreter for the thread.
	 */
	if (intp) {
		unlang_interpret_set(child, intp);
		if (unlang_subrequest_child_push_and_detach(child) < 0) {
		error:
			ROPTIONAL(RPEDEBUG, PERROR, "Running trigger failed");
			talloc_free(child);
			return -1;
		}
	}

	if (unlang_interpret_push_function(child, trigger_run, trigger_resume,
					   NULL, UNLANG_TOP_FRAME, trigger) < 0) goto error;

	if (!intp) {
		/*
		 *	Wait for the exec to finish too,
		 *	so where there are global events
		 *	the child processes don't race
		 *	with something like the server
		 *	shutting down.
		 */
		trigger->synchronous = true;
		unlang_interpret_synchronous(child);
		talloc_free(child);
	}

	/*
	 *	Otherwise the worker cleans up the child request.
	 */
	return 0;
}

/** Create trigger arguments to describe the server the pool connects to
 *
 * @note #trigger_exec_init must be called before calling this function,
 *	 else it will return NULL.
 *
 * @param[in] ctx	to allocate fr_pair_t s in.
 * @param[out] list	to append Pool-Server and Pool-Port pairs to
 * @param[in] server	we're connecting to.
 * @param[in] port	on that server.
 */
void trigger_args_afrom_server(TALLOC_CTX *ctx, fr_pair_list_t *list, char const *server, uint16_t port)
{
	fr_dict_attr_t const	*server_da;
	fr_dict_attr_t const	*port_da;
	fr_pair_t		*vp;

	server_da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_CONNECTION_POOL_SERVER);
	if (!server_da) {
		ERROR("Incomplete dictionary: Missing definition for \"Connection-Pool-Server\"");
		return;
	}

	port_da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_CONNECTION_POOL_PORT);
	if (!port_da) {
		ERROR("Incomplete dictionary: Missing definition for \"Connection-Pool-Port\"");
		return;
	}

	MEM(vp = fr_pair_afrom_da(ctx, server_da));
	fr_pair_value_strdup(vp, server);
	fr_pair_append(list, vp);

	MEM(vp = fr_pair_afrom_da(ctx, port_da));
	vp->vp_uint16 = port;
	fr_pair_append(list, vp);
}
