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
#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/server/main_loop.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/request_data.h>
#include <freeradius-devel/server/trigger.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/subrequest.h>
#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/tmpl.h>


#include <sys/wait.h>

/** Whether triggers are enabled globally
 *
 */
static CONF_SECTION const	*trigger_cs;
static fr_rb_tree_t		*trigger_last_fired_tree;
static pthread_mutex_t		*trigger_mutex;

/** Describes a rate limiting entry for a trigger
 *
 */
typedef struct {
	fr_rb_node_t	node;		//!< Entry in the trigger last fired tree.
	CONF_ITEM	*ci;		//!< Config item this rate limit counter is associated with.
	fr_time_t	last_fired;	//!< When this trigger last fired.
} trigger_last_fired_t;

static fr_dict_t const *dict_freeradius;
extern fr_dict_autoload_t trigger_dict[];
fr_dict_autoload_t trigger_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_trigger_name;
extern fr_dict_attr_autoload_t trigger_dict_attr[];
fr_dict_attr_autoload_t trigger_dict_attr[] = {
	{ .out = &attr_trigger_name, .name = "Trigger-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL }
};

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

/** Return whether triggers are enabled
 *
 */
bool trigger_enabled(void)
{
	return (trigger_cs != NULL);
}

typedef struct {
	fr_value_box_list_t	out;		//!< result of the xlap (which we ignore)
	unlang_result_t		result;		//!< the result of expansion
	tmpl_t			*vpt;		//!< the template to execute
	int			exec_status;	//!< Result of the program (if the trigger is a tmpl)
} fr_trigger_t;

/** Execute a trigger - call an executable to process an event
 *
 * A trigger ties a state change (e.g. connection up) in a module to an action
 * (e.g. send an SNMP trap) defined in raqddb/triggers.conf or in the trigger
 * section of a module, and can be created with one call to trigger().
 *
 * The trigger function expands the configuration item, and runs the given
 * function (exec, sql insert, etc.) asynchronously, allowing the server to
 * keep processing packets while the action is being taken.
 *
 * The name of each trigger is based on the module or portion of the server
 * which runs the trigger, and is usually taken from the state when the module
 * has a state change.
 *
 * Triggers are separate from logs, because log messages are generally
 * informational, are not time sensitive, and usually require log files to be
 * parsed and filtered in order to find relevant information.
 *
 * In contrast, triggers are something specific which the administrator needs
 * to be notified about immediately and can't wait to post-process a log file.
 *
 * @note Calls to this function will be ignored if #trigger_init has not been called.
 *
 * @param[in] intp		Interpreter to run the trigger with.  If this is NULL the
 *				trigger will be executed synchronously.
 * @param[in] cs		to search for triggers in.
 *				If cs is not NULL, the portion after the last '.' in name is used for the trigger.
 *				If cs is NULL, the entire name is used to find the trigger in the global trigger
 *				section.
 * @param[in] name		the path relative to the global trigger section ending in the trigger name
 *				e.g. module.ldap.pool.start.
 * @param[in] rate_limit	whether to rate limit triggers.
 * @param[in] args		to make available via the @verbatim %trigger(<arg>) @endverbatim xlat.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int trigger(unlang_interpret_t *intp,
	    CONF_SECTION const *cs, char const *name, bool rate_limit, fr_pair_list_t *args)
{
	CONF_ITEM		*ci;
	CONF_PAIR		*cp;

	char const		*attr;
	char const		*value;

	request_t		*request;
	fr_trigger_t		*trigger;
	ssize_t			slen;

	fr_event_list_t		*el;
	tmpl_rules_t		t_rules;

	/*
	 *	noop if trigger_init was never called, or if
	 *	we're just checking the configuration.
	 */
	if (!trigger_cs || check_config) return 0;

	/*
	 *	A module can have a local "trigger" section.  In which
	 *	case that is used in preference to the global one.
	 *
	 *	@todo - we should really allow triggers via @trigger,
	 *	so that all of the triggers are in one location.  And
	 *	then we can have different triggers for different
	 *	module instances.
	 */
	if (cs) {
		CONF_SECTION const *subcs;

		subcs = cf_section_find(cs, "trigger", NULL);
		if (!subcs) goto use_global;

		/*
		 *	If a local trigger{...} section exists, then
		 *	use the local part of the name, rather than
		 *	the full path.
		 */
		attr = strrchr(name, '.');
		if (attr) {
			attr++;
		} else {
			attr = name;
		}
	} else {
	use_global:
		cs = trigger_cs;
		attr = name;
	}

	/*
	 *	Find the trigger.  Note that we do NOT allow searching
	 *	from the root of the tree.  Triggers MUST be in a
	 *	trigger{...} section.
	 */
	ci = cf_reference_item(cs, cs, attr);
	if (!ci) {
		if (cs != trigger_cs) goto use_global; /* not found locally, try to find globally */

		DEBUG3("Failed finding trigger '%s'", attr);
		return -1;
	}

	if (!cf_item_is_pair(ci)) {
		ERROR("Trigger is not a configuration variable: %s", attr);
		return -1;
	}

	cp = cf_item_to_pair(ci);
	if (!cp) return -1;

	value = cf_pair_value(cp);
	if (!value) {
		DEBUG3("Trigger has no value: %s", name);
		return -1;
	}

	/*
	 *	Perform periodic rate_limiting.
	 */
	if (rate_limit) {
		trigger_last_fired_t	find, *found;
		fr_time_t		now = fr_time();

		find.ci = ci;

		pthread_mutex_lock(trigger_mutex);

		found = fr_rb_find(trigger_last_fired_tree, &find);
		if (!found) {
			MEM(found = talloc(NULL, trigger_last_fired_t));
			found->ci = ci;
			/*
			 *	Initialise last_fired to 2 seconds ago so
			 *	the trigger fires on the first occurrence
			 */
			found->last_fired = fr_time_wrap(NSEC * -2);

			fr_rb_insert(trigger_last_fired_tree, found);
		}

		pthread_mutex_unlock(trigger_mutex);

		/*
		 *	Send the rate_limited traps at most once per second.
		 *
		 *	@todo - make this configurable for longer periods of time.
		 */
		if (fr_time_to_sec(found->last_fired) == fr_time_to_sec(now)) return -1;
		found->last_fired = now;
	}

	/*
	 *	Allocate a request to run asynchronously in the interpreter.
	 */
	request = request_local_alloc_internal(NULL, (&(request_init_args_t){ .detachable = true }));
	request->name = talloc_typed_asprintf(request, "trigger-%s", name);

	if (args) {
		fr_pair_t	*vp;

		if (fr_pair_list_copy(request->request_ctx, &request->request_pairs, args) < 0) {
			PERROR("Failed copying trigger arguments");
			talloc_free(request);
			return -1;
		}

		/*
		 *	Add the trigger name to the request data
		 */
		MEM(pair_append_request(&vp, attr_trigger_name) >= 0);
		fr_pair_value_strdup(vp, cf_pair_value(cp), false);
	}

	MEM(trigger = talloc_zero(request, fr_trigger_t));
	fr_value_box_list_init(&trigger->out);

	el = unlang_interpret_event_list(request);
	if (!el) el = main_loop_event_list();

	t_rules = (tmpl_rules_t) {
		.attr = {
			.dict_def = request->local_dict, /* we can use local attributes */
			.list_def = request_attr_request,
		},
		.xlat = {
						     .runtime_el = el,
		},
		.at_runtime = true,
	};

	slen = tmpl_afrom_substr(trigger, &trigger->vpt, &FR_SBUFF_IN(value, talloc_strlen(value)),
				 cf_pair_value_quote(cp), NULL, &t_rules);
	if (slen <= 0) {
		char *spaces, *text;

		fr_canonicalize_error(trigger, &spaces, &text, slen, value);

		cf_log_err(cp, "Failed parsing trigger expresion");
		cf_log_err(cp, "%s", text);
		cf_log_perr(cp, "%s^", spaces);

		talloc_free(request);
		talloc_free(spaces);
		talloc_free(text);
		return -1;
	}

	if (!tmpl_is_exec(trigger->vpt) && !tmpl_is_xlat(trigger->vpt)) {
		/*
		 *	We only support exec and xlat templates.
		 *	Anything else is an error.
		 */
		cf_log_err(cp, "Trigger must be an \"expr\" or `exec`");
		talloc_free(request);
		return -1;
	}

	fr_assert(trigger->vpt != NULL);

	if (unlang_tmpl_push(trigger, &trigger->result, &trigger->out, request, trigger->vpt,
			     &(unlang_tmpl_args_t) {
				.type = UNLANG_TMPL_ARGS_TYPE_EXEC,
				.exec = {
					.status_out = &trigger->exec_status,
					.timeout = fr_time_delta_from_sec(5),
					},
			     }, UNLANG_TOP_FRAME) < 0) {
		talloc_free(request);
	}

	/*
	 *	An interpreter was passed in, we can run the expansion
	 *	asynchronously in that interpreter.  And then the
	 *	worker cleans up the detached request.
	 */
	if (intp) {
		unlang_interpret_set(request, intp);

		/*
		 *	Don't allow the expansion to run for a long time.
		 *
		 *	@todo - make the timeout configurable.
		 */
		if (unlang_interpret_set_timeout(request, fr_time_delta_from_sec(1)) < 0) {
			DEBUG("Failed setting timeout on trigger %s", value);
			talloc_free(request);
			return -1;
		}

		if (unlang_subrequest_child_push_and_detach(request) < 0) {
			PERROR("Running trigger failed");
			talloc_free(request);
			return -1;
		}
	} else {
		/*
		 *	No interpreter, we MUST be running from the
		 *	main loop.  We then run the expansion
		 *	synchronously.  This allows the expansion /
		 *	notification to finish before the server shuts
		 *	down.
		 *
		 *	If the expansion was async, then it may be
		 *	possible for the server to exit before the
		 *	expansion finishes.  Arguably the worker
		 *	thread should ensure that the server doesn't
		 *	exit until all requests have acknowledged that
		 *	they've exited.
		 *
		 *	But those exits may be advisory.  i.e. "please
		 *	finish the request".  This one here is
		 *	mandatary to finish before the server exits.
		 */
		unlang_interpret_synchronous(NULL, request);
		talloc_free(request);
	}

	return 0;
}

/** Create trigger arguments to describe the server the pool connects to
 *
 * @note #trigger_init must be called before calling this function,
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
	fr_pair_value_strdup(vp, server, false);
	fr_pair_append(list, vp);

	MEM(vp = fr_pair_afrom_da(ctx, port_da));
	vp->vp_uint16 = port;
	fr_pair_append(list, vp);
}

static int _mutex_free(pthread_mutex_t *mutex)
{
	pthread_mutex_destroy(mutex);
	return 0;
}

/** Free trigger resources
 *
 */
static int _trigger_free(UNUSED void *uctx)
{
	fr_dict_autofree(trigger_dict);
	TALLOC_FREE(trigger_last_fired_tree);
	TALLOC_FREE(trigger_mutex);

	return 0;
}

/** Set the global trigger section trigger will search in, and register xlats
 *
 * This function exists because triggers are used by the connection pool, which
 * is used in the server library which may not have the mainconfig available.
 * Additionally, utilities may want to set their own root config sections.
 *
 * We don't register the trigger xlat here, as we may inadvertently initialise
 * the xlat code, which is annoying when this is called from a utility.
 *
 * @param[in] cs_arg	to use as global trigger section.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _trigger_init(void *cs_arg)
{
	CONF_SECTION *cs;

	if (unlikely(fr_dict_autoload(trigger_dict) < 0)) {
		PERROR("Failed loading trigger dictionaries");
		return -1;
	}
	if (unlikely(fr_dict_attr_autoload(trigger_dict_attr) < 0)) {
		PERROR("Failed loading trigger attributes");
		return -1;
	}

	cs = talloc_get_type_abort(cs_arg, CONF_SECTION);
	if (!cs) {
		ERROR("%s - Pointer to main_config was NULL", __FUNCTION__);
		return -1;
	}

	trigger_cs = cf_section_find(cs, "trigger", NULL);
	if (!trigger_cs) {
		WARN("trigger { ... } subsection not found, triggers will be disabled");
		return 0;
	}

	MEM(trigger_last_fired_tree = fr_rb_inline_talloc_alloc(talloc_null_ctx(),
								trigger_last_fired_t, node,
								_trigger_last_fired_cmp, _trigger_last_fired_free));

	trigger_mutex = talloc(talloc_null_ctx(), pthread_mutex_t);
	pthread_mutex_init(trigger_mutex, 0);
	talloc_set_destructor(trigger_mutex, _mutex_free);

	return 0;
}

int trigger_init(CONF_SECTION const *cs)
{
	int ret;

	fr_atexit_global_once_ret(&ret, _trigger_init, _trigger_free, UNCONST(CONF_SECTION *, cs));

	return ret;
}
