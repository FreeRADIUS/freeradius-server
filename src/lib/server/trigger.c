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

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/rad_assert.h>

/** Whether triggers are enabled globally
 *
 */
static bool			triggers_init;
static CONF_SECTION const	*trigger_exec_main, *trigger_exec_subcs;
static rbtree_t			*trigger_last_fired_tree;
static pthread_mutex_t		*trigger_mutex;

#define REQUEST_INDEX_TRIGGER_NAME	1
#define REQUEST_INDEX_TRIGGER_ARGS	2

/** Describes a rate limiting entry for a trigger
 *
 */
typedef struct {
	CONF_ITEM	*ci;		//!< Config item this rate limit counter is associated with.
	time_t		last_fired;	//!< When this trigger last fired.
} trigger_last_fired_t;

/** Retrieve attributes from a special trigger list
 *
 */
ssize_t trigger_xlat(UNUSED TALLOC_CTX *ctx, char **out, UNUSED size_t outlen,
		     UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
		     REQUEST *request, char const *fmt)
{
	VALUE_PAIR		*head;
	fr_dict_attr_t const	*da;
	VALUE_PAIR		*vp;

	if (!triggers_init) {
		ERROR("Triggers are not enabled");
		return -1;
	}

	if (!request_data_reference(request, &trigger_exec_main, REQUEST_INDEX_TRIGGER_NAME)) {
		ERROR("trigger xlat may only be used in a trigger command");
		return -1;
	}

	head = request_data_reference(request, &trigger_exec_main, REQUEST_INDEX_TRIGGER_ARGS);

	/*
	 *	No arguments available.
	 */
	if (!head) return -1;

	da = fr_dict_attr_by_name(request->dict, fmt);
	if (!da) {
		ERROR("Unknown attribute \"%s\"", fmt);
		return -1;
	}

	vp = fr_pair_find_by_da(head, da, TAG_ANY);
	if (!vp) {
		ERROR("Attribute \"%s\" is not valid for this trigger", fmt);
		return -1;
	}
	*out = fr_pair_value_asprint(request, vp, '\0');

	return talloc_array_length(*out) - 1;
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
 * @param a first pointer to compare.
 * @param b second pointer to compare.
 * @return
 *	- -1 if a < b.
 *	- +1 if b > a.
 *	- 0 if both equal.
 */
static int _trigger_last_fired_cmp(void const *a, void const *b)
{
	trigger_last_fired_t const *lf_a = a, *lf_b = b;

	return (lf_a->ci < lf_b->ci) - (lf_a->ci > lf_b->ci);
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
 * @param cs	to use as global trigger section.
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

	MEM(trigger_last_fired_tree = rbtree_talloc_create(talloc_null_ctx(),
							   _trigger_last_fired_cmp, trigger_last_fired_t,
							   _trigger_last_fired_free, 0));

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

/** Execute a trigger - call an executable to process an event
 *
 * @note Calls to this function will be ignored if #trigger_exec_init has not been called.
 *
 * @param request	The current request.
 * @param cs		to search for triggers in.
 *			If cs is not NULL, the portion after the last '.' in name is used for the trigger.
 *			If cs is NULL, the entire name is used to find the trigger in the global trigger
 *			section.
 * @param name		the path relative to the global trigger section ending in the trigger name
 *			e.g. module.ldap.pool.start.
 * @param rate_limit	whether to rate limit triggers.
 * @param args		to make available via the @verbatim %{trigger:<arg>} @endverbatim xlat.
 * @return 		- 0 on success.
 *			- -1 on failure.
 */
int trigger_exec(REQUEST *request, CONF_SECTION const *cs, char const *name, bool rate_limit, VALUE_PAIR *args)
{
	CONF_SECTION const	*subcs;

	CONF_ITEM		*ci;
	CONF_PAIR		*cp;

	char const		*attr;
	char const		*value;

	VALUE_PAIR		*vp;

	REQUEST			*fake = NULL;
	int			ret = 0;

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
	 *	May be called for Status-Server packets.
	 */
	vp = NULL;
	if (request && request->packet) vp = request->packet->vps;

	/*
	 *	Perform periodic rate_limiting.
	 */
	if (rate_limit) {
		trigger_last_fired_t	find, *found;
		time_t			now = time(NULL);

		find.ci = ci;

		pthread_mutex_lock(trigger_mutex);

		found = rbtree_finddata(trigger_last_fired_tree, &find);
		if (!found) {
			MEM(found = talloc(NULL, trigger_last_fired_t));
			found->ci = ci;
			found->last_fired = 0;

			rbtree_insert(trigger_last_fired_tree, found);
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
	if (!request) request = fake = request_alloc(NULL);

	RDEBUG2("Trigger \"%s\": %s", name, value);

	/*
	 *	Add the args to the request data, so they can be picked up by the
	 *	xlat_trigger function.
	 */
	if (args && (request_data_add(request, &trigger_exec_main, REQUEST_INDEX_TRIGGER_ARGS, args,
				      false, false, false) < 0)) {
		RERROR("Failed adding trigger request data");
		return -1;
	}

	{
		void *name_tmp;

		memcpy(&name_tmp, &name, sizeof(name_tmp));

		if (request_data_add(request, &trigger_exec_main, REQUEST_INDEX_TRIGGER_NAME,
				     name_tmp, false, false, false) < 0) {
			RERROR("Failed marking request as inside trigger");
			return -1;
		}
	}

	/*
	 *	Don't fire triggers if we're just testing
	 */
	if (!check_config) ret = radius_exec_program(request, NULL, 0, NULL,
						     request, value, vp, false, true,
						     fr_time_delta_from_sec(EXEC_TIMEOUT));
	(void) request_data_get(request, &trigger_exec_main, REQUEST_INDEX_TRIGGER_NAME);
	(void) request_data_get(request, &trigger_exec_main, REQUEST_INDEX_TRIGGER_ARGS);

	if (fake) talloc_free(fake);

	return ret;
}

/** Create trigger arguments to describe the server the pool connects to
 *
 * @note #trigger_exec_init must be called before calling this function,
 *	 else it will return NULL.
 *
 * @param[in] ctx	to allocate VALUE_PAIR s in.
 * @param[in] server	we're connecting to.
 * @param[in] port	on that server.
 * @return
 *	- NULL on failure, or if triggers are not enabled.
 *	- list containing Pool-Server and Pool-Port
 */
VALUE_PAIR *trigger_args_afrom_server(TALLOC_CTX *ctx, char const *server, uint16_t port)
{
	fr_dict_attr_t const	*server_da;
	fr_dict_attr_t const	*port_da;
	VALUE_PAIR		*out = NULL, *vp;
	fr_cursor_t		cursor;

	server_da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_CONNECTION_POOL_SERVER);
	if (!server_da) {
		ERROR("Incomplete dictionary: Missing definition for \"Connection-Pool-Server\"");
		return NULL;
	}

	port_da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal()), FR_CONNECTION_POOL_PORT);
	if (!port_da) {
		ERROR("Incomplete dictionary: Missing definition for \"Connection-Pool-Port\"");
		return NULL;
	}

	fr_cursor_init(&cursor, &out);

	MEM(vp = fr_pair_afrom_da(ctx, server_da));
	fr_pair_value_strcpy(vp, server);
	fr_cursor_append(&cursor, vp);

	MEM(vp = fr_pair_afrom_da(ctx, port_da));
	vp->vp_uint16 = port;
	fr_cursor_append(&cursor, vp);

	return out;
}
