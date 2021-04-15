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
 * @file tls/engine.c
 * @brief Initialise and manage OpenSSL engines
 *
 * @copyright 2021 The FreeRADIUS server project
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls - "

#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/engine.h>
#include <freeradius-devel/tls/log.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/value.h>

#include <openssl/engine.h>

/** Our wrapper around an OpenSSL engine
 *
 */
typedef struct {
	fr_rb_node_t			node;		//!< rbtree node fields.

	char const			*id;		//!< Engine identifier.
	char const			*instance;	//!< Instance identifier for the engine.

	ENGINE				*e;		//!< Engine that was loaded.
	fr_tls_engine_ctrl_list_t 	*pre_ctrls;	//!< Pre controls applied to the engine.
	fr_tls_engine_ctrl_list_t	*post_ctrls;	//!< Post controls applied to the engine.
} tls_engine_t;

/** Engines that we've loaded
 *
 * This is the global set of OpenSSL engines that are in use by the
 * current configuration.
 *
 * We could use OpenSSL's reference counting system, but this doesn't
 * work well for dynamically loaded engines, where we may want one
 * instance of the engine per thread.
 */
static fr_rb_tree_t	*tls_engines;

/** Compares two engines
 *
 */
static int8_t tls_engine_cmp(void const *one, void const *two)
{
	tls_engine_t const *a = talloc_get_type_abort_const(one, tls_engine_t);
	tls_engine_t const *b = talloc_get_type_abort_const(two, tls_engine_t);
	int8_t ret;

	ret = strcmp(a->id, b->id);
	ret = CMP(ret, 0);
	if (ret != 0) return ret;

	/*
	 *	May not have an instance ID
	 */
	if (!a->instance && !b->instance) return 0;
	if (!a->instance) return -1;
	if (!b->instance) return +1;

	ret = strcmp(a->instance, b->instance);
	return CMP(ret, 0);
}

/** Add the list of supported engine commands to the error stack
 *
 * Uses OpenSSL's ridiculously complex ENGINE_ctrl API to provide useful
 * information about the controls the given engine provides.
 *
 * @param[in] e		Engine to return commands for.
 */
static void CC_HINT(nonnull) tls_engine_control_notfound_strerror(ENGINE *e, char const *bad_ctrl)
{
	int		cmd, ret;
	TALLOC_CTX	*pool;

	/*
	 *	ENGINE_HAS_CTRL_FUNCTION doesn't seem
	 *	to be available in OpenSSL 1.1.0 so
	 *	we fudge it with this.
	 */
	bool		first = true;

	pool = talloc_pool(NULL, 256);	/* Avoid lots of mallocs */
	if (unlikely(!pool)) return;

	fr_strerror_printf("engine %s does not export control %s", ENGINE_get_id(e), bad_ctrl);

	for (cmd = ENGINE_ctrl(e, ENGINE_CTRL_GET_FIRST_CMD_TYPE, 0, NULL, NULL);
	     cmd > 0;
	     cmd = ENGINE_ctrl(e, ENGINE_CTRL_GET_NEXT_CMD_TYPE, cmd, NULL, NULL)) {
		size_t name_len, desc_len;
		char *name, *desc;
		char const *flags;

	     	if (!ENGINE_cmd_is_executable(e, cmd)) continue;

		/*
		 *	Copy the ctrl name out to a temporary buffer
		 */
		name_len = ENGINE_ctrl(e, ENGINE_CTRL_GET_NAME_LEN_FROM_CMD, 0, NULL, NULL);
		if (unlikely(name_len == 0)) continue;

		name = talloc_array(pool, char, name_len + 1);
		if (unlikely(!name)) break;

		if (unlikely(ENGINE_ctrl(e, ENGINE_CTRL_GET_NAME_FROM_CMD, 0, name, NULL) <= 0)) break;

		/*
		 *	Copy the ctrl description out to a temporary buffer
		 */
		desc_len = ENGINE_ctrl(e, ENGINE_CTRL_GET_DESC_LEN_FROM_CMD, 0, NULL, NULL);
		if (desc_len > 0) {
			desc = talloc_array(pool, char, desc_len + 1);
			if (unlikely(!desc)) break;

			if (unlikely(ENGINE_ctrl(e, ENGINE_CTRL_GET_DESC_FROM_CMD, 0, desc, NULL) <= 0)) break;
		} else {
			desc = NULL;
		}

		ret = ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, 0, NULL, NULL);
		if (ret & ENGINE_CMD_FLAG_NO_INPUT) {
			flags = "none";
		} else if ((ret & ENGINE_CMD_FLAG_NUMERIC) && (ret & ENGINE_CMD_FLAG_STRING)) {
			flags = "number and string";
		} else if (ret & ENGINE_CMD_FLAG_NUMERIC) {
			flags = "number";
		} else if (ret & ENGINE_CMD_FLAG_STRING) {
			flags = "string";
		} else {
			flags = "unavailable";
		}

		if (first) {
			fr_strerror_const_push("available controls are:");
			first = false;
		}
		fr_strerror_printf_push("%s, arg(s) %s%s%s", name, flags, desc ? " - " : "", desc ? desc : "");
		talloc_free_children(pool);
	}
	if (first) fr_strerror_const_push("no controls available");

	talloc_free(pool);
}

/** Duplicate an engine control
 *
 * @param[in] ctx	To allocate new control in.
 * @param[in] in	control to copy.
 * @return
 *	- A copy of the engine control on success.
 *	- NULL on failure.
 */
static inline CC_HINT(always_inline) fr_tls_engine_ctrl_t *tls_engine_ctrl_dup(TALLOC_CTX *ctx,
									       fr_tls_engine_ctrl_t const *in)
{
	fr_tls_engine_ctrl_t *n;

	n = talloc(ctx, fr_tls_engine_ctrl_t);
	if (unlikely(!n)) {
		fr_strerror_const("Out of memory");
		return n;
	}

	*n = (fr_tls_engine_ctrl_t){
		.name = talloc_typed_strdup(n, in->name),
		.value = talloc_typed_strdup(n, in->value)
	};

	return n;
}

/** Unloads the underlying OpenSSL engine
 *
 */
static int _tls_engine_free(tls_engine_t *our_e)
{
	/*
	 *	Make memory leaks very explicit
	 *	so someone will investigate.
	 */
	if (unlikely(ENGINE_finish(our_e->e) != 1)) {
		fr_tls_log_error(NULL, "de-init on engine %s failed", our_e->id);
		return -1;
	}

	if (unlikely(ENGINE_free(our_e->e) != 1)) {
		fr_tls_log_error(NULL, "free on engine %s failed", our_e->id);
		return -1;
	}

	return 0;
}

/** Initialise an OpenSSL engine, adding it to our list of engines
 *
 * @note Errors should be retrieved with fr_strerror().
 *
 * @param[out] e_out		The engine that was just initialised.
 *				The caller must not free/finish this engine
 *				it will be called up when the server exits.
 * @param[in] id		Engine identifier.  This is usually identifier
 *				that matches OpenSSL's engine ID e.g. "pkcs11".
 * @param[in] instance		Instance identifier for a given engine.
 *				This is useful for "dynamic" engines, i.e. ones
 *				OpenSSL dynamically loads.
 * @param[in] pre_ctrls		Engine ctls to be used after obtaining a
 *				structural reference but before obtaining a
 *				functional reference (after loading before init).
 *				Will be duplicated to avoid ordering issues.
 * @param[in] post_ctrls	Engine ctls to be used before unloading an
 *				engine (to shut it down in a graceful way).
 *				Will be duplicated to avoid ordering issues.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_tls_engine_init(ENGINE **e_out,
		       char const *id, char const *instance,
		       fr_tls_engine_ctrl_list_t const *pre_ctrls, fr_tls_engine_ctrl_list_t const *post_ctrls)
{
	tls_engine_t		*our_e = NULL;
	ENGINE			*e;
	fr_tls_engine_ctrl_t	*ctrl = NULL, *n;

	if (!tls_engines) {
		tls_engines = fr_rb_alloc(NULL, tls_engine_t, node, tls_engine_cmp, fr_rb_node_talloc_free, 0);
		if (unlikely(!tls_engines)) {
		oom:
			fr_strerror_const("Out of memory");
			return -1;
		}
	} else {
		tls_engine_t *found = NULL;

		found = fr_rb_find(tls_engines, &(tls_engine_t){ .id = id, .instance = instance });
		if (found) {
			fr_strerror_printf("engine %s%s%s%salready initialised", id,
					   instance ? " (" : "",
					   instance ? instance : "",
					   instance ? ") " : "");
			return -1;
		}
	}

	e = ENGINE_by_id(id);
	if (!e) {
		fr_strerror_printf("%s engine is not available", id);
		return -1;
	}

	if (pre_ctrls) while ((ctrl = fr_dlist_next(pre_ctrls, ctrl))) {
		int cmd, flags, ret;

		cmd = ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FROM_NAME, 0, UNCONST(void *, ctrl->name), NULL);
		if (cmd == 0) {
			fr_strerror_printf("%s engine does not implement \"%s\" control", id, ctrl->name);
			/*
			 *	Dumps all available controls to
			 *	the error stack.
			 */
			tls_engine_control_notfound_strerror(e, ctrl->name);
		error:
			ENGINE_free(e);
			return -1;
		}

		/*
		 *	If the command has the ENGINE_CMD_FLAG_NO_INPUT flag set,
		 *	arg must be NULL and ENGINE_ctrl() is called with i set to
		 *	0 and p set to NULL. Otherwise, arg must not be NULL.
		 *	If the command accepts string input, i is set to 0 and arg
		 *      is passed as the p argument to ENGINE_ctrl(). Otherwise, arg
		 *	is converted with strtol(3) and passed as the i argument to
		 *	ENGINE_ctrl(), setting p to NULL.
		 */
		flags = ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, 0, NULL, NULL);
		if (flags & ENGINE_CMD_FLAG_NO_INPUT) {
			ret = ENGINE_ctrl(e, cmd, 0, NULL, NULL);
		/*
		 *	Do an explicit sanity check for this
		 */
		} else if (unlikely((flags & ENGINE_CMD_FLAG_STRING) && (flags & ENGINE_CMD_FLAG_NUMERIC))) {
			fr_strerror_printf("File bug against freeradius-server stating "
					   "both numeric and string commands needed for OpenSSL engine controls");
			goto error;
		/*
		 *	We do an explicit conversion to provide more useful feedback
		 *	to the user in case the log
		 */
		} else if (flags & ENGINE_CMD_FLAG_NUMERIC) {
			fr_value_box_t	vb;

			if (fr_value_box_cast(NULL, &vb, FR_TYPE_INT32, NULL, fr_box_strvalue(ctrl->value)) < 0) {
				fr_strerror_printf_push("control %s requires an integer value", ctrl->name);
				goto error;
			}
			ret = ENGINE_ctrl(e, cmd, vb.vb_int32, NULL, 0);
		} else if (flags & ENGINE_CMD_FLAG_STRING) {
			ret = ENGINE_ctrl(e, cmd, 0, UNCONST(void *, ctrl->value), NULL);
		} else {
			fr_strerror_printf("control %s exports invalid flags", ctrl->name);
			goto error;
		}

		/*
		 *	ENGINE_ctrl_cmd() and ENGINE_ctrl_cmd_string() return 1 on
		 *	success or 0 on error.
		 */
		if (ret != 1) {
			tls_strerror_printf("control %s failed (%i)", ctrl->name, ret);
			goto error;
		}
	}

	if (unlikely(ENGINE_init(e) != 1)) {
		tls_strerror_printf("failed initialising engine %s", id);
		goto error;
	}

	our_e = talloc(tls_engines, tls_engine_t);
	if (unlikely(!our_e)) goto oom;

	*our_e = (tls_engine_t){
		.id = talloc_typed_strdup(our_e, id),
		.instance = talloc_typed_strdup(our_e, instance),
		.e = e
	};
	talloc_set_destructor(our_e, _tls_engine_free);

	/*
	 *	Duplicate pre and post ctrl lists
	 *
	 *	This will allow us to create thread-specific
	 *	dynamic engines later.
	 */
	fr_dlist_talloc_init(our_e->pre_ctrls, fr_tls_engine_ctrl_t, entry);
	fr_dlist_talloc_init(our_e->post_ctrls, fr_tls_engine_ctrl_t, entry);

	if (pre_ctrls) {
		ctrl = NULL;
		while ((ctrl = fr_dlist_next(pre_ctrls, ctrl))) {
			n = tls_engine_ctrl_dup(our_e, ctrl);
			if (unlikely(!n)) {
				talloc_free(our_e);
				return -1;
			}
			fr_dlist_insert_tail(our_e->pre_ctrls, n);
		}
	}

	if (post_ctrls) {
		ctrl = NULL;
		while ((ctrl = fr_dlist_next(post_ctrls, ctrl))) {
			n = tls_engine_ctrl_dup(our_e, ctrl);
			if (unlikely(!n)) {
				talloc_free(our_e);
				return -1;
			}
			fr_dlist_insert_tail(our_e->post_ctrls, n);
		}
	}

	*e_out = e;
	return 0;
}

/** Retrieve a pointer to an OpenSSL engine
 *
 * Does not change the reference count to the engine (we don't use this
 * particular OpenSSL feature).
 *
 * If the engine is not found in the current engine tree and auto_init
 * if true then it will be initialised with no pre or post ctrls.
 *
 * @note Errors should be retrieved with fr_strerror().
 *
 * @param[out] e_out		The engine that was just initialised.
 *				The caller must not free/finish this engine
 *				it will be called up when the server exits.
 * @param[in] id		Engine identifier.  This is usually identifier
 *				that matches OpenSSL's engine ID e.g. "pkcs11".
 * @param[in] instance		Instance identifier for a given engine.
 *				This is useful for "dynamic" engines, i.e. ones
 *				OpenSSL dl loads.
 * @param[in] auto_init		If the engine hasn't already been initialised
 *				auto-initialise it now, with no pre or post
 *				ctrls.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_tls_engine(ENGINE **e_out, char const *id, char const *instance, bool auto_init)
{
	tls_engine_t *found = NULL;

	if (!tls_engines) {
		if (!auto_init) {
		not_init:
			fr_strerror_printf("engine %s%s%s%snot initialised", id,
					   instance ? " (" : "",
					   instance ? instance : "",
					   instance ? ") " : "");
			return -1;
		}

	do_init:
		return fr_tls_engine_init(e_out, id, instance, NULL, NULL);
	}


	found = fr_rb_find(tls_engines, &(tls_engine_t){ .id = id, .instance = instance });
	if (!found) {
		if (!auto_init) goto not_init;
		goto do_init;
	}

	*e_out = found->e;
	return 0;
}

/** Should be called after any engine configuration has been completed
 *
 */
void fr_tls_engine_load_builtin(void)
{
	ENGINE_load_builtin_engines();	/* Needed to load AES-NI engine (also loads rdrand, boo) */

	/*
	 *	Mitigate against CrossTalk (CVE-2020-0543)
	 */
	if (!tls_engines || !fr_rb_find(tls_engines, &(tls_engine_t){ .id = "rdrand" })) {
		ENGINE *rand_engine;

		ENGINE_register_all_RAND();	/* Give rand engines a chance to register */

		/*
		 *	If OpenSSL settled on Intel's rdrand
		 *	unregister it and unload rdrand.
		 */
		rand_engine = ENGINE_get_default_RAND();
		if (rand_engine && (strcmp(ENGINE_get_id(rand_engine), "rdrand") == 0)) {
			ENGINE_unregister_RAND(rand_engine);
			ENGINE_finish(rand_engine);	/* Unload rdrand */
		}
	}
	ENGINE_register_all_complete();
}

/** Free any engines we've loaded
 *
 */
void fr_tls_engine_free_all(void)
{
	TALLOC_FREE(tls_engines);

#if OPENSSL_API_COMPAT < 0x10100000L
	/*
	 *	Free any lingering memory
	 *	OpenSSL man pages say to do this.
	 */
	ENGINE_cleanup();
#endif
}

#endif
