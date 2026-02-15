/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * $Id$
 *
 * @file global_lib.c
 * @brief Handle global configuration, initialisation and freeing for libraries
 *
 * @copyright 2022 The FreeRADIUS server project
 */
#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/util/atexit.h>

/*
 *  Terminator for array of global_lib_autoinst_t
 */
global_lib_autoinst_t const global_lib_terminator = { .name = NULL };

/*
 *  Global list of libraries
 */
typedef struct {
	fr_rb_tree_t		libs;
} global_lib_list_t;

static global_lib_list_t *lib_list;

/** Structure to track use of libraries.
 *
 */
typedef struct {
	fr_rb_node_t			entry;			//!<  Entry in tree of libraries
	global_lib_autoinst_t const	*autoinit;		//!<  Autoinit structure used to manage this library
	uint32_t			instance_count;		//!<  Number of current uses of this library
	bool				initialised;		//!<  Has the init callback been run for this library
} global_lib_inst_t;

/** Parse the global config section for a library and call its init function
 *
 * @param[in] lib	to configure and initialise
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int lib_init_call(global_lib_inst_t *lib)
{
	CONF_SECTION	*global_cs, *cs;

	/*
	 *	Find relevant config section
	 *	If the section does not exist allocate an empty one
	 *	so default rules can be evaluated.
	 */
	global_cs = cf_section_find(cf_root(main_config->root_cs), "global", NULL);
	if (!global_cs) global_cs = cf_section_alloc(main_config->root_cs, main_config->root_cs, "global", NULL);

	cs = cf_section_find(global_cs, lib->autoinit->name, NULL);
	if (!cs) cs = cf_section_alloc(global_cs, global_cs, lib->autoinit->name, NULL);

	if ((cf_section_rules_push(cs, lib->autoinit->config)) < 0 ||
	    (cf_section_parse(lib, lib->autoinit->inst, cs) < 0)) {
		cf_log_err(cs, "Failed evaluating configuration for libldap");
		return -1;
	}

	/*
	 *  Call the init callback if defined
	 */
	if (lib->autoinit->init && (lib->autoinit->init()) < 0) return -1;

	lib->initialised = true;

	return 0;
}

/** Instantiate a list of libraries
 *
 * @param to_init	Array of autoinit structures detailing libraries to initialise
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int lib_auto_instantiate(global_lib_autoinst_t * const *to_init)
{
	global_lib_autoinst_t * const *p;

	for (p = to_init; *p != &global_lib_terminator; p++) {
		global_lib_inst_t	*lib = NULL;

		lib = fr_rb_find(&lib_list->libs, &(global_lib_inst_t){ .autoinit = *p });

		/*
		 *  If the library is already initialised, just increase the reference count
		 */
		if ((lib) && (lib->initialised)) {
			lib->instance_count++;
			continue;
		}

		if (!lib) {
			MEM(lib = talloc_zero(lib_list, global_lib_inst_t));
			lib->autoinit = *p;
			fr_rb_insert(&lib_list->libs, lib);
		}
		lib->instance_count++;

		/*
		 *  If the main config parsing is not complete we can't initialise the library yet
		 */
		if (!main_config->root_cs) continue;

		DEBUG2("Instantiating %s", lib->autoinit->name);
		if (lib_init_call(lib) < 0) return -1;
	}

	return 0;
}

/** Callback for creation of "lib" symbols
 *
 */
int global_lib_auto_instantiate(UNUSED dl_t const *module, void *symbol, UNUSED void *user_ctx)
{
	if (lib_auto_instantiate((global_lib_autoinst_t **)symbol) < 0) return -1;

	return 0;
}

/** Run free callbacks for external libraries no-longer in use
 *
 * @param[in] to_free	Array of autoinit structures detailing libraries to free
 */
static void lib_autofree(global_lib_autoinst_t * const *to_free)
{
	global_lib_autoinst_t * const *p;

	for (p = to_free; *p != &global_lib_terminator; p++) {
		global_lib_inst_t	*lib = NULL;

		lib = fr_rb_find(&lib_list->libs, &(global_lib_inst_t){ .autoinit = *p });

		fr_assert_msg(lib, "Library %s already freed", (*p)->name);

		if (--lib->instance_count > 0) continue;

		/*
		 *  Only run the free callback if the library was successfully initialised
		 */
		if (lib->initialised && ((*p)->free)) (*p)->free();

		fr_rb_remove(&lib_list->libs, lib);
		talloc_free(lib);
	}
}

/** Callback for freeing of "lib" symbols
 *
 */
void global_lib_autofree(UNUSED dl_t const *module, void *symbol, UNUSED void *user_ctx)
{
	lib_autofree((global_lib_autoinst_t **)symbol);
}

/** Compare two fr_lib_t
 *
 */
static int8_t _lib_cmp(void const *one, void const *two)
{
	global_lib_inst_t const	*a = one;
	global_lib_inst_t const	*b = two;

	return CMP(a->autoinit, b->autoinit);
}

/** Free global list of libraries
 *
 * Called as an atexit function
 */
static int _lib_list_free_atexit(UNUSED void *uctx)
{
	if (talloc_free(lib_list) < 0) return -1;
	lib_list = NULL;
	return 0;
}

/** Initialise the global list of external libraries
 *
 */
int global_lib_init(void)
{
	if (lib_list) return 0;

	MEM(lib_list = talloc_zero(NULL, global_lib_list_t));
	fr_rb_inline_init(&lib_list->libs, global_lib_inst_t, entry, _lib_cmp, NULL);

	fr_atexit_global(_lib_list_free_atexit, NULL);
	return 0;
}

/** Walk the tree of libraries and instantiate any which are pending
 *
 */
int global_lib_instantiate(void)
{
	/*
	 *  Must be called after main config has been parsed
	 */
	fr_assert(main_config->root_cs);

	DEBUG2("#### Instantiating libraries ####");
	fr_rb_inorder_foreach(&lib_list->libs, global_lib_inst_t, lib) {
		if (lib->initialised) continue;

		DEBUG2("Instantiating %s", lib->autoinit->name);
		if (lib_init_call(lib) < 0) return -1;

	}
	endforeach
	return 0;
}
