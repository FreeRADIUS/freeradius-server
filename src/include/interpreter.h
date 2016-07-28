/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
#ifndef _FR_INTERPRETER_H
#define _FR_INTERPRETER_H
/**
 * $Id$
 *
 * @file include/interpreter.h
 * @brief The outside interface to interpreter.
 *
 * @author Alan DeKok <aland@freeradius.org>
 */
#include <freeradius-devel/conffile.h> /* Need CONF_* definitions */
#include <freeradius-devel/map_proc.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/rad_assert.h>

#ifdef __cplusplus
extern "C" {
#endif
/* Actions may be a positive integer (the highest one returned in the group
 * will be returned), or the keyword "return", represented here by
 * MOD_ACTION_RETURN, to cause an immediate return.
 * There's also the keyword "reject", represented here by MOD_ACTION_REJECT
 * to cause an immediate reject. */
#define MOD_ACTION_RETURN  (-1)
#define MOD_ACTION_REJECT  (-2)

/** Types of modcallable_t nodes
 *
 * Here are our basic types: modcallable, modgroup, and modsingle. For an
 * explanation of what they are all about, see doc/configurable_failover.rst
 */
typedef enum {
	MOD_NULL = 0,			//!< Modcallable type not set.
	MOD_SINGLE = 1,			//!< Module method.
	MOD_GROUP,			//!< Grouping section.
	MOD_LOAD_BALANCE,		//!< Load balance section.
	MOD_REDUNDANT_LOAD_BALANCE,	//!< Redundant load balance section.
	MOD_PARALLEL,			//!< execute statements in parallel
#ifdef WITH_UNLANG
	MOD_IF,				//!< Condition.
	MOD_ELSE,			//!< !Condition.
	MOD_ELSIF,			//!< !Condition && Condition.
	MOD_UPDATE,			//!< Update block.
	MOD_SWITCH,			//!< Switch section.
	MOD_CASE,			//!< Case section (within a #MOD_SWITCH).
	MOD_FOREACH,			//!< Foreach section.
	MOD_BREAK,			//!< Break statement (within a #MOD_FOREACH).
	MOD_RETURN,			//!< Return statement.
	MOD_MAP,			//!< Mapping section (like #MOD_UPDATE, but uses
					//!< values from a #map_proc_t call).
#endif
	MOD_POLICY,			//!< Policy section.
	MOD_XLAT,			//!< Bare xlat statement.
	MOD_RESUME,			//!< where to resume something
} mod_type_t;

#define MOD_NUM_TYPES (MOD_XLAT + 1)

typedef struct modcallable {
	struct modcallable	*parent;
	struct modcallable	*next;
	char const		*name;
	char const 		*debug_name;
	mod_type_t		type;
	int			actions[RLM_MODULE_NUMCODES];
} modcallable;


typedef enum {
	GROUPTYPE_SIMPLE = 0,
	GROUPTYPE_REDUNDANT,
	GROUPTYPE_COUNT
} grouptype_t;

typedef struct {
	modcallable		mc;		//!< Self.
	grouptype_t		grouptype;
	modcallable		*children;
	modcallable		*tail;		//!< of the children list.
	CONF_SECTION		*cs;
	int			num_children;

	vp_map_t		*map;		//!< #MOD_UPDATE, #MOD_MAP.
	vp_tmpl_t		*vpt;		//!< #MOD_SWITCH, #MOD_MAP.
	fr_cond_t		*cond;		//!< #MOD_IF, #MOD_ELSIF.

	map_proc_inst_t		*proc_inst;	//!< Instantiation data for #MOD_MAP.
	bool			done_pass2;
} modgroup;

typedef struct {
	modcallable		mc;
	module_instance_t	*modinst;
	char const		*name;
	void			*inst;
	module_method_t		method;
} modsingle;

typedef struct {
	modcallable mc;
	int exec;
	char *xlat_name;
} modxlat;

typedef struct {
	modsingle	single;
	fr_unlang_resume_t callback;
	void *inst;
	void *ctx;
} modresume;

extern char const *unlang_keyword[];

extern char const *const comp2str[];

/* Simple conversions: modsingle and modgroup are subclasses of modcallable,
 * so we often want to go back and forth between them. */
static inline modsingle *mod_callabletosingle(modcallable *p)
{
	rad_assert(p->type==MOD_SINGLE);
	return (modsingle *)p;
}
static inline modgroup *mod_callabletogroup(modcallable *p)
{
	rad_assert((p->type > MOD_SINGLE) && (p->type <= MOD_POLICY));

	return (modgroup *)p;
}
static inline modcallable *mod_singletocallable(modsingle *p)
{
	return (modcallable *)p;
}
static inline modcallable *mod_grouptocallable(modgroup *p)
{
	return (modcallable *)p;
}

static inline modxlat *mod_callabletoxlat(modcallable *p)
{
	rad_assert(p->type==MOD_XLAT);
	return (modxlat *)p;
}
static inline modcallable *mod_xlattocallable(modxlat *p)
{
	return (modcallable *)p;
}
static inline modresume *mod_callabletoresume(modcallable *p)
{
	rad_assert(p->type==MOD_RESUME);
	return (modresume *)p;
}
static inline modcallable *mod_resumetocallable(modresume *p)
{
	return (modcallable *)p;
}

#define UNLANG_STACK_MAX (64)

typedef struct unlang_foreach_t {
	vp_cursor_t cursor;
	VALUE_PAIR *vps;
	VALUE_PAIR *variable;
	int depth;
} unlang_foreach_t;

typedef struct unlang_redundant_t {
	modcallable *child;
	modcallable *found;
} unlang_redundant_t;

/*
 *	Don't call the modules recursively.  Instead, do them
 *	iteratively, and manage the call stack ourselves.
 */
typedef struct unlang_stack_entry_t {
	rlm_rcode_t result;
	int priority;
	mod_type_t unwind;		/* unwind to this one if it exists */
	bool do_next_sibling;
	bool was_if;
	bool if_taken;
	bool resume;
	bool top_frame;
	modcallable *c;

	union {
		unlang_foreach_t foreach;
		unlang_redundant_t redundant;
	};
} unlang_stack_entry_t;

typedef struct unlang_stack_t {
	int depth;
	unlang_stack_entry_t entry[UNLANG_STACK_MAX];
} unlang_stack_t;

#ifdef __cplusplus
}
#endif

#endif
