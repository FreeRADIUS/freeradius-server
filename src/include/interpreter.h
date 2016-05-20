#ifndef _FR_INTERPRETER_H
#define _FR_INTERPRETER_H

/* interpreter.h: the outside interface to interpreter
 *
 * Version: $Id$ */

#include <freeradius-devel/conffile.h> /* Need CONF_* definitions */
#include <freeradius-devel/modcall.h>
#include <freeradius-devel/map_proc.h>
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
	MOD_XLAT			//!< Bare xlat statement.
} mod_type_t;

#define MOD_NUM_TYPES (MOD_XLAT + 1)

struct modcallable {
	modcallable		*parent;
	struct modcallable	*next;
	char const		*name;
	char const 		*debug_name;
	mod_type_t		type;
	rlm_components_t	method;
	int			actions[RLM_MODULE_NUMCODES];
};


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

	vp_map_t		*map;		//!< #MOD_UPDATE, #MOD_MAP.
	vp_tmpl_t		*vpt;		//!< #MOD_SWITCH, #MOD_MAP.
	fr_cond_t		*cond;		//!< #MOD_IF, #MOD_ELSIF.

	map_proc_inst_t		*proc_inst;	//!< Instantiation data for #MOD_MAP.
	bool			done_pass2;
} modgroup;

typedef struct {
	modcallable mc;
	module_instance_t *modinst;
} modsingle;

typedef struct {
	modcallable mc;
	int exec;
	char *xlat_name;
} modxlat;

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

rlm_rcode_t unlang_interpret(REQUEST *request, modcallable *c, rlm_components_t component);

#ifdef __cplusplus
}
#endif

#endif
