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
#ifndef _FR_MODCALL_H
#define _FR_MODCALL_H
/**
 * $Id$
 *
 * @file include/modcall.h
 * @brief API to the module-calling tree.
 *
 * Functions to build the tree from the config file, and to call it by
 * feeding it REQUESTs.
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(modcall_h, "$Id$")

#include <freeradius-devel/conffile.h> /* Need CONF_* definitions */
#include <freeradius-devel/modules.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	For each authorize/authtype/etc, we have an ordered
 *	tree of instances to call.  This data structure keeps track
 *	of that order.
 */
typedef struct modcallable modcallable;

int modcall_fixup_update(vp_map_t *map, void *ctx);

/* Parse a module-method's config section (e.g. authorize{}) into a tree that
 * may be called with modcall() */
modcallable *modcall_compile_section(modcallable *parent,
			     rlm_components_t component, CONF_SECTION *cs);

void modcall_debug(modcallable *mc, int depth);

int modcall_pass2_condition(fr_cond_t *c);

#ifdef __cplusplus
}
#endif
#endif /* _FR_MODCALL_H */
