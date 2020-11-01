#pragma once
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

/**
 * $Id$
 *
 * @file modpriv.h
 * @brief Stuff needed by both module.c but should not be
 *	accessed from anywhere else.
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(modpriv_h, "$Id$")

#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/module.h>

#ifdef __cplusplus
extern "C" {
#endif
int			module_sibling_section_find(CONF_SECTION **out, CONF_SECTION *module, char const *name);

int			unlang_fixup_update(map_t *map, void *ctx);

#ifdef __cplusplus
}
#endif
