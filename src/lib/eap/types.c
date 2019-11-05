/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file lib/eap/types.h
 * @brief EAP type resolution
 *
 * @copyright 2019 The FreeRADIUS server project
 */
#include "attrs.h"
#include "types.h"

/** Return an EAP-Type for a particular name
 *
 * Converts a name into an IANA EAP type.
 *
 * @param name to convert.
 * @return
 *	- IANA EAP type.
 *	- #FR_EAP_METHOD_INVALID if the name doesn't match any known types.
 */
eap_type_t eap_name2type(char const *name)
{
	fr_dict_enum_t	*dv;

	dv = fr_dict_enum_by_name(attr_eap_type, name, -1);
	if (!dv) return FR_EAP_METHOD_INVALID;

	if (dv->value->vb_uint32 >= FR_EAP_METHOD_MAX) return FR_EAP_METHOD_INVALID;

	return dv->value->vb_uint32;
}

/** Return an EAP-name for a particular type
 *
 * Resolve
 */
char const *eap_type2name(eap_type_t method)
{
	fr_dict_enum_t	*dv;

	dv = fr_dict_enum_by_value(attr_eap_type, fr_box_uint32(method));
	if (dv) return dv->name;

	return "unknown";
}
