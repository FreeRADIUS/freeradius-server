#pragma once
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
 * @file src/protocols/bfd/attrs.h
 * @brief BFD attributes
 *
 * @copyright 20223 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(radius_attrs_h, "$Id$")

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/bfd/bfd.h>

extern HIDDEN fr_dict_t const *dict_freeradius;
extern HIDDEN fr_dict_t const *dict_bfd;

extern HIDDEN fr_dict_attr_t const *attr_packet_type;
extern HIDDEN fr_dict_attr_t const *attr_bfd_packet;
extern HIDDEN fr_dict_attr_t const *attr_bfd_additional_data;
