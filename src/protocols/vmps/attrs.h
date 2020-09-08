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
 * @file src/protocols/vqp/attrs.h
 * @brief VQP attributes
 *
 * @copyright 2019 The FreeRADIUS project
 */
RCSIDH(vqp_attrs_h, "$Id$")

#include <freeradius-devel/util/dict.h>

extern fr_dict_t const *dict_vmps;

extern fr_dict_attr_t const *attr_error_code;
extern fr_dict_attr_t const *attr_packet_type;
extern fr_dict_attr_t const *attr_sequence_number;
