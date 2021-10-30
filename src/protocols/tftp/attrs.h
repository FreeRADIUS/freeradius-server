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
 * @file src/protocols/tftp/attrs.h
 * @brief TFTP protocol.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2021 The FreeRADIUS server project.
 * @copyright 2021 Network RADIUS SARL (legal@networkradius.com)
 */
RCSIDH(tftp_attrs_h, "$Id$")

#include <freeradius-devel/util/dict.h>

extern HIDDEN fr_dict_t const *dict_tftp;

extern HIDDEN fr_dict_attr_t const *attr_tftp_block;
extern HIDDEN fr_dict_attr_t const *attr_tftp_block_size;
extern HIDDEN fr_dict_attr_t const *attr_tftp_data;
extern HIDDEN fr_dict_attr_t const *attr_tftp_error_code;
extern HIDDEN fr_dict_attr_t const *attr_tftp_error_message;
extern HIDDEN fr_dict_attr_t const *attr_tftp_filename;
extern HIDDEN fr_dict_attr_t const *attr_tftp_opcode;
extern HIDDEN fr_dict_attr_t const *attr_tftp_mode;

extern HIDDEN fr_dict_attr_t const *attr_packet_type;
