#pragma once
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

/** Common things to initialize the fuzzers.
 *
 * @file src/fuzzer/common.h
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(fuzzer_common_h, "$Id$")

#include <freeradius-devel/util/dl.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/io/test_point.h>

extern TALLOC_CTX		*autofree;
extern fr_dict_t		*dict;
extern fr_dict_attr_t const	*root_da;

extern fr_dict_protocol_t	*dl_proto;

int	fuzzer_common_init(int *argc, char ***argv, bool load_proto);
