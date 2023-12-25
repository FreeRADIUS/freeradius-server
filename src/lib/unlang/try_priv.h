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

/**
 * $Id$
 *
 * @file unlang/try_priv.h
 * @brief Declaration for unlang try
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
#include "unlang_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unlang_group_t	group;
} unlang_try_t;

#ifdef __cplusplus
}
#endif
