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
 * @file unlang/finally.h
 * @brief Declarations for unlang timeouts
 *
 * @copyright 2025 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/server/request.h>

#ifdef __cplusplus
extern "C" {
#endif

int unlang_finally_push_instruction(request_t *request, void *instruction, fr_time_delta_t min_time, bool top_frame);

#ifdef __cplusplus
}
#endif
