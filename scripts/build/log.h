#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file build/log.h
 * @brief Wrap make's logging facilities in C functions
 *
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <string.h>
#include <stdarg.h>

void _make_log(char const *log_keyword, char const *file, int line, char const *fmt, ...) __attribute__((format (printf, 4, 5)));

#define make_error(_fmt, ...)		_make_log("error", __FILE__, __LINE__, _fmt, ## __VA_ARGS__)
#define make_warning(_fmt, ...)		_make_log("warning", __FILE__, __LINE__, _fmt, ## __VA_ARGS__)
#define make_info(_fmt, ...)		_make_log("info", __FILE__, __LINE__, _fmt, ## __VA_ARGS__)

void _make_vlog(char const *log_keyword, char const *file, int line, char const *fmt, va_list ap) __attribute__((format (printf, 4, 0)));

#define make_verror(_fmt, _ap)		_make_vlog("error", __FILE__, __LINE__, _fmt, _ap)
#define make_vwarning(_fmt, _ap)	_make_vlog("warning", __FILE__, __LINE__, _fmt, _ap)
#define make_vinfo(_fmt, _ap)		_make_vlog("info", __FILE__, __LINE__, _fmt, _ap)

#define ERROR(_fmt, ...)		make_error(_fmt "\n", ## __VA_ARGS__)
#define WARN(_fmt, ...)			make_warn(_fmt "\n", ## __VA_ARGS__)
#define INFO(_fmt, ...)			make_info(_fmt "\n", ## __VA_ARGS__)
#define DEBUG(_fmt, ...)		make_info(_fmt "\n", ## __VA_ARGS__)
