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
#ifndef _FR_TLS_LOG_H
#define _FR_TLS_LOG_H

#ifdef WITH_TLS
/**
 * $Id$
 *
 * @file include/tls_log.h
 * @brief Prototypes for TLS logging functions
 *
 * @copyright 2017 The FreeRADIUS project
 */
RCSIDH(tls_log_h, "$Id$")

#include <stdbool.h>
#include <stdint.h>

/*
 *	tls/log.c
 */
int	tls_strerror_printf(bool drain_all, char const *msg, ...) CC_HINT(format (printf, 2, 3));
#endif
#endif	/* _FR_TLS_LOG_H */
