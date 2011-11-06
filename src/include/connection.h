#ifndef FR_CONNECTION_H
#define FR_CONNECTION_H
/**
 * @file connection.h
 * @brief	Structures, prototypes and global variables
 *		for server connection pools.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 1999,2000,2002,2003,2004,2005,2006,2007,2008  The FreeRADIUS server project
 *
 */

#include <freeradius-devel/ident.h>
RCSIDH(connection_h, "$Id$")

#include <freeradius-devel/conffile.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_connection_pool_t fr_connection_pool_t;

typedef void *(*fr_connection_create_t)(void *ctx);
typedef int (*fr_connection_alive_t)(void *ctx, void *connection);
typedef int (*fr_connection_delete_t)(void *ctx, void *connection);

fr_connection_pool_t *fr_connection_pool_init(CONF_SECTION *cs,
					      void *ctx,
					      fr_connection_create_t c,
					      fr_connection_alive_t a,
					      fr_connection_delete_t d);
void fr_connection_pool_delete(fr_connection_pool_t *fc);

int fr_connection_check(fr_connection_pool_t *fc, void *conn);
void *fr_connection_get(fr_connection_pool_t *fc);
void fr_connection_release(fr_connection_pool_t *fc, void *conn);
void *fr_connection_reconnect(fr_connection_pool_t *fc, void *conn);
int fr_connection_add(fr_connection_pool_t *fc, void *conn);
int fr_connection_del(fr_connection_pool_t *fc, void *conn);

#ifdef __cplusplus
}
#endif

#endif /* FR_CONNECTION_H*/
