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
#ifndef VMPS_H
#define VMPS_H
/*
 * $Id$
 *
 * @file vmps.h
 * @brief Routines to handle VMPS sockets.
 *
 * @copyright 2013 The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSIDH(vmps_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

int vqp_socket_recv(rad_listen_t *listener);
int vqp_socket_send(rad_listen_t *listener, REQUEST *request);
int vqp_socket_encode(UNUSED rad_listen_t *listener, REQUEST *request);
int vqp_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request);
int vmps_process(REQUEST *request);

#ifdef __cplusplus
}
#endif

#endif /* VMPS_H */
