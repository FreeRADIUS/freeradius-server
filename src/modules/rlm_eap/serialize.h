/*
 * serialize.h    Header file containing the interfaces for EAP serialization.
 *
 * Version:     $Id$
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
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 * Copyright 2003  Alan DeKok <aland@freeradius.org>
 * Copyright 2006  The FreeRADIUS server project
 */
#ifndef _EAP_SERIALIZE_H
#define _EAP_SERIALIZE_H

int serialize_fixed(UNUSED void *instance, REQUEST *fake, eap_handler_t *handler, size_t len);
int deserialize_fixed(UNUSED void *instance, REQUEST *fake, eap_handler_t *handler, size_t len);
int serialize_noop(UNUSED void *instance, REQUEST *fake, eap_handler_t *handler, size_t len);
#endif
