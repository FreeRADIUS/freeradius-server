/* RFCNB Standard includes ... */
/*

   RFCNB Standard Includes

   Copyright (C) 1996, Richard Sharpe
   Copyright 2006 The FreeRADIUS server project

   One day we will conditionalize these on OS types ...

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <freeradius-devel/ident.h>
RCSIDH(std_includes_h, "$Id$")

#include "config.h"

#define BOOL int
typedef short int16;

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

/* Pick up define for INADDR_NONE */

#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif
