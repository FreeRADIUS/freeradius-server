#pragma once
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

/** Master include file to access all functions and structures in the library
 *
 * In the vast majority of cases it isn't necessary to include this file, and
 * individual headers should be used instead.
 *
 * @file src/lib/util/base.h
 *
 * @copyright 1999-2018 The FreeRADIUS server project
 */

#include <freeradius-devel/build.h>
RCSIDH(libradius_h, "$Id$")

/*
 *	Sanity checks
 */
#ifdef SIZEOF_UNSIGNED_INT
#  if SIZEOF_UNSIGNED_INT != 4
#    error FATAL: sizeof(unsigned int) != 4
#  endif
#endif

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/radius/defs.h>
#include <freeradius-devel/radius/radius.h>

#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/fifo.h>
#include <freeradius-devel/util/filters.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/inet.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/md4.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/packet.h>
#include <freeradius-devel/util/pair_cursor.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/rbtree.h>
#include <freeradius-devel/util/regex.h>
#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/socket.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/thread_local.h>
#include <freeradius-devel/util/token.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/version.h>
