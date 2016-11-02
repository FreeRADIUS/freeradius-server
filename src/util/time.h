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
#ifndef _FR_TIME_H
#define _FR_TIME_H
/**
 * $Id$
 *
 * @file util/time.h
 * @brief Simple time functions
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(time_h, "$Id$")

/*
 *	For sys/time.h and time.h
 */
#include <freeradius-devel/missing.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  A typedef for "server local" time.  This is the time in
 *  nanoseconds since the application started.
 */
typedef uint64_t fr_time_t;

int fr_time_start(void);
fr_time_t fr_time(void);
void fr_time_to_timeval(struct timeval *tv, fr_time_t when);


#ifdef __cplusplus
}
#endif

#endif /* _FR_TIME_H */
