/*
 *   This program is is free software; you can redistribute it and/or modify
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
 * @file src/lib/server/crypt.c
 * @brief A thread safe crypt wrapper.
 *
 * @copyright 2000-2006,2016  The FreeRADIUS server project.
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>

#ifdef HAVE_CRYPT_H
#  include <crypt.h>
#endif

#include <pthread.h>
#ifndef HAVE_CRYPT_R
static pthread_mutex_t fr_crypt_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/** Performs a crypt password check in an thread-safe way.
 *
 * @param password The user's plaintext password.
 * @param reference_crypt The 'known good' crypt the password
 *	is being compared to.
 * @return
 *	- 0 crypt output matched reference crypt.
 *	- 1 crypt output did not match reference crypt.
 *	- -1 crypt failed.
 */
int fr_crypt_check(char const *password, char const *reference_crypt)
{
	char *crypt_out;
	int cmp = 0;

#ifdef HAVE_CRYPT_R
	struct crypt_data crypt_data;

	crypt_data.initialized = 0;

	crypt_out = crypt_r(password, reference_crypt, &crypt_data);
	if (crypt_out) cmp = strcmp(reference_crypt, crypt_out);
#else
	/*
	 *	Ensure we're thread-safe, as crypt() isn't.
	 */
	pthread_mutex_lock(&fr_crypt_mutex);
	crypt_out = crypt(password, reference_crypt);

	/*
	 *	Got something, check it within the lock.  This is
	 *	faster than copying it to a local buffer, and the
	 *	time spent within the lock is critical.
	 */
	if (crypt_out) cmp = strcmp(reference_crypt, crypt_out);
	pthread_mutex_unlock(&fr_crypt_mutex);
#endif

	/*
	 *	Error.
	 */
	if (!crypt_out) return -1;

	/*
	 *	OK, return OK.
	 */
	if (cmp == 0) return 0;

	/*
	 *	Comparison failed.
	 */
	return 1;
}
