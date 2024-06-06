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
 * @file lib/bio/null.c
 * @brief BIO NULL handlers
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/null.h>

/** Always return 0 on read.
 *
 */
ssize_t fr_bio_null_read(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void *buffer, UNUSED size_t size)
{
	return 0;
}

/** Always return 0 on write.
 *
 */
ssize_t fr_bio_null_write(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, UNUSED size_t size)
{
	return 0;
}

/** Always return error on read.
 *
 */
ssize_t fr_bio_fail_read(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void *buffer, UNUSED size_t size)
{
	fr_strerror_const("BIO is not readable");
	return fr_bio_error(GENERIC);
}

/** Always return 0 on write.
 *
 */
ssize_t fr_bio_fail_write(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, UNUSED size_t size)
{
	fr_strerror_const("BIO is not writeable");
	return fr_bio_error(GENERIC);
}
