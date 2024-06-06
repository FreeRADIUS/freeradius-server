#pragma once
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

/**
 * $Id$
 * @file lib/bio/null.h
 * @brief BIO null handlers.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_null_h, "$Id$")

ssize_t fr_bio_null_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size);
ssize_t fr_bio_null_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size);

ssize_t fr_bio_fail_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size);
ssize_t fr_bio_fail_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size);
