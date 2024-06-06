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
 * @file lib/bio/pipe.h
 * @brief BIO pipe handlers.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_pipe_h, "$Id$")

typedef struct {
	fr_bio_callback_t      	readable;
	fr_bio_callback_t      	writeable;
} fr_bio_pipe_cb_funcs_t;

fr_bio_t	*fr_bio_pipe_alloc(TALLOC_CTX *ctx, fr_bio_pipe_cb_funcs_t *cb, size_t buffer_size) CC_HINT(nonnull);
