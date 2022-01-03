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
#ifdef WITH_TLS
/**
 * $Id$
 *
 * @file lib/tls/bio.h
 * @brief Custom BIOs to pass to OpenSSL's functions
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(bio_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/bio.h>
#include <freeradius-devel/util/dbuff.h>

typedef struct fr_tls_bio_dbuff_s fr_tls_bio_dbuff_t;

uint8_t		*fr_tls_bio_dbuff_finalise(fr_tls_bio_dbuff_t *bd);

char		*fr_tls_bio_dbuff_finalise_bstr(fr_tls_bio_dbuff_t *bd);

fr_dbuff_t	*fr_tls_bio_dbuff_out(fr_tls_bio_dbuff_t *bd);

fr_dbuff_t	*fr_tls_bio_dbuff_in(fr_tls_bio_dbuff_t *bd);

void		fr_tls_bio_dbuff_reset(fr_tls_bio_dbuff_t *bd);

BIO		*fr_tls_bio_dbuff_alloc(fr_tls_bio_dbuff_t **out, TALLOC_CTX *bio_ctx, TALLOC_CTX *buff_ctx,
					 size_t init, size_t max, bool free_buff);

uint8_t		*fr_tls_bio_dbuff_thread_local_finalise(void);

char		*fr_tls_bio_dbuff_thread_local_finalise_bstr(void);

void		fr_tls_bio_dbuff_thread_local_clear(void);

BIO		*fr_tls_bio_dbuff_thread_local(TALLOC_CTX *ctx, size_t init, size_t max);

int		fr_tls_bio_init(void);

void		fr_tls_bio_free(void);

#endif /* WITH_TLS */
