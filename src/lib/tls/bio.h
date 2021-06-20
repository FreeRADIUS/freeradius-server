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

#include <openssl/bio.h>
#include <freeradius-devel/util/dbuff.h>

BIO		*fr_tls_bio_talloc_agg(TALLOC_CTX *ctx, size_t init, size_t max);

uint8_t		*fr_tls_bio_talloc_agg_finalise(void);
char		*fr_tls_bio_talloc_agg_finalise_bstr(void);

void		fr_tls_bio_talloc_agg_clear(void);

int		fr_tls_bio_init(void);

void		fr_tls_bio_free(void);

#endif /* WITH_TLS */
