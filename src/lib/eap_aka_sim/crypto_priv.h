#pragma once
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
 * @file src/lib/eap_aka_sim/crypto_priv.h
 * @brief EAP-SIM/EAP-AKA Private crypto functions
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <sys/types.h>
#include <freeradius-devel/util/token.h>

#ifdef __cplusplus
extern "C" {
#endif

void _evp_cipher_ctx_free_on_exit(void *arg);	/* Used as a handle to disable destructors on fr_aka_sim_free */

EVP_CIPHER_CTX *aka_sim_crypto_cipher_ctx(void);

#ifdef __cplusplus
}
#endif
