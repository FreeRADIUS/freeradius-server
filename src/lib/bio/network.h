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
 * @file lib/bio/network.h
 * @brief  BIO patricia trie filtering handlers
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_network_h, "$Id$")

#include <freeradius-devel/util/inet.h>

fr_bio_t *fr_bio_network_alloc(TALLOC_CTX *ctx, fr_ipaddr_t const *allow, fr_ipaddr_t const *deny,
			       fr_bio_read_t discard, fr_bio_t *next) CC_HINT(nonnull(1,2,5));
 
fr_trie_t *fr_bio_network_trie_alloc(TALLOC_CTX *ctx, int af, fr_ipaddr_t const *allow, fr_ipaddr_t const *deny);

/*
 *	IP address lookups return one of these two magic pointers.
 *
 *	NULL means "nothing matches", which should also be interpreted as "deny".
 *
 *	The difference between "NULL" and "deny" is that NULL is an IP address which was never inserted into
 *	the trie.  Whereas "deny" means that there is a parent "allow" range, and we are carving out a "deny"
 *	in the middle of that range.
 */
#define FR_BIO_NETWORK_ALLOW ((void *) (-1))
#define FR_BIO_NETWORK_DENY ((void *) (-2))
