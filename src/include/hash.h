#ifndef LRAD_HASH_H
#define LRAD_HASH_H

/*
 * hash.h	Structures and prototypes
 *		for fast hashing.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2005,2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSIDH(hash_h, "$Id$")

/*
 *	Fast hash, which isn't too bad.  Don't use for cryptography,
 *	just for hashing internal data.
 */
uint32_t lrad_hash(const void *, size_t);
uint32_t lrad_hash_update(const void *data, size_t size, uint32_t hash);
uint32_t lrad_hash_string(const char *p);

/*
 *	If you need fewer than 32-bits of hash, use this macro to get
 *	the number of bits in the hash you need.  The upper bits of the
 *	hash will be set to zero.
 */
uint32_t lrad_hash_fold(uint32_t hash, int bits);

typedef struct lrad_hash_table_t lrad_hash_table_t;
typedef void (*lrad_hash_table_free_t)(void *);
typedef uint32_t (*lrad_hash_table_hash_t)(const void *);
typedef int (*lrad_hash_table_cmp_t)(const void *, const void *);
typedef int (*lrad_hash_table_walk_t)(void * /* ctx */, void * /* data */);

lrad_hash_table_t *lrad_hash_table_create(lrad_hash_table_hash_t hashNode,
					  lrad_hash_table_cmp_t cmpNode,
					  lrad_hash_table_free_t freeNode);
void		lrad_hash_table_free(lrad_hash_table_t *ht);
int		lrad_hash_table_insert(lrad_hash_table_t *ht, void *data);
int		lrad_hash_table_delete(lrad_hash_table_t *ht, const void *data);
void		*lrad_hash_table_yank(lrad_hash_table_t *ht, const void *data);
int		lrad_hash_table_replace(lrad_hash_table_t *ht, void *data);
void		*lrad_hash_table_finddata(lrad_hash_table_t *ht, const void *data);
int		lrad_hash_table_num_elements(lrad_hash_table_t *ht);
int		lrad_hash_table_walk(lrad_hash_table_t *ht,
				     lrad_hash_table_walk_t callback,
				     void *ctx);
#endif /* LRAD_HASH_H */
