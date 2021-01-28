#pragma once
/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Functions to get randomness
 *
 * @file src/lib/util/rand.h
 *
 * @copyright 1999-2017 The FreeRADIUS server project
 */
RCSIDH(rand_h, "$Id$")

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* random numbers in isaac.c */
/* context of random number generator */
typedef struct {
	uint32_t randcnt;
	uint32_t randrsl[256];
	uint32_t randmem[256];
	uint32_t randa;
	uint32_t randb;
	uint32_t randc;
} fr_randctx;

/** Smaller fast random number generator.
 *
 *  From George Marsaglia's Multiply with Carry (MWC) algorithm.
 *
 *  The two seeds here should be initialized by calling fr_rand(),
 *  or for tests, via some static values.
 */
typedef struct {
	uint32_t a, b;
} fr_fast_rand_t;

void		fr_isaac(fr_randctx *ctx);
void		fr_rand_init(fr_randctx *ctx, int flag);
uint32_t	fr_rand(void);	/* like rand(), but better. */
void		fr_rand_buffer(void *start, size_t length) CC_HINT(nonnull);
void		fr_rand_str(uint8_t *out, size_t len, char class);
void		fr_rand_seed(void const *, size_t ); /* seed the random pool */
uint32_t	fr_fast_rand(fr_fast_rand_t *ctx);

#ifdef __cplusplus
}
#endif
