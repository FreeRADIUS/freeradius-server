#pragma once
/** Structures and prototypes for our local MD4 implementation
 *
 * @note license is LGPL, but largely derived from a public domain source.
 *
 * @file src/lib/util/md4.h
 * @brief Structures and declarations for md4.
 */
RCSIDH(md4_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <inttypes.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifndef MD4_DIGEST_LENGTH
#  define MD4_DIGEST_LENGTH 16
#endif

typedef void fr_md4_ctx_t;

/* md4.c */

/** Reset the ctx to allow reuse
 *
 * @param[in] ctx	To reuse.
 */
typedef		void (*fr_md4_ctx_reset_t)(fr_md4_ctx_t *ctx);
extern		fr_md4_ctx_reset_t	fr_md4_ctx_reset;

/** Copy the contents of a ctx
 *
 * @param[in] dst	Where to copy the context to.
 * @param[in] src	Where to copy the context from.
 */
typedef		void (*fr_md4_ctx_copy_t)(fr_md4_ctx_t *dst, fr_md4_ctx_t const *src);
extern		fr_md4_ctx_copy_t	fr_md4_ctx_copy;

/** Allocation function for MD4 digest context
 *
 * @return
 *	- An MD4 ctx.
 *	- NULL if out of memory.
 */
typedef		fr_md4_ctx_t *(*fr_md4_ctx_alloc_t)(void);
extern		fr_md4_ctx_alloc_t	fr_md4_ctx_alloc;

/** Free function for MD4 digest ctx
 *
 * @param[in] ctx	MD4 ctx to free.  If the shared ctx is passed in
 *			then the ctx is reset but not freed.
 */
typedef		void (*fr_md4_ctx_free_t)(fr_md4_ctx_t **ctx);
extern		fr_md4_ctx_free_t	fr_md4_ctx_free;


/** Ingest plaintext into the digest
 *
 * @param[in] ctx	To ingest data into.
 * @param[in] in	Data to ingest.
 * @param[in] inlen	Length of data to ingest.
 */
typedef		void (*fr_md4_update_t)(fr_md4_ctx_t *ctx, uint8_t const *in, size_t inlen);
extern		fr_md4_update_t		fr_md4_update;

/** Finalise the ctx, producing the digest
 *
 * @param[out] out	The MD4 digest.
 * @param[in] ctx	To finalise.
 */
typedef		void (*fr_md4_final_t)(uint8_t out[static MD4_DIGEST_LENGTH], fr_md4_ctx_t *ctx);
extern		fr_md4_final_t		fr_md4_final;

/** Perform a single digest operation on a single input buffer
 *
 */
void		fr_md4_calc(uint8_t out[static MD4_DIGEST_LENGTH], uint8_t const *in, size_t inlen);

/** Allocate an md4 context from a free list
 *
 */
fr_md4_ctx_t	*fr_md4_ctx_alloc_from_list(void);

/** Release an md4 context back to a free list
 *
 */
void		fr_md4_ctx_free_from_list(fr_md4_ctx_t **ctx);
#ifdef __cplusplus
}
#endif
