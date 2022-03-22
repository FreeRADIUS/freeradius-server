#pragma once
/** Structures and prototypes for our local MD5 implementation
 *
 * @note license is LGPL, but largely derived from a public domain source.
 *
 * @file src/lib/util/md5.h
 * @brief Structures and declarations for md5.
 */
RCSIDH(md5_h, "$Id$")

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

#ifndef MD5_DIGEST_LENGTH
#  define MD5_DIGEST_LENGTH 16
#endif

typedef void fr_md5_ctx_t;

/* md5.c */

/** Reset the ctx to allow reuse
 *
 * @param[in] ctx	To reuse.
 */
typedef		void (*fr_md5_ctx_reset_t)(fr_md5_ctx_t *ctx);
extern		fr_md5_ctx_reset_t	fr_md5_ctx_reset;

/** Copy the contents of a ctx
 *
 * @param[in] dst	Where to copy the context to.
 * @param[in] src	Where to copy the context from.
 */
typedef		void (*fr_md5_ctx_copy_t)(fr_md5_ctx_t *dst, fr_md5_ctx_t const *src);
extern		fr_md5_ctx_copy_t	fr_md5_ctx_copy;

/** Allocation function for MD5 digest context
 *
 * @return
 *	- An MD5 ctx.
 *	- NULL if out of memory.
 */
typedef		fr_md5_ctx_t *(*fr_md5_ctx_alloc_t)(void);
extern		fr_md5_ctx_alloc_t	fr_md5_ctx_alloc;

/** Free function for MD5 digest ctx
 *
 * @param[in] ctx	MD5 ctx to free.  If the shared ctx is passed in
 *			then the ctx is reset but not freed.
 */
typedef		void (*fr_md5_ctx_free_t)(fr_md5_ctx_t **ctx);
extern		fr_md5_ctx_free_t	fr_md5_ctx_free;

/** Ingest plaintext into the digest
 *
 * @param[in] ctx	To ingest data into.
 * @param[in] in	Data to ingest.
 * @param[in] inlen	Length of data to ingest.
 */
typedef		void (*fr_md5_update_t)(fr_md5_ctx_t *ctx, uint8_t const *in, size_t inlen);
extern		fr_md5_update_t		fr_md5_update;

/** Finalise the ctx, producing the digest
 *
 * @param[out] out	The MD5 digest.
 * @param[in] ctx	To finalise.
 */
typedef		void (*fr_md5_final_t)(uint8_t out[static MD5_DIGEST_LENGTH], fr_md5_ctx_t *ctx);
extern		fr_md5_final_t		fr_md5_final;

/** Perform a single digest operation on a single input buffer
 *
 */
void		fr_md5_calc(uint8_t out[static MD5_DIGEST_LENGTH], uint8_t const *in, size_t inlen);

/** Allocate an MD5 context from a free list
 *
 */
fr_md5_ctx_t	*fr_md5_ctx_alloc_from_list(void);

/** Release an MD5 context back to a free list
 *
 */
void		fr_md5_ctx_free_from_list(fr_md5_ctx_t **ctx);

/* hmac.c */
int		fr_hmac_md5(uint8_t digest[static MD5_DIGEST_LENGTH], uint8_t const *in, size_t inlen,
			    uint8_t const *key, size_t key_len);
#ifdef __cplusplus
}
#endif
