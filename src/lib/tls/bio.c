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
 *
 * @file tls/bio.c
 * @brief Custom BIOs to pass to OpenSSL's functions
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#include <freeradius-devel/util/atexit.h>

#include "bio.h"

/** Holds the state of a talloc aggregation BIO
 *
 * Most of these fields are expected to change between uses of the BIO.
 *
 * BIOs do not have indexed extension structures like other structures in OpenSSL,
 * so we're forced to place all information in a structure, and populate it just
 * prior to a BIO being used.
 *
 * These BIOs are thread local to avoid conflicts or locking issues.
 */
typedef struct {
	BIO			*bio;		//!< Logging bio to write to.
	TALLOC_CTX		*ctx;		//!< Talloc ctx
	fr_dbuff_t		dbuff;		//!< Used to aggregate data.
	fr_dbuff_uctx_talloc_t	tctx;		//!< extra talloc information for the dbuff.
} fr_tls_bio_talloc_agg_t;

/** Template for the thread local request log BIOs
 */
static BIO_METHOD	*tls_bio_talloc_agg_meth;

/** Thread local aggregation BIO
 */
static _Thread_local	fr_tls_bio_talloc_agg_t		*tls_bio_talloc_agg;

/** Aggregates BIO_write() calls into a talloc'd buffer
 *
 * @param[in] bio	that was written to.
 * @param[in] in	data being written to BIO.
 * @param[in] len	Length of data being written.
 */
static int tls_log_bio_talloc_agg_write_cb(BIO *bio, char const *in, int len)
{
	fr_tls_bio_talloc_agg_t	*ab = talloc_get_type_abort(BIO_get_data(bio), fr_tls_bio_talloc_agg_t);

	fr_assert_msg(ab->dbuff.buff, "BIO not initialised");

	return fr_dbuff_in_memcpy_partial(&ab->dbuff, (uint8_t const *)in, len);
}

/** Aggregates BIO_puts() calls into a talloc'd buffer
 *
 * @param[in] bio	that was written to.
 * @param[in] in	data being written to BIO.
 */
static int tls_log_bio_talloc_agg_puts_cb(BIO *bio, char const *in)
{
	return tls_log_bio_talloc_agg_write_cb(bio, in, strlen(in));
}

/** Frees a logging bio and its underlying OpenSSL BIO *
 *
 */
static void _fr_tls_bio_talloc_agg_free(void *bio_talloc_agg)
{
	fr_tls_bio_talloc_agg_t	*our_bio_talloc_agg = talloc_get_type_abort(bio_talloc_agg, fr_tls_bio_talloc_agg_t);

	BIO_free(our_bio_talloc_agg->bio);
	our_bio_talloc_agg->bio = NULL;
	talloc_free(our_bio_talloc_agg);
}

/** Return a BIO which will aggregate data in an expandable talloc buffer
 *
 * @note Only one of these BIOs may be in use at a given time.
 *
 * @param[in] init	how much memory to allocate initially.
 * @param[in] max	the maximum amount of memory to allocate (0 for unlimited).
 * @return A thread local BIO to pass to OpenSSL logging functions.
 */
BIO *fr_tls_bio_talloc_agg(TALLOC_CTX *ctx, size_t init, size_t max)
{
	if (unlikely(!tls_bio_talloc_agg)) {
		fr_tls_bio_talloc_agg_t	*ab;

		MEM(ab = talloc(NULL, fr_tls_bio_talloc_agg_t));
		*ab = (fr_tls_bio_talloc_agg_t) {
			.bio = BIO_new(tls_bio_talloc_agg_meth),
			.ctx = ctx,
		};
		MEM(ab->bio);
		BIO_set_data(ab->bio, ab);	/* So we can retrieve the fr_tls_bio_talloc_agg_t in the callbacks */

		MEM(fr_dbuff_init_talloc(ctx, &ab->dbuff, &ab->tctx, init, max));
		fr_atexit_thread_local(tls_bio_talloc_agg, _fr_tls_bio_talloc_agg_free, ab);

		return ab->bio;
	}

	fr_assert_msg(!tls_bio_talloc_agg->dbuff.buff, "BIO not finialised");

	MEM(fr_dbuff_init_talloc(ctx, &tls_bio_talloc_agg->dbuff, &tls_bio_talloc_agg->tctx, init, max));

	return tls_bio_talloc_agg->bio;
}

/** Finalise a talloc aggregation buffer, returning the underlying talloc array holding the data
 *
 * @return
 *	- NULL if the aggregation buffer wasn't initialised.
 *	- A talloc_array holding the aggregated data.
 */
uint8_t *fr_tls_bio_talloc_agg_finalise(void)
{
	uint8_t *buff;

	if (unlikely(!tls_bio_talloc_agg)) return NULL;
	if (unlikely(!tls_bio_talloc_agg->dbuff.buff)) return NULL;

	fr_dbuff_trim_talloc(&tls_bio_talloc_agg->dbuff, SIZE_MAX);

	buff = tls_bio_talloc_agg->dbuff.buff;
	tls_bio_talloc_agg->dbuff.buff = NULL;
	return buff;
}

/** Finalise a talloc aggregation buffer, returning the underlying talloc array holding the data
 *
 * This variant adds an additional \0 byte, and sets the talloc chunk type to char.
 *
 * @return
 *	- NULL if the aggregation buffer wasn't initialised.
 *	- A talloc_array holding the aggregated data.
 */
char *fr_tls_bio_talloc_agg_finalise_bstr(void)
{
	uint8_t *buff;

	if (unlikely(!tls_bio_talloc_agg)) return NULL;
	if (unlikely(!tls_bio_talloc_agg->dbuff.buff)) return NULL;

	fr_dbuff_in_bytes(&tls_bio_talloc_agg->dbuff, 0x00);

	fr_dbuff_trim_talloc(&tls_bio_talloc_agg->dbuff, SIZE_MAX);

	buff = tls_bio_talloc_agg->dbuff.buff;
	tls_bio_talloc_agg->dbuff.buff = NULL;
	talloc_set_type(buff, char);

	return (char *)buff;
}

/** Discard any data in a talloc aggregation buffer
 *
 */
void fr_tls_bio_talloc_agg_clear(void)
{
	if (unlikely(!tls_bio_talloc_agg)) return;
	if (unlikely(!tls_bio_talloc_agg->dbuff.buff)) return;

	TALLOC_FREE(tls_bio_talloc_agg->dbuff.buff);
}

/** Initialise the BIO logging meths which are used to create thread local logging BIOs
 *
 */
int fr_tls_bio_init(void)
{
	/*
	 *	As per the boringSSL documentation
	 *
	 *	BIO_TYPE_START is the first user-allocated |BIO| type.
	 *	No pre-defined type, flag bits aside, may exceed this
	 *	value.
	 *
	 *	The low byte here defines the BIO ID, and the high byte
	 *	defines its capabilities.
	 */
	tls_bio_talloc_agg_meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "fr_tls_bio_talloc_agg");
	if (unlikely(!tls_bio_talloc_agg_meth)) return -1;

	BIO_meth_set_write(tls_bio_talloc_agg_meth, tls_log_bio_talloc_agg_write_cb);
	BIO_meth_set_puts(tls_bio_talloc_agg_meth, tls_log_bio_talloc_agg_puts_cb);

	return 0;
}

/** Free the global log method templates
 *
 */
void fr_tls_bio_free(void)
{
	if (tls_bio_talloc_agg_meth) {
		BIO_meth_free(tls_bio_talloc_agg_meth);
		tls_bio_talloc_agg_meth = NULL;
	}
}
#endif /* WITH_TLS */
