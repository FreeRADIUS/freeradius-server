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

/** Holds the state of a talloc aggregation 'write' BIO
 *
 * With these BIOs OpenSSL is the producer, and we're the consumer.
 */
struct fr_tls_bio_dbuff_s {
	BIO			*bio;		//!< Logging bio to write to.
	fr_dbuff_t		dbuff_in;	//!< dbuff used to write data to our talloced buffer.
	fr_dbuff_t		dbuff_out;	//!< dbuff used to read data from our talloced buffer.
	fr_dbuff_uctx_talloc_t	tctx;		//!< extra talloc information for the dbuff.
	bool			free_buff;	//!< Free the talloced buffer when this structure is freed.
};

/** Template for the thread local request log BIOs
 */
static BIO_METHOD	*tls_bio_talloc_meth;

/** Thread local aggregation BIO
 */
static _Thread_local	fr_tls_bio_dbuff_t		*tls_bio_talloc_agg;

/** Aggregates BIO_write() calls into a talloc'd buffer
 *
 * @param[in] bio	that was written to.
 * @param[in] in	data being written to BIO.
 * @param[in] len	Length of data being written.
 */
static int _tls_bio_talloc_write_cb(BIO *bio, char const *in, int len)
{
	fr_tls_bio_dbuff_t	*bd = talloc_get_type_abort(BIO_get_data(bio), fr_tls_bio_dbuff_t);

	fr_assert_msg(bd->dbuff_in.buff, "BIO not initialised");

	/*
	 *	Shift out any data which has been read
	 *	since we were last called.
	 */
	fr_dbuff_shift(&bd->dbuff_in, fr_dbuff_used(&bd->dbuff_out));

	return fr_dbuff_in_memcpy_partial(&bd->dbuff_in, (uint8_t const *)in, (size_t)len);
}

/** Aggregates BIO_puts() calls into a talloc'd buffer
 *
 * @param[in] bio	that was written to.
 * @param[in] in	data being written to BIO.
 */
static int _tls_bio_talloc_puts_cb(BIO *bio, char const *in)
{
	return _tls_bio_talloc_write_cb(bio, in, strlen(in));
}

/** Serves BIO_read() from a talloced buffer
 *
 * @param[in] bio	performing the read operation.
 * @param[out] buf	to write data to.
 * @param[in] size	of data to write (maximum).
 * @return The amount of data written.
 */
static int _tls_bio_talloc_read_cb(BIO *bio, char *buf, int size)
{
	fr_tls_bio_dbuff_t	*bd = talloc_get_type_abort(BIO_get_data(bio), fr_tls_bio_dbuff_t);
	size_t			to_copy;
	ssize_t			slen;

	fr_assert_msg(bd->dbuff_out.buff, "BIO not initialised");

	to_copy = fr_dbuff_remaining(&bd->dbuff_out);
	if (to_copy > (size_t)size) to_copy = (size_t)size;

	slen = fr_dbuff_out_memcpy((uint8_t *)buf, &bd->dbuff_out, to_copy);
	if (!fr_cond_assert(slen >= 0)) {	/* Shouldn't happen */
		buf[0] = '\0';
		return (int)slen;
	}

	fr_dbuff_shift(&bd->dbuff_in, (size_t)slen);	/* Shift contents */

	return (int)slen;
}

/** Serves BIO_gets() from a talloced buffer
 *
 * Writes all data up to size, or up to and including the next \n to
 * the provided buffer.
 *
 * @param[in] bio	performing the gets operation.
 * @param[out] buf	to write data to.
 * @param[in] size	of data to write (maximum).
 * @return The amount of data written.
 */
static int _tls_bio_talloc_gets_cb(BIO *bio, char *buf, int size)
{
	fr_tls_bio_dbuff_t	*bd = talloc_get_type_abort(BIO_get_data(bio), fr_tls_bio_dbuff_t);
	size_t			to_copy;
	uint8_t			*p;
	ssize_t			slen;

	fr_assert_msg(bd->dbuff_out.buff, "BIO not initialised");

	/*
	 *	Deal with stupid corner case
	 */
	if (unlikely(size == 1)) {
		buf[0] = '\0';
		return 0;
	} else if (unlikely(size == 0)) {
		return 0;
	}

	/*
	 *	Copy up to the next line, or the end of the buffer
	 */
	p = memchr(fr_dbuff_current(&bd->dbuff_out), '\n', fr_dbuff_remaining(&bd->dbuff_out));
	if (!p) {
		to_copy = fr_dbuff_remaining(&bd->dbuff_out);
	} else {
		to_copy = (p - fr_dbuff_current(&bd->dbuff_out)) + 1;	/* Preserve the \n as per BIO_read() man page */
	}

	if (to_copy >= (size_t)size) to_copy = (size_t)size - 1; /* Space for \0 */

	slen = fr_dbuff_out_memcpy((uint8_t *)buf, &bd->dbuff_out, to_copy);
	if (!fr_cond_assert(slen > 0)) {	/* Shouldn't happen */
		buf[0] = '\0';
		return (int)slen;
	}

	buf[to_copy] = '\0';
	fr_dbuff_shift(&bd->dbuff_in, (size_t)slen);	/* Shift contents */

	return (int)to_copy;
}

/** Finalise a talloc aggregation buffer, returning the underlying talloc array holding the data
 *
 * @return
 *	- NULL if the aggregation buffer wasn't initialised.
 *	- A talloc_array holding the aggregated data.
 */
uint8_t *fr_tls_bio_dbuff_finalise(fr_tls_bio_dbuff_t *bd)
{
	uint8_t *buff;

	if (unlikely(!bd)) return NULL;
	if (unlikely(!bd->dbuff_in.buff)) return NULL;

	fr_dbuff_trim_talloc(&bd->dbuff_in, SIZE_MAX);

	buff = bd->dbuff_in.buff;
	bd->dbuff_in.buff = NULL;
	bd->dbuff_out.buff = NULL;
	return buff;
}

/** Finalise a talloc aggregation buffer, returning the underlying talloc array holding the data
 *
 * @return
 *	- NULL if the aggregation buffer wasn't initialised.
 *	- A talloc_array holding the aggregated data.
 */
char *fr_tls_bio_dbuff_finalise_bstr(fr_tls_bio_dbuff_t *bd)
{
	uint8_t *buff;

	if (unlikely(!bd)) return NULL;
	if (unlikely(!bd->dbuff_in.buff)) return NULL;

	fr_dbuff_in_bytes(&bd->dbuff_in, 0x00);
	fr_dbuff_trim_talloc(&bd->dbuff_in, SIZE_MAX);

	buff = bd->dbuff_in.buff;
	bd->dbuff_in.buff = NULL;
	bd->dbuff_out.buff = NULL;
	talloc_set_type(buff, char);

	return (char *)buff;
}

/* Reset pointer positions for in/out
 *
 * Leaves the underlying buffer intact to avoid useless free/malloc.
 */
void fr_tls_bio_dbuff_reset(fr_tls_bio_dbuff_t *bd)
{
	fr_dbuff_set_to_start(&bd->dbuff_in);
}

/** Free the underlying BIO, and the buffer if it wasn't finalised
 *
 */
static int _fr_tls_bio_dbuff_free(fr_tls_bio_dbuff_t *bd)
{
	BIO_free(bd->bio);
	if (bd->free_buff) fr_dbuff_free_talloc(&bd->dbuff_out);

	return 0;
}

/** Return the output dbuff
 *
 */
fr_dbuff_t *fr_tls_bio_dbuff_out(fr_tls_bio_dbuff_t *bd)
{
	return &bd->dbuff_out;
}

/** Return the input dbuff
 *
 */
fr_dbuff_t *fr_tls_bio_dbuff_in(fr_tls_bio_dbuff_t *bd)
{
	return &bd->dbuff_in;
}

/** Allocate a new BIO/talloc buffer
 *
 * @param[out] out	Where to write a pointer to the #fr_tls_bio_dbuff_t.
 *			When this structure is freed the underlying BIO *
 *			will also be freed. May be NULL.
 * @param[in] bio_ctx	to allocate the BIO and wrapper struct in. May be NULL.
 * @param[in] buff_ctx	to allocate the expanding buffer in. May be NULL.
 * @param[in] init	how much memory to allocate initially.
 * @param[in] max	the maximum amount of memory to allocate (0 for unlimited).
 * @param[in] free_buff	free the talloced buffer when the #fr_tls_bio_dbuff_t is
 *			freed.
 * @return
 *	- A new BIO - Do not free manually, free the #fr_tls_bio_dbuff_t or
 *	  the ctx containing it instead.
 */
BIO *fr_tls_bio_dbuff_alloc(fr_tls_bio_dbuff_t **out, TALLOC_CTX *bio_ctx, TALLOC_CTX *buff_ctx,
			     size_t init, size_t max, bool free_buff)
{
	fr_tls_bio_dbuff_t	*bd;

	MEM(bd = talloc_zero(bio_ctx, fr_tls_bio_dbuff_t));
	MEM(bd->bio = BIO_new(tls_bio_talloc_meth));
	BIO_set_data(bd->bio, bd);

	/*
	 *	Initialise the dbuffs
	 */
	MEM(fr_dbuff_init_talloc(buff_ctx, &bd->dbuff_out, &bd->tctx, init, max));	/* Where we read from */
	bd->dbuff_in = FR_DBUFF_BIND_END_ABS(&bd->dbuff_out);				/* Where we write to */
	bd->dbuff_out.is_const = 1;
	bd->free_buff = free_buff;

	talloc_set_destructor(bd, _fr_tls_bio_dbuff_free);

	if (out) *out = bd;

	return bd->bio;
}

/** Finalise a talloc aggregation buffer, returning the underlying talloc array holding the data
 *
 * @return
 *	- NULL if the aggregation buffer wasn't initialised.
 *	- A talloc_array holding the aggregated data.
 */
uint8_t *fr_tls_bio_dbuff_thread_local_finalise(void)
{
	return fr_tls_bio_dbuff_finalise(tls_bio_talloc_agg);
}

/** Finalise a talloc aggregation buffer, returning the underlying talloc array holding the data
 *
 * This variant adds an additional \0 byte, and sets the talloc chunk type to char.
 *
 * @return
 *	- NULL if the aggregation buffer wasn't initialised.
 *	- A talloc_array holding the aggregated data.
 */
char *fr_tls_bio_dbuff_thread_local_finalise_bstr(void)
{
	return fr_tls_bio_dbuff_finalise_bstr(tls_bio_talloc_agg);
}

/** Discard any data in a talloc aggregation buffer
 *
 * fr_tls_bio_dbuff_thread_local must be called again before using the BIO
 */
void fr_tls_bio_dbuff_thread_local_clear(void)
{
	fr_tls_bio_dbuff_t *bd = tls_bio_talloc_agg;

	if (unlikely(!bd)) return;
	if (unlikely(!bd->dbuff_in.buff)) return;

	fr_dbuff_free_talloc(&bd->dbuff_in);
}

/** Frees the thread local TALLOC bio and its underlying OpenSSL BIO *
 *
 */
static int _fr_tls_bio_dbuff_thread_local_free(void *bio_talloc_agg)
{
	fr_tls_bio_dbuff_t	*our_bio_talloc_agg = talloc_get_type_abort(bio_talloc_agg, fr_tls_bio_dbuff_t);

	return talloc_free(our_bio_talloc_agg);			/* Frees the #fr_tls_bio_dbuff_t and BIO */
}

/** Return a BIO which will aggregate data in an expandable talloc buffer
 *
 * @note Only one of these BIOs may be in use at a given time.
 *
 * @param[in] init	how much memory to allocate initially.
 * @param[in] max	the maximum amount of memory to allocate (0 for unlimited).
 * @return A thread local BIO to pass to OpenSSL logging functions.
 */
BIO *fr_tls_bio_dbuff_thread_local(TALLOC_CTX *ctx, size_t init, size_t max)
{
	fr_tls_bio_dbuff_t *bd = tls_bio_talloc_agg;

	if (unlikely(!bd)) {
		fr_tls_bio_dbuff_alloc(&bd, NULL, ctx, init, max, true);
		fr_atexit_thread_local(tls_bio_talloc_agg, _fr_tls_bio_dbuff_thread_local_free, bd);

		return bd->bio;
	}

	fr_assert_msg(!tls_bio_talloc_agg->dbuff_out.buff, "BIO not finialised");
	MEM(fr_dbuff_init_talloc(ctx, &bd->dbuff_out, &bd->tctx, init, max));	/* Where we read from */
	bd->dbuff_in = FR_DBUFF_BIND_END_ABS(&bd->dbuff_out);			/* Where we write to */

	return tls_bio_talloc_agg->bio;
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
	tls_bio_talloc_meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "fr_tls_bio_dbuff_t");
	if (unlikely(!tls_bio_talloc_meth)) return -1;

	/*
	 *	If BIO_meth_set_create is ever used here be sure to call
	 *	BIO_set_init(bio, 1); in the create callbacks else all
	 *	operations on the BIO will fail.
	 */
	BIO_meth_set_write(tls_bio_talloc_meth, _tls_bio_talloc_write_cb);
	BIO_meth_set_puts(tls_bio_talloc_meth, _tls_bio_talloc_puts_cb);
	BIO_meth_set_read(tls_bio_talloc_meth, _tls_bio_talloc_read_cb);
	BIO_meth_set_gets(tls_bio_talloc_meth, _tls_bio_talloc_gets_cb);

	return 0;
}

/** Free the global log method templates
 *
 */
void fr_tls_bio_free(void)
{
	if (tls_bio_talloc_meth) {
		BIO_meth_free(tls_bio_talloc_meth);
		tls_bio_talloc_meth = NULL;
	}
}
#endif /* WITH_TLS */
