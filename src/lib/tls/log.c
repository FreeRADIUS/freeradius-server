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
 * @file tls/log.c
 * @brief Retrieve errors and log messages from OpenSSL's overly complex logging system.
 *
 * @copyright 2016,2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 The FreeRADIUS server project
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls"

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/tls/strerror.h>
#include <freeradius-devel/tls/utils.h>
#include <stdatomic.h>

#include "log.h"

/** Holds the state of a log BIO
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
	fr_sbuff_t		sbuff;		//!< Used to aggregate line data.
	fr_sbuff_uctx_talloc_t	tctx;		//!< extra talloc information for the sbuff.
	fr_sbuff_marker_t	logged_m;	//!< How much data has been written.

	request_t		*request;	//!< the current request.  Only used for the
						///< request log BIOs.
	fr_log_type_t		type;		//!< The type of log messages the bio will produce.
	fr_log_lvl_t		lvl;		//!< Level to log message at.
	char const		*file;		//!< File this log bio was bound on.
	int			line;		//!< Line this log bio was bound on.
} fr_tls_log_bio_t;

/** Template for the thread local request log BIOs
 */
static BIO_METHOD	*tls_request_log_meth;

/** Template for the global log BIOs
 */
static BIO_METHOD	*tls_global_log_meth;

/** Counter for users of the request log bio
 *
 */
static _Atomic(uint32_t) tls_request_log_ref;

/** Counter for users of the global log bio
 *
 */
static _Atomic(uint32_t) tls_global_log_ref;

/** Thread local request log BIO
 */
static _Thread_local	fr_tls_log_bio_t	*request_log_bio;

/** Thread local global log BIO
 */
static _Thread_local	fr_tls_log_bio_t	*global_log_bio;

/** Print out the current stack of certs
 *
 * @param[in] file	File where this function is being called.
 * @param[in] line	Line where this function is being called.
 * @param[in] request	Current request, may be NULL.
 * @param[in] log_type	The type of log message to produce L_INFO, L_ERR, L_DBG etc...
 * @param[in] chain	The certificate chain.
 * @param[in] cert	The leaf certificate.
 */
void _fr_tls_chain_log(char const *file, int line,
		       request_t *request, fr_log_type_t log_type,
		       STACK_OF(X509) *chain, X509 *cert)
{
	/*
	 *	Dump to the thread local buffer
	 */
	fr_strerror_clear();
	_fr_tls_strerror_push_chain(file, line, chain, cert);
	if (request) {
		log_request_perror(log_type, L_DBG_LVL_OFF, request, file, line, NULL);
	} else {
		fr_perror(NULL);
	}
}

/** Print out the current stack of certs
 *
 * @param[in] file	File where this function is being called.
 * @param[in] line	Line where this function is being called.
 * @param[in] request	Current request, may be NULL.
 * @param[in] log_type	The type of log message to produce L_INFO, L_ERR, L_DBG etc...
 * @param[in] chain	The certificate chain.
 * @param[in] cert	The leaf certificate.
 * @param[in] marker	The certificate we want to mark.
 */
void _fr_tls_chain_marker_log(char const *file, int line,
			      request_t *request, fr_log_type_t log_type,
			      STACK_OF(X509) *chain, X509 *cert, X509 *marker)
{
	/*
	 *	Dump to the thread local buffer
	 */
	fr_strerror_clear();
	_fr_tls_strerror_push_chain_marker(file, line, chain, cert, marker);
	if (request) {
		log_request_perror(log_type, L_DBG_LVL_OFF, request, file, line, NULL);
	} else {
		fr_perror(NULL);
	}
}

/** Print out the current stack of X509 objects (certificates only)
 *
 * @param[in] file		File where this function is being called.
 * @param[in] line		Line where this function is being called.
 * @param[in] request		Current request, may be NULL.
 * @param[in] log_type		The type of log message to produce L_INFO, L_ERR, L_DBG etc...
 * @param[in] objects		A stack of X509 objects
 */
void _fr_tls_x509_objects_log(char const *file, int line,
			      request_t *request, fr_log_type_t log_type,
			      STACK_OF(X509_OBJECT) *objects)
{

	fr_strerror_clear();
	_fr_tls_strerror_push_x509_objects(file, line, objects);
	if (request) {
		log_request_perror(log_type, L_DBG_LVL_OFF, request, file, line, NULL);
	} else {
		fr_perror(NULL);
	}
}

/** Print errors raised by OpenSSL I/O functions
 *
 * Drains the thread local OpenSSL error queue, and prints out errors
 * based on the SSL handle and the return code of the I/O  function.
 *
 * OpenSSL lists I/O functions to be:
 *   - SSL_connect
 *   - SSL_accept
 *   - SSL_do_handshake
 *   - SSL_read
 *   - SSL_peek
 *   - SSL_write
 *
 * @param request	The current request (may be NULL).
 * @param err		returned from SSL_get_error().
 * @param fmt		Error message describing the operation being attempted.
 * @param ...		Arguments for msg.
 * @return
 *	- 0 TLS session may still be viable.
 *	- -1 TLS session cannot continue.
 */
int fr_tls_log_io_error(request_t *request, int err, char const *fmt, ...)
{
	static fr_table_num_ordered_t const ssl_io_error_table[] = {
		{ L("SSL_ERROR_NONE"),			SSL_ERROR_NONE			},
		{ L("SSL_ERROR_ZERO_RETURN"),		SSL_ERROR_ZERO_RETURN		},
		{ L("SSL_ERROR_WANT_READ"),		SSL_ERROR_WANT_READ		},
		{ L("SSL_ERROR_WANT_WRITE"),		SSL_ERROR_WANT_WRITE		},
		{ L("SSL_ERROR_WANT_CONNECT"),		SSL_ERROR_WANT_CONNECT		},
		{ L("SSL_ERROR_WANT_ACCEPT"),		SSL_ERROR_WANT_ACCEPT		},
		{ L("SSL_ERROR_WANT_X509_LOOKUP"),	SSL_ERROR_WANT_X509_LOOKUP	},
		{ L("SSL_ERROR_WANT_ASYNC"),		SSL_ERROR_WANT_ASYNC		},
		{ L("SSL_ERROR_WANT_ASYNC_JOB"),	SSL_ERROR_WANT_ASYNC_JOB	},
		{ L("SSL_ERROR_WANT_CLIENT_HELLO_CB"),	SSL_ERROR_WANT_CLIENT_HELLO_CB	},
		{ L("SSL_ERROR_SYSCALL"),		SSL_ERROR_SYSCALL		},
		{ L("SSL_ERROR_SSL"),			SSL_ERROR_SSL			}
	};
	static size_t ssl_io_error_table_len = NUM_ELEMENTS(ssl_io_error_table);

	va_list ap;
	char *msg = NULL;

	switch (err) {
	/*
	 *	These seem to be harmless and already "dealt
	 *	with" by our non-blocking environment. NB:
	 *	"ZERO_RETURN" is the clean "error"
	 *	indicating a successfully closed SSL
	 *	tunnel. We let this happen because our IO
	 *	loop should not appear to have broken on
	 *	this condition - and outside the IO loop, the
	 *	"shutdown" state is checked.
	 *
	 *	Don't print anything if we ignore the error.
	 */
	case SSL_ERROR_NONE:
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_X509_LOOKUP:
	case SSL_ERROR_ZERO_RETURN:
		if (DEBUG_ENABLED2 || RDEBUG_ENABLED2) {
			va_start(ap, fmt);
			msg = fr_vasprintf(NULL, fmt, ap);
			va_end(ap);

			ROPTIONAL(RDEBUG2, DEBUG2, "%s - %s (%i)",
				  msg, fr_table_str_by_value(ssl_io_error_table, err, "<UNKNOWN>"), err);
			talloc_free(msg);
		}
		break;

	/*
	 *	These seem to be indications of a genuine
	 *	error that should result in the SSL tunnel
	 *	being regarded as "dead".
	 */
	case SSL_ERROR_SYSCALL:
		va_start(ap, fmt);
		msg = fr_vasprintf(NULL, fmt, ap);
		va_end(ap);

		ROPTIONAL(REDEBUG, ERROR, "%s - System call (I/O) error - %s (%i)",
			  msg, fr_table_str_by_value(ssl_io_error_table, err, "<UNKNOWN>"), err);

		talloc_free(msg);
		return -1;

	/*
	 *	Docs say a more verbose error is available
	 *	in the normal error stack.
	 */
	case SSL_ERROR_SSL:
		va_start(ap, fmt);
		(void)fr_tls_strerror_vprintf(fmt, ap);
		va_end(ap);

		ROPTIONAL(RPERROR, PERROR, "");
		return -1;

	/*
	 *	For any other errors that (a) exist, and (b)
	 *	crop up - we need to interpret what to do with
	 *	them - so "politely inform" the caller that
	 *	the code needs updating here.
	 */
	default:
		va_start(ap, fmt);
		msg = fr_vasprintf(NULL, fmt, ap);
		va_end(ap);

		ROPTIONAL(REDEBUG, ERROR, "%s - TLS session error - %s (%i)",
			  msg, fr_table_str_by_value(ssl_io_error_table, err, "<UNKNOWN>"), err);

		talloc_free(msg);

		return -1;
	}

	return 0;
}


/** Print errors in the TLS thread local error stack
 *
 * Drains the thread local OpenSSL error queue, and prints out errors.
 *
 * @param[in] request	The current request (may be NULL).
 * @param[in] msg	Error message describing the operation being attempted.
 * @param[in] ...	Arguments for msg.
 * @return the number of errors drained from the stack.
 */
int fr_tls_log(request_t *request, char const *msg, ...)
{
	va_list ap;
	int ret;

	va_start(ap, msg);
	ret = fr_tls_strerror_vprintf(msg, ap);
	va_end(ap);

	ROPTIONAL(RPERROR, PERROR, "");

	return ret;
}

/** Clear errors in the TLS thread local error stack
 *
 */
void fr_tls_log_clear(void)
{
	while (ERR_get_error() != 0);
}

/** Increment the bio meth reference counter
 *
 */
static int tls_log_request_bio_create_cb(BIO *bio)
{
	atomic_fetch_add(&tls_request_log_ref, 1);
	BIO_set_init(bio, 1);
	return 1;
}

/** Converts BIO_write() calls to request log calls
 *
 * This callback is used to glue the output of OpenSSL functions into request log calls.
 *
 * @param[in] bio	that was written to.
 * @param[in] in	data being written to BIO.
 * @param[in] len	Length of data being written.
 */
static int tls_log_request_bio_write_cb(BIO *bio, char const *in, int len)
{
	fr_tls_log_bio_t	*lb = talloc_get_type_abort(BIO_get_data(bio), fr_tls_log_bio_t);
	request_t		*request = talloc_get_type_abort(lb->request, request_t);
	log_request_func_t	func;
	char			*le;

	/*
	 *	Pick the right logging function based on the type
	 */
	if ((lb->type == L_ERR) || (lb->type == L_DBG_ERR) || (lb->type == L_DBG_ERR_REQ)) {
		func = log_request_error;
	} else {
		func = log_request;
	}

	/*
	 *	OpenSSL feeds us data in fragments so we need
	 *	to aggregate it, then look for new line chars
	 *	as an indication we need to print the line.
	 */
	/* coverity[check_return] */
	fr_sbuff_in_bstrncpy(&lb->sbuff, in, len);

	/*
	 *	Split incoming data on new lines
	 */
	while (fr_sbuff_behind(&lb->logged_m)) {
		le = memchr(fr_sbuff_current(&lb->logged_m), '\n',
			    fr_sbuff_current(&lb->sbuff) - fr_sbuff_current(&lb->logged_m));
		/*
		 *	Wait until we have a complete line
		 */
		if (le == NULL) break;

		/*
		 *	Skip empty lines
		 */
		if ((le - fr_sbuff_current(&lb->logged_m)) > 0) {
			func(lb->type, lb->lvl, request, __FILE__, __LINE__, "%pV",
			     fr_box_strvalue_len(fr_sbuff_current(&lb->logged_m),
			     			 le - fr_sbuff_current(&lb->logged_m)));
		}

		fr_sbuff_set(&lb->logged_m, le + 1);
	}

	/*
	 *	Clear out printed data
	 */
	fr_sbuff_shift(&lb->sbuff, fr_sbuff_used(&lb->logged_m));

	return len;	/* Amount of data written */
}

/** Converts BIO_puts() calls to request log calls
 *
 * This callback is used to glue the output of OpenSSL functions into request log calls.
 *
 * @param[in] bio	that was written to.
 * @param[in] in	data being written to BIO.
 */
static int tls_log_request_bio_puts_cb(BIO *bio, char const *in)
{
	return tls_log_request_bio_write_cb(bio, in, strlen(in));
}

/** Decrement the bio meth reference counter
 *
 */
static int tls_log_request_bio_free_cb(BIO *bio)
{
	atomic_fetch_sub(&tls_request_log_ref, 1);
	BIO_set_init(bio, 0);
	return 1;
}

/** Increment the bio meth reference counter
 *
 */
static int tls_log_global_bio_create_cb(BIO *bio)
{
	atomic_fetch_add(&tls_global_log_ref, 1);
	BIO_set_init(bio, 1);
	return 1;
}

/** Converts BIO_write() calls to global log calls
 *
 * This callback is used to glue the output of OpenSSL functions into global log calls.
 *
 * @param[in] bio	that was written to.
 * @param[in] in	data being written to BIO.
 * @param[in] len	Length of data being written.
 */
static int tls_log_global_bio_write_cb(BIO *bio, char const *in, int len)
{
	fr_tls_log_bio_t	*lb = talloc_get_type_abort(BIO_get_data(bio), fr_tls_log_bio_t);
	char			*le;

	/*
	 *	OpenSSL feeds us data in fragments so we need
	 *	to aggregate it, then look for new line chars
	 *	as an indication we need to print the line.
	 */
	/* coverity[check_return] */
	fr_sbuff_in_bstrncpy(&lb->sbuff, in, len);

	/*
	 *	Split incoming data on new lines
	 */
	while (fr_sbuff_behind(&lb->logged_m)) {
		le = memchr(fr_sbuff_current(&lb->logged_m), '\n',
			    fr_sbuff_current(&lb->sbuff) - fr_sbuff_current(&lb->logged_m));
		/*
		 *	Wait until we have a complete line
		 */
		if (le == NULL) break;

		/*
		 *	Skip empty lines
		 */
		if ((le - fr_sbuff_current(&lb->logged_m)) > 0) {
			if (fr_debug_lvl >= lb->lvl) fr_log(&default_log, lb->type, __FILE__, __LINE__,
							    "%pV",
							    fr_box_strvalue_len(fr_sbuff_current(&lb->logged_m),
										le - fr_sbuff_current(&lb->logged_m)));
		}

		fr_sbuff_set(&lb->logged_m, le + 1);
	}

	/*
	 *	Clear out printed data
	 */
	fr_sbuff_shift(&lb->sbuff, fr_sbuff_used(&lb->logged_m));

	return len;	/* Amount of data written */
}

/** Converts BIO_puts() calls to global log calls
 *
 * This callback is used to glue the output of OpenSSL functions into global log calls.
 *
 * @param[in] bio	that was written to.
 * @param[in] in	data being written to BIO.
 */
static int tls_log_global_bio_puts_cb(BIO *bio, char const *in)
{
	return tls_log_global_bio_write_cb(bio, in, strlen(in));
}

/** Decrement the bio meth reference counter
 *
 */
static int tls_log_global_bio_free_cb(BIO *bio)
{
	atomic_fetch_sub(&tls_global_log_ref, 1);
	BIO_set_init(bio, 0);
	return 1;
}

/** Frees a logging bio and its underlying OpenSSL BIO *
 *
 */
static int _fr_tls_log_bio_free(void *log_bio)
{
	fr_tls_log_bio_t	*our_log_bio = talloc_get_type_abort(log_bio, fr_tls_log_bio_t);

	BIO_free(our_log_bio->bio);
	our_log_bio->bio = NULL;
	return talloc_free(our_log_bio);
}

/** Return a request log BIO to use with OpenSSL logging functions
 *
 * @note The contents of the BIO will only be written to the logging system on finding
 *       a new line.  If data remains in the BIO when it is re-initialised (this function
 *       is called again), that data will be discarded.
 *
 * @note The returned BIO should be assumed to be invalid if the request yields.
 *
 * @param[in] file	of caller.
 * @Parma[in] line	of caller.
 * @param[in] request	to temporarily associate with logging BIO.
 * @param[in] type	to temporarily assign to logging bio.
 * @param[in] lvl	to temporarily assign to logging bio.
 * @return A thread local BIO to pass to OpenSSL logging functions.
 */
BIO *_fr_tls_request_log_bio(char const *file, int line, request_t *request, fr_log_type_t type, fr_log_lvl_t lvl)
{
	if (unlikely(!request_log_bio)) {
		fr_tls_log_bio_t	*lb;

		MEM(lb = talloc(NULL, fr_tls_log_bio_t));
		*lb = (fr_tls_log_bio_t) {
			.bio = BIO_new(tls_request_log_meth),
			.request = request,
			.type = type,
			.lvl = lvl,
			.file = file,
			.line = line
		};
		MEM(lb->bio);
		BIO_set_data(lb->bio, lb);	/* So we can retrieve the fr_tls_lb_t in the callbacks */
		fr_sbuff_init_talloc(lb, &lb->sbuff, &lb->tctx, 1024, 10 * 1024);	/* start 1k, max 10k */
		fr_atexit_thread_local(request_log_bio, _fr_tls_log_bio_free, lb);
		fr_sbuff_marker(&lb->logged_m, &lb->sbuff);
		return lb->bio;
	}

	fr_sbuff_set(&request_log_bio->logged_m, fr_sbuff_start(&request_log_bio->sbuff));
	fr_sbuff_reset_talloc(&request_log_bio->sbuff);	/* Reset to initial size */
	request_log_bio->request = request;
	request_log_bio->type = type;
	request_log_bio->lvl = lvl;
	request_log_bio->file = file;
	request_log_bio->line = line;

	return request_log_bio->bio;
}

/** Return a global log BIO to use with OpenSSL logging functions
 *
 * @note The contents of the BIO will only be written to the logging system on finding
 *       a new line.  If data remains in the BIO when it is re-initialised (this function
 *       is called again), that data will be discarded.
 *
 * @note The returned BIO should be assumed to be invalid if the current request yields.
 *
 * @param[in] file	of caller.
 * @Parma[in] line	of caller.
 * @param[in] type	to temporarily assign to logging bio.
 * @param[in] lvl	to temporarily assign to logging bio.
 * @return A thread local BIO to pass to OpenSSL logging functions.
 */
BIO *_fr_tls_global_log_bio(char const *file, int line, fr_log_type_t type, fr_log_lvl_t lvl)
{
	if (unlikely(!global_log_bio)) {
		fr_tls_log_bio_t	*lb;

		MEM(lb = talloc(NULL, fr_tls_log_bio_t));
		*lb = (fr_tls_log_bio_t) {
			.bio = BIO_new(tls_global_log_meth),
			.type = type,
			.lvl = lvl,
			.file = file,
			.line = line
		};
		MEM(lb->bio);
		BIO_set_data(lb->bio, lb);	/* So we can retrieve the fr_tls_lb_t in the callbacks */
		fr_sbuff_init_talloc(lb, &lb->sbuff, &lb->tctx, 1024, 10 * 1024);	/* start 1k, max 10k */
		fr_atexit_thread_local(global_log_bio, _fr_tls_log_bio_free, lb);
		fr_sbuff_marker(&lb->logged_m, &lb->sbuff);
		return lb->bio;
	}

	fr_sbuff_set(&global_log_bio->logged_m, fr_sbuff_start(&global_log_bio->sbuff));
	fr_sbuff_reset_talloc(&request_log_bio->sbuff);	/* Reset to initial size */
	global_log_bio->type = type;
	global_log_bio->lvl = lvl;
	global_log_bio->file = file;
	global_log_bio->line = line;

	return global_log_bio->bio;
}

/** Initialise the BIO logging meths which are used to create thread local logging BIOs
 *
 */
int fr_tls_log_init(void)
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
	tls_request_log_meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "fr_tls_request_log");
	if (unlikely(!tls_request_log_meth)) return -1;

	BIO_meth_set_create(tls_request_log_meth, tls_log_request_bio_create_cb);
	BIO_meth_set_write(tls_request_log_meth, tls_log_request_bio_write_cb);
	BIO_meth_set_puts(tls_request_log_meth, tls_log_request_bio_puts_cb);
	BIO_meth_set_destroy(tls_request_log_meth, tls_log_request_bio_free_cb);

	tls_global_log_meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "fr_tls_global_log");
	if (unlikely(!tls_global_log_meth)) {
		BIO_meth_free(tls_request_log_meth);
		tls_request_log_meth = NULL;
		return -1;
	}

	BIO_meth_set_create(tls_global_log_meth, tls_log_global_bio_create_cb);
	BIO_meth_set_write(tls_global_log_meth, tls_log_global_bio_write_cb);
	BIO_meth_set_puts(tls_global_log_meth, tls_log_global_bio_puts_cb);
	BIO_meth_set_destroy(tls_global_log_meth, tls_log_global_bio_free_cb);

	return 0;
}

/** Free the global log method templates
 *
 */
void fr_tls_log_free(void)
{
	/*
	 *	These must be freed first else
	 *      we get crashes in the OpenSSL
	 *	code when we try to free them.
	 */
	fr_assert_msg(atomic_load(&tls_request_log_ref) == 0, "request log BIO refs remaining %u", atomic_load(&tls_request_log_ref));
	fr_assert_msg(atomic_load(&tls_global_log_ref) == 0, "global log BIO refs remaining %u", atomic_load(&tls_global_log_ref));

	if (tls_request_log_meth) {
		BIO_meth_free(tls_request_log_meth);
		tls_request_log_meth = NULL;
	}

	if (tls_global_log_meth) {
		BIO_meth_free(tls_global_log_meth);
		tls_global_log_meth = NULL;
	}
}
#endif /* WITH_TLS */
