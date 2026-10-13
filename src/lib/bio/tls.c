/*
 *   This program is free software; you can redistribute it and/or modify
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
 * $Id$
 * @file lib/bio/tls.c
 * @brief Binary IO abstractions for TLS and DTLS connections
 *
 *  The TLS bio sits between the application and an fd bio, which carries the encrypted records.  The TLS bio
 *  owns the whole life of the TLS connection:
 *
 *  1. `fr_bio_tls_alloc()` allocates the bio and the `fr_tls_connection_t` from the request, and sets
 *     `conn->request`.  The request must already use an interpreter.
 *  2. `fr_bio_tls_connect()` takes the connection through every state which comes before application data:
 *     the connect() of the fd bio, the TLS or DTLS handshake, and the policies which run before and after
 *     the handshake.  During these states the TLS bio reads and writes the fd bio, and owns the events of
 *     the fd in the event list of the interpreter.
 *  3. When the connection can carry application data, the TLS bio removes the events of the fd, and calls
 *     the `connected` callback.  From then on the application reads and writes the TLS bio in the same way as
 *     any other bio.  A read takes encrypted data from the fd bio, passes the encrypted data through
 *     OpenSSL, and returns the decrypted application data.  A write encrypts the application data, and
 *     writes the encrypted records to the fd bio.
 *
 *  The next bio MUST be a fd bio.  If the connection fails at any point, the TLS bio removes the events of
 *  the fd, and calls the `failed` callback.  The `failed` callback must not free the bio, as the failure can
 *  happen inside a read or a write on the bio.
 *
 *  The bio and the `fr_tls_connection_t` are allocated from the request, so freeing the request frees both.
 *  Freeing the bio cancels the request, as the request has a frame which points to the connection.
 *
 *  After each read or write to the fd bio, the TLS bio calls `fr_tls_connection_io_error()` to decide what to
 *  do next: try again, wait, or stop.  `fr_tls_connection_io_error()` also tells the TLS connection about EOF
 *  and fatal errors.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/server/base.h>

#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/connection.h>

#include <freeradius-devel/unlang/interpret.h>

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/fd.h>
#include <freeradius-devel/bio/tls.h>

/** The TLS bio
 *
 */
struct fr_bio_tls_s {
	FR_BIO_COMMON;

	fr_tls_connection_t	*conn;			//!< The TLS connection, which is a child of the bio.
							///< `conn->request` is the request which the bio came from.

	fr_event_list_t		*el;			//!< The event list of the interpreter.
	bool			events;			//!< The bio owns the events of the fd, which it has until the
							///< connection is connected.  The event loop can remove the
							///< events by itself, e.g. at EOF, so the bio keeps no pointer.
	int			fd;			//!< The fd of the next bio.

	SSL_CTX			*ssl_ctx;		//!< Used to create the TLS session.
	bool			client;			//!< Act as the client, and connect to a server.
	bool			client_cert;		//!< For a server, require a client certificate.

	bool			write_wait;		//!< The write event of the fd is active.

	void			*packet_ctx;		//!< Passed to the next bio when writing encrypted records.
							///< Set only while `fr_bio_tls_write()` runs.  Records which
							///< are written later, by `fr_bio_tls_write_resume()`, have
							///< no `packet_ctx`, as the caller's `packet_ctx` may be gone.

	size_t			clean_len;		//!< How much decrypted data is in `clean_out`.
	size_t			clean_offset;		//!< How much of the decrypted data the caller has read.

	ssize_t			next_error;		//!< The error which the next bio returned from a write.

	bool			write_blocked;		//!< The next bio is blocked.  Encrypted records wait in the
							///< TLS connection until `fr_bio_tls_write_resume()` runs.

	uint8_t			buffer[SSL3_RT_MAX_PLAIN_LENGTH]; //!< Encrypted data read from the next bio.
};

static fr_event_update_t const pause_write[] = {
	FR_EVENT_SUSPEND(fr_event_io_func_t, write),
	{ 0 }
};

static fr_event_update_t const resume_write[] = {
	FR_EVENT_RESUME(fr_event_io_func_t, write),
	{ 0 }
};

/** Start or stop waiting for the fd to have room for more records
 *
 *  The event of the fd is inserted with a write callback, and then the write event is suspended, as an fd
 *  which has room fires the write event on every pass of the event loop.  The write event is active only
 *  while encrypted records are waiting for room.
 *
 *  A suspend reads the active callback and a resume reads the suspended callback, so a suspend and a resume
 *  have to alternate.  `write_wait` records whether the write event is active.
 *
 * @return
 *	- 0 on success, or when the bio does not own the events of the fd
 *	- <0 on error
 */
static int fr_bio_tls_write_wait(fr_bio_tls_t *my, bool wait)
{
	if (!my->events || (my->write_wait == wait)) return 0;

	if (fr_event_filter_update(my->el, my->fd, FR_EVENT_FILTER_IO, wait ? resume_write : pause_write) < 0) {
		fr_strerror_const_push("Failed updating the write event of the TLS connection");
		return -1;
	}

	my->write_wait = wait;

	return 0;
}

/** Stop owning the events of the fd
 *
 */
static void fr_bio_tls_events_delete(fr_bio_tls_t *my)
{
	if (!my->events) return;

	/*
	 *	Fails harmlessly when the event loop has already removed the events.
	 */
	(void) fr_event_fd_delete(my->el, my->fd, FR_EVENT_FILTER_IO);
	my->events = false;
	my->write_wait = false;
}

/** Tell the next bio that it can write again
 *
 *  The next bio does not know that the event loop saw the fd become writable.
 */
static void fr_bio_tls_next_resume(fr_bio_t *next)
{
	fr_bio_common_t *this = (fr_bio_common_t *) next;

	if (this->priv_cb.write_resume) (void) this->priv_cb.write_resume(next);
}

/** Stop the connection, and tell the application
 *
 *  This function is for failures which the TLS connection does not know about, i.e. before the connection
 *  has started.
 */
static void fr_bio_tls_failed(fr_bio_tls_t *my, fr_tls_connection_fail_t reason, int error)
{
	fr_bio_tls_events_delete(my);

	my->conn->failed = reason;
	my->conn->error = error;

	my->bio.read = fr_bio_shutdown_read;
	my->bio.write = fr_bio_shutdown_write;

	if (my->cb.failed) my->cb.failed(&my->bio);
}

/** Write encrypted records to the next bio
 *
 *  `fr_tls_connection_write()` calls this function once for each block of encrypted data in the TLS
 *  connection.  For datagrams, each block is one datagram.
 *
 *  A partial write means that the fd bio is out of room, so we assume that writes are blocked, in the same
 *  way as `fr_bio_mem_write_next()`.  For every other result, `fr_tls_connection_io_error()` decides what
 *  to do.
 *
 *  On EOF or a fatal error, `fr_tls_connection_io_error()` tells the TLS connection, which runs the
 *  `failed` callback of the application.
 *
 * @return
 *	- >0 the amount of data which was written
 *	- 0 writes are blocked.  The data stays in the TLS connection, and `fr_bio_tls_write_resume()`
 *	  writes the data.
 *	- <0 the write failed.  The error is saved in `next_error`.
 */
static ssize_t fr_bio_tls_conn_write(fr_tls_connection_t *conn, uint8_t const *data, size_t size)
{
	fr_bio_tls_t	*my = talloc_get_type_abort(conn->uctx, fr_bio_tls_t);
	fr_bio_t	*next;
	ssize_t		slen;

	/*
	 *	An earlier write was partial, or blocked.  Leave the data in the TLS connection until
	 *	`fr_bio_tls_write_resume()` runs.
	 */
	if (my->write_blocked) return 0;

	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

retry:
	slen = next->write(next, my->packet_ctx, data, size);
	if (slen > 0) {
		if ((size_t) slen == size) {
			/*
			 *	Something went out, so the fd had room.  Stop waiting for room, which does
			 *	nothing when the bio is not waiting.
			 */
			if (fr_bio_tls_write_wait(my, false) < 0) return -1;
			return slen;
		}

		/*
		 *	Tell the previous bios that writes are blocked.  The data has been written, so we
		 *	return how much was written, even if a previous bio returns an error.  Otherwise the
		 *	TLS connection would write the same data again.
		 */
		my->write_blocked = true;
		(void) fr_bio_write_blocked(&my->bio);
		if (fr_bio_tls_write_wait(my, true) < 0) return -1;
		return slen;
	}

	/*
	 *	The fd bio returns 0 after it shuts the chain down for an error such as `EPIPE`.
	 */
	my->next_error = (slen < 0) ? slen : fr_bio_error(SHUTDOWN);

	/*
	 *	The fd bio calls its `write_blocked` callback before returning `IO_WOULD_BLOCK`, and the
	 *	callback may change `errno`.
	 */
	if (slen == fr_bio_error(IO_WOULD_BLOCK)) errno = EAGAIN;

	switch (fr_tls_connection_io_error(conn, slen)) {
	case FR_TLS_CONNECTION_IO_RETRY:
		goto retry;

	case FR_TLS_CONNECTION_IO_BLOCKED:
		my->write_blocked = true;
		if (fr_bio_tls_write_wait(my, true) < 0) return -1;
		return 0;

	/*
	 *	`write()` failed, so the result cannot be "no error".  Treat the impossible value as fatal.
	 */
	case FR_TLS_CONNECTION_IO_OK:
	case FR_TLS_CONNECTION_IO_EOF:
	case FR_TLS_CONNECTION_IO_FATAL:
		break;
	}

	return -1;
}

static ssize_t fr_bio_tls_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size);
static ssize_t fr_bio_tls_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size);

/** The TLS connection can carry application data
 *
 *  The TLS connection calls this function once, when the connection enters the `TLS_CONNECTION_CONNECTED`
 *  state.  The application owns the fd from now on, so the events of the fd go away before the application
 *  hears about the connection.  The application can then read and write the bio.
 */
static void fr_bio_tls_conn_connected(fr_tls_connection_t *conn)
{
	fr_bio_tls_t *my = talloc_get_type_abort(conn->uctx, fr_bio_tls_t);

	fr_bio_tls_events_delete(my);

	my->bio.read = fr_bio_tls_read;
	my->bio.write = fr_bio_tls_write;

	if (my->cb.connected) my->cb.connected(&my->bio);
}

/** The TLS connection failed
 *
 *  The TLS connection runs the `close` callback only after a failure.  After a failure the bio cannot read
 *  or write, and the application decides when to free the bio.
 */
static void fr_bio_tls_conn_close(fr_tls_connection_t *conn)
{
	fr_bio_tls_t *my = talloc_get_type_abort(conn->uctx, fr_bio_tls_t);

	fr_bio_tls_events_delete(my);

	my->bio.read = fr_bio_shutdown_read;
	my->bio.write = fr_bio_shutdown_write;

	if (my->cb.failed) my->cb.failed(&my->bio);
}

/** Write any pending encrypted records to the next bio
 *
 * @return
 *	- 1 nothing is left to write
 *	- 0 the next bio is blocked, and some data is still waiting
 *	- <0 the error which the next bio returned
 */
static int fr_bio_tls_flush(fr_bio_tls_t *my)
{
	fr_tls_session_t *tls_session = my->conn->tls_session;

	if (fr_tls_connection_write(my->conn) < 0) return my->next_error;

	if (fr_dbuff_remaining(tls_session->dirty_out) > 0) return 0;

	return 1;
}

/** Record that the next bio is blocked
 *
 */
static int fr_bio_tls_write_blocked(fr_bio_t *bio)
{
	fr_bio_tls_t *my = talloc_get_type_abort(bio, fr_bio_tls_t);

	my->write_blocked = true;

	return 1;
}

/** Write the encrypted records which were waiting for the next bio
 *
 * @return
 *	- 1 writes can resume
 *	- 0 still blocked
 *	- <0 on error
 */
static int fr_bio_tls_write_resume(fr_bio_t *bio)
{
	fr_bio_tls_t	*my = talloc_get_type_abort(bio, fr_bio_tls_t);
	int		rcode;

	/*
	 *	`fr_bio_tls_conn_write()` sets `write_blocked` again if the next bio is still blocked.
	 */
	my->write_blocked = false;

	rcode = fr_bio_tls_flush(my);
	if (rcode <= 0) return rcode;

	if (!my->cb.write_resume) return 1;

	return my->cb.write_resume(bio);
}

/** Encrypt application data, and write the encrypted records to the next bio
 *
 *  `SSL_MODE_ENABLE_PARTIAL_WRITE` is not set, so OpenSSL encrypts all of the data passed to
 *  `SSL_write()`. The application data therefore counts as written as soon as OpenSSL encrypts the data.
 *  If the next bio blocks, the encrypted records wait in the TLS connection, and the next write or
 *  `fr_bio_tls_write_resume()` writes the records later.  Until the waiting records reach the next bio,
 *  the bio returns `fr_bio_error(IO_WOULD_BLOCK)` for new application data.  The amount of waiting data
 *  therefore cannot grow without limit.
 *
 * @return
 *	- >0 the amount of application data which was written
 *	- `fr_bio_error(IO_WOULD_BLOCK)` when encrypted records are still waiting for the next bio
 *	- <0 on error
 */
static ssize_t fr_bio_tls_write_data(fr_bio_tls_t *my, void const *buffer, size_t size)
{
	fr_tls_session_t	*tls_session = my->conn->tls_session;
	uint8_t const		*p = buffer;
	size_t			written = 0;
	int			rcode;

	/*
	 *	Writes are blocked.  `fr_bio_tls_write_resume()` writes the waiting records.
	 */
	if (my->write_blocked) return fr_bio_error(IO_WOULD_BLOCK);

	/*
	 *	A read can leave encrypted records waiting.  `fr_bio_tls_flush()` writes the waiting
	 *	records first, so that the next bio receives the records in order.
	 */
	if (fr_dbuff_remaining(tls_session->dirty_out) > 0) {
		rcode = fr_bio_tls_flush(my);
		if (rcode < 0) return rcode;
		if (rcode == 0) return fr_bio_error(IO_WOULD_BLOCK);
	}

	while (written < size) {
		size_t chunk = size - written;

		if (chunk > fr_dbuff_remaining(&tls_session->clean_in)) chunk = fr_dbuff_remaining(&tls_session->clean_in);

		(void) fr_dbuff_in_memcpy(&tls_session->clean_in, p + written, chunk);

		/*
		 *	After a failure inside OpenSSL, the TLS connection cannot continue.  The TLS bio is the
		 *	bio which failed, so the TLS bio shuts the chain down.
		 */
		if (fr_tls_session_send(my->conn->request, tls_session) < 0) {
			fr_strerror_const("Failed encrypting TLS application data");
			(void) fr_bio_shutdown(&my->bio);
			return fr_bio_error(GENERIC);
		}

		/*
		 *	OpenSSL has taken the data, so the data has been written, even if the encrypted
		 *	records have not yet reached the next bio.
		 */
		written += chunk;

		rcode = fr_bio_tls_flush(my);
		if (rcode == 1) continue;

		/*
		 *	Writes are blocked, or the write failed.  OpenSSL has already taken the application
		 *	data, so we return how much data OpenSSL took, and not the error.  If the caller wrote
		 *	the same data again, the peer would get the data twice.
		 */
		break;
	}

	return written;
}

static ssize_t fr_bio_tls_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	fr_bio_tls_t	*my = talloc_get_type_abort(bio, fr_bio_tls_t);
	ssize_t		rcode;

	/*
	 *	The fd bio asks the previous bios to write any pending data by passing `SIZE_MAX`, before the fd
	 *	bio shuts down.
	 */
	if (size == SIZE_MAX) {
		rcode = fr_bio_tls_flush(my);
		return (rcode < 0) ? rcode : 0;
	}

	my->packet_ctx = packet_ctx;
	rcode = fr_bio_tls_write_data(my, buffer, size);
	my->packet_ctx = NULL;

	return rcode;
}

/** Check whether OpenSSL holds data which the bio has not yet processed
 *
 */
static bool fr_bio_tls_pending(fr_bio_tls_t *my)
{
	fr_tls_session_t *tls_session = my->conn->tls_session;

	return (fr_dbuff_remaining(fr_tls_bio_dbuff_out(tls_session->into_ssl)) > 0) ||
		(SSL_pending(tls_session->ssl) > 0);
}

/** Decrypt one record which is waiting in OpenSSL
 *
 * @return
 *	- 1 one record was processed.  The record may not contain application data.
 *	- 0 OpenSSL needs more data for a complete record
 *	- <0 on error
 */
static int fr_bio_tls_decrypt(fr_bio_tls_t *my)
{
	fr_tls_session_t	*tls_session = my->conn->tls_session;
	int			rcode;

	rcode = fr_tls_session_recv(my->conn->request, tls_session);
	if (rcode < 0) {
		/*
		 *	After a failure inside OpenSSL, the TLS connection cannot continue.  The TLS bio is the
		 *	bio which failed, so the TLS bio shuts the chain down.
		 */
		fr_strerror_const("Failed decrypting TLS application data");
		(void) fr_bio_shutdown(&my->bio);
		return fr_bio_error(GENERIC);
	}

	if (rcode == 1) return 0;

	my->clean_len = fr_dbuff_used(&tls_session->clean_out);
	my->clean_offset = 0;

	/*
	 *	`fr_tls_session_recv()` can leave encrypted records in `dirty_out`.  When writes are
	 *	blocked, `fr_bio_tls_write_resume()` writes the records later.
	 */
	if (fr_dbuff_remaining(tls_session->dirty_out) > 0) {
		rcode = fr_bio_tls_flush(my);
		if (rcode < 0) return rcode;
	}

	return 1;
}

/** Copy decrypted data which the caller has not yet read into the caller's buffer
 *
 */
static size_t fr_bio_tls_clean_read(fr_bio_tls_t *my, void *buffer, size_t size)
{
	size_t used = my->clean_len - my->clean_offset;

	if (size > used) size = used;

	memcpy(buffer, fr_dbuff_start(&my->conn->tls_session->clean_out) + my->clean_offset, size);
	my->clean_offset += size;

	return size;
}

/** Read encrypted data from the next bio, and return the decrypted application data
 *
 *  One record can hold more application data than the caller asked for.  The rest of the data stays in
 *  the TLS connection, and the next read returns the rest.  The bio asks OpenSSL to decrypt the next
 *  record only after the caller has read all of the data from the previous record.
 *
 * @return
 *	- >0 the amount of application data which was read
 *	- 0 no application data is available, or the peer closed the TLS connection
 *	- <0 on error
 */
static ssize_t fr_bio_tls_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	fr_bio_tls_t		*my = talloc_get_type_abort(bio, fr_bio_tls_t);
	fr_tls_connection_t	*conn = my->conn;
	fr_tls_session_t	*tls_session = conn->tls_session;
	fr_bio_t		*next;

	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	while (true) {
		size_t	room;
		ssize_t	rcode;

		if (my->clean_offset < my->clean_len) return fr_bio_tls_clean_read(my, buffer, size);

		/*
		 *	Decrypt the records which OpenSSL already has.  A record which holds no application
		 *	data, such as a session ticket, produces no data, and the loop then decrypts the next
		 *	record.
		 */
		if (fr_bio_tls_pending(my)) {
			rcode = fr_bio_tls_decrypt(my);
			if (rcode < 0) return rcode;

			if (rcode == 1) {
				if (my->clean_len > 0) continue;

				/*
				 *	The peer sent a TLS `close_notify` alert, which ends the TLS connection.
				 *	No more application data will arrive.
				 */
				if ((SSL_get_shutdown(tls_session->ssl) & SSL_RECEIVED_SHUTDOWN) != 0) {
					fr_bio_eof(&my->bio);
					return 0;
				}

				if (fr_bio_tls_pending(my)) continue;
			}
		}

		/*
		 *	OpenSSL needs more data.  When `dirty_in` is full, and OpenSSL still needs more data,
		 *	the peer sent a record which is too large.
		 */
		room = fr_dbuff_extend_lowat(NULL, tls_session->dirty_in, sizeof(my->buffer));
		if (room == 0) {
			fr_strerror_const("TLS record is too large");
			(void) fr_bio_shutdown(&my->bio);
			return fr_bio_error(BUFFER_FULL);
		}
		if (room > sizeof(my->buffer)) room = sizeof(my->buffer);

		rcode = next->read(next, packet_ctx, my->buffer, room);
		if (rcode <= 0) {
			/*
			 *	The fd bio has already shut the chain down for EOF, and for fatal errors.  That
			 *	shutdown may have run `fr_bio_tls_shutdown()`.  On EOF or a fatal error,
			 *	`fr_tls_connection_io_error()` tells the TLS connection, which runs the `failed`
			 *	callback.
			 *
			 *	The fd bio calls its `read_blocked` callback before returning `IO_WOULD_BLOCK`,
			 *	and the callback may change `errno`.
			 */
			if (rcode == fr_bio_error(IO_WOULD_BLOCK)) errno = EAGAIN;

			switch (fr_tls_connection_io_error(conn, rcode)) {
			case FR_TLS_CONNECTION_IO_RETRY:
				continue;

			/*
			 *	Blocked, or a datagram socket with no data.  Wait for the next read event.
			 */
			case FR_TLS_CONNECTION_IO_BLOCKED:
			case FR_TLS_CONNECTION_IO_OK:
			case FR_TLS_CONNECTION_IO_EOF:
			case FR_TLS_CONNECTION_IO_FATAL:
				break;
			}

			return rcode;
		}

		/*
		 *	`room` limits the read to the free space in `dirty_in`, so the copy cannot be
		 *	partial.
		 */
		(void) fr_dbuff_in_memcpy(tls_session->dirty_in, my->buffer, (size_t) rcode);
	}
}

/** Return the decrypted data which remains after the next bio reached EOF, and then return EOF
 *
 */
static ssize_t fr_bio_tls_read_eof(fr_bio_t *bio, UNUSED void *packet_ctx, void *buffer, size_t size)
{
	fr_bio_tls_t	*my = talloc_get_type_abort(bio, fr_bio_tls_t);
	int		rcode;

	while (true) {
		if (my->clean_offset < my->clean_len) return fr_bio_tls_clean_read(my, buffer, size);

		if (!fr_bio_tls_pending(my)) break;

		/*
		 *	The next bio is at EOF, so an incomplete record never completes.
		 */
		rcode = fr_bio_tls_decrypt(my);
		if (rcode < 0) return rcode;
		if (rcode == 0) break;
	}

	/*
	 *	Clear `priv_cb.eof`, so that `fr_bio_eof()` does not call `fr_bio_tls_eof()` again.
	 *	`fr_bio_eof()` then tells the previous bios that the TLS bio is at EOF.
	 */
	my->priv_cb.eof = NULL;
	fr_bio_eof(&my->bio);
	return 0;
}

/** Handle EOF from the next bio
 *
 *  When the TLS bio still holds data for the application, this function sets the read function to
 *  `fr_bio_tls_read_eof()`.  `fr_bio_tls_read_eof()` returns the remaining data, and then signals EOF.
 *
 * @return
 *	- 1 the TLS bio holds no data for the application, so `fr_bio_eof()` continues to the previous bios
 *	- 0 the TLS bio still holds data for the application
 */
static int fr_bio_tls_eof(fr_bio_t *bio)
{
	fr_bio_tls_t *my = talloc_get_type_abort(bio, fr_bio_tls_t);

	/*
	 *	Before the connection is connected, there is no application data.
	 */
	if (my->conn->state != TLS_CONNECTION_CONNECTED) return 1;

	if ((my->clean_offset == my->clean_len) && !fr_bio_tls_pending(my)) return 1;

	my->bio.read = fr_bio_tls_read_eof;

	return 0;
}


/** Disconnect the bio from the fd
 *
 *  This function runs when a shutdown of the chain completes, and when the bio is freed.  The events of the
 *  fd go away, and the application can no longer read or write.  The TLS connection is a child of the bio, so
 *  the TLS connection stays valid until the bio is freed.
 */
static int fr_bio_tls_shutdown(fr_bio_t *bio)
{
	fr_bio_tls_t *my = talloc_get_type_abort(bio, fr_bio_tls_t);

	fr_bio_tls_events_delete(my);

	my->bio.read = fr_bio_shutdown_read;
	my->bio.write = fr_bio_shutdown_write;

	return 0;
}

/** Application data cannot move until the connection is connected
 *
 *  A read or write before the `connected` callback runs gets "would block".  The write is a flush request from
 *  the fd bio, which has nothing to flush.
 */
static ssize_t fr_bio_tls_read_wait(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void *buffer, UNUSED size_t size)
{
	return fr_bio_error(IO_WOULD_BLOCK);
}

static ssize_t fr_bio_tls_write_wait_connected(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, size_t size)
{
	if (size == SIZE_MAX) return 0;

	return fr_bio_error(IO_WOULD_BLOCK);
}

/** A record arrived on the fd, so hand the record to the TLS connection
 *
 *  Reading the fd is all this function does.  Everything the record means to TLS is `fr_tls_connection_recv()`'s
 *  business.
 */
static void fr_bio_tls_el_read(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_bio_tls_t	*my = talloc_get_type_abort(uctx, fr_bio_tls_t);
	fr_bio_t	*next = fr_bio_next(&my->bio);
	ssize_t		slen;

	while (true) {
		slen = next->read(next, NULL, my->buffer, sizeof(my->buffer));
		if (slen > 0) {
			fr_tls_connection_recv(my->conn, my->buffer, (size_t) slen);
			return;
		}

		/*
		 *	The fd bio calls its `read_blocked` callback before returning `IO_WOULD_BLOCK`, and the
		 *	callback may change `errno`.
		 */
		if (slen == fr_bio_error(IO_WOULD_BLOCK)) errno = EAGAIN;

		/*
		 *	The connection records what happened, and ends itself when the result ends it.  An
		 *	interrupted read is run again.  A blocked read waits for the next read event, as an fd
		 *	which still holds a record fires the read event again.
		 */
		if (fr_tls_connection_io_error(my->conn, slen) != FR_TLS_CONNECTION_IO_RETRY) return;
	}
}

/** The fd is ready for writes
 *
 *  Run the connection state machine, which either flushes pending data, or keeps going with the next TLS
 *  state.  The event loop calls this function only after a write blocked, see `fr_bio_tls_write_wait()`.
 *
 *  `fr_tls_connection_process()` writes the rest of the encrypted records, and then checks the connection
 *  again.  The check ends a connection whose handshake finished while a record was still waiting.
 */
static void fr_bio_tls_el_write(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_bio_tls_t *my = talloc_get_type_abort(uctx, fr_bio_tls_t);

	/*
	 *	Stop the event first, as an fd which has room fires the event on every pass of the event
	 *	loop.  Writing the records which are waiting starts the event again if the fd is still full.
	 */
	if (fr_bio_tls_write_wait(my, false) < 0) {
		fr_bio_tls_failed(my, TLS_CONNECTION_FAIL_APPLICATION, 0);
		return;
	}

	my->write_blocked = false;
	fr_bio_tls_next_resume(fr_bio_next(&my->bio));

	fr_tls_connection_process(my->conn);
}

/** The fd failed
 *
 */
static void fr_bio_tls_el_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	fr_bio_tls_t *my = talloc_get_type_abort(uctx, fr_bio_tls_t);

	if (fd_errno == 0) {
		(void) fr_tls_connection_io_error(my->conn, 0);
		return;
	}

	/*
	 *	The event loop reports the error rather than leaving it in `errno`, so put it back where
	 *	`fr_tls_connection_io_error()` reads it.
	 */
	errno = fd_errno;
	(void) fr_tls_connection_io_error(my->conn, -1);
}

/** The fd is connected, so start the TLS connection
 *
 *  Create the TLS session, put the events of the fd in the event list, and start the connection state
 *  machine.  The state machine runs in one frame of the request, which `fr_tls_connection_push()` pushes.
 *  The TLS bio does the IO for the state machine.
 *
 * @return
 *	- 0 on success
 *	- <0 on error
 */
static int fr_bio_tls_handshake_start(fr_bio_tls_t *my)
{
	fr_tls_connection_t		*conn = my->conn;
	request_t			*request = conn->request;
	fr_bio_t			*next = fr_bio_next(&my->bio);
	fr_bio_fd_info_t const		*info = fr_bio_fd_info(next);

	my->fd = info->socket.fd;

	/*
	 *	The application knows more about what identifies a connection, so it can set the name before it
	 *	calls fr_bio_tls_connect().
	 */
	if (!conn->name) {
		conn->name = talloc_asprintf(conn, "%s %s", (info->socket.type == SOCK_DGRAM) ? "DTLS" : "TLS",
					     info->name ? info->name : "");
		if (!conn->name) return -1;
	}

	if (conn->client) {
		conn->tls_session = fr_tls_session_alloc_client(request, my->ssl_ctx, request);
	} else {
		conn->tls_session = fr_tls_session_alloc_server(request, my->ssl_ctx, request, my->client_cert);
	}
	if (!conn->tls_session) return -1;

	/*
	 *	Bind the DTLS cookie to the socket which the connection runs on.  The library hashes the whole
	 *	structure with a key of its own, and never reads it.
	 */
	if (info->socket.type == SOCK_DGRAM) conn->tls_session->cookie = &info->socket;

	/*
	 *	The events exist before the connection starts, so that a write which blocks during the first
	 *	round can ask for the write event.  A fd which has room fires the write event on every pass of
	 *	the event loop, so suspend the write event until it is needed.
	 */
	if (fr_event_fd_insert(my, NULL, my->el, my->fd,
			       fr_bio_tls_el_read, fr_bio_tls_el_write, fr_bio_tls_el_error, my) < 0) {
		fr_strerror_const_push("Failed adding the TLS connection to the event loop");
		return -1;
	}
	my->events = true;

	my->write_wait = true;
	if (fr_bio_tls_write_wait(my, false) < 0) {
		fr_bio_tls_events_delete(my);
		return -1;
	}

	if (fr_tls_connection_push(conn) < 0) {
		fr_bio_tls_events_delete(my);
		fr_strerror_const_push("Failed starting the TLS connection");
		return -1;
	}

	/*
	 *	Run the interpreter once, so that the first frame yields.  `unlang_interpret_mark_runnable()`
	 *	acts only on a frame which has yielded.
	 */
	(void) unlang_interpret(request, UNLANG_REQUEST_RESUME);

	/*
	 *	Run `new session { ... }` and, for a client, `load session`.  A server then waits for the
	 *	ClientHello.  A client has to send the ClientHello.
	 */
	fr_tls_connection_wake(conn);

	return 0;
}

/** Find the TLS bio from the fd bio
 *
 *  The TLS bio is always the bio before the fd bio.
 */
static fr_bio_tls_t *fr_bio_tls_from_fd(fr_bio_t *fd_bio)
{
	fr_bio_t *prev = fr_bio_prev(fd_bio);

	if (!prev) return NULL;

	return talloc_get_type_abort(prev, fr_bio_tls_t);
}

/** The fd is connected
 *
 */
static void fr_bio_tls_fd_connected(fr_bio_t *fd_bio)
{
	fr_bio_tls_t *my = fr_bio_tls_from_fd(fd_bio);

	if (!my) return;

	if (fr_bio_tls_handshake_start(my) < 0) fr_bio_tls_failed(my, TLS_CONNECTION_FAIL_APPLICATION, 0);
}

/** The fd failed to connect
 *
 *  The fd bio has recorded the error, and shuts down.
 */
static void fr_bio_tls_fd_error(fr_bio_t *fd_bio)
{
	fr_bio_tls_t *my = fr_bio_tls_from_fd(fd_bio);

	if (!my) return;

	fr_bio_tls_failed(my, TLS_CONNECTION_FAIL_SYSCALL, fr_bio_fd_info(fd_bio)->connect_errno);
}

/** Cancel the request, and then run the common bio destructor
 *
 *  The request has a frame which points at the TLS connection, and the TLS connection is freed with the bio.
 *  Cancelling the request unwinds the frame first, so the interpreter never runs a frame which points at a
 *  freed connection.
 */
static int fr_bio_tls_destructor(fr_bio_tls_t *my)
{
	unlang_interpret_signal(my->conn->request, FR_SIGNAL_CANCEL);

	return fr_bio_destructor((fr_bio_t *) my);
}

/** Allocate a TLS bio
 *
 *  The bio and the TLS connection are allocated from the request, so they cannot outlive the request.  The
 *  request must already use an interpreter, as the connection state machine runs in a frame of the request,
 *  and the bio takes the event list from the interpreter.  After allocating the bio, call `fr_bio_tls_connect()`.
 *
 *  Use `fr_bio_cb_set()` to set the callbacks:
 *
 *  - `connected` is called when the connection can carry application data.  The fd events are gone, and the
 *    application can read and write the bio.
 *  - `failed` is called when the connection fails, for any reason, at any time.  The reason is in
 *    `conn->failed`, and `conn->error` holds the errno for system call failures.  The callback must not free
 *    the bio, as the callback can run from inside a read or a write on the bio.  The callback can instead
 *    arrange for the application to free the bio later, for example from the event loop.
 *
 * @param[in] request	to allocate the bio and the connection from, and which runs the connection.
 * @param[in] next	the fd bio which carries the encrypted records.
 * @param[in] ssl_ctx	to create the TLS session from.
 * @param[in] client	true to connect to a server, false to accept a connection.
 * @param[in] client_cert for a server, whether to require a client certificate.  Ignored for a client.
 * @return
 *	- the TLS bio
 *	- `NULL` when the next bio is not an fd bio, when the request has no event list, or when an allocation
 *	  fails
 */
fr_bio_tls_t *fr_bio_tls_alloc(request_t *request, fr_bio_t *next, SSL_CTX *ssl_ctx, bool client, bool client_cert)
{
	fr_bio_tls_t	*my;
	fr_event_list_t	*el = unlang_interpret_event_list(request);

	if (!el) {
		fr_strerror_const("The request does not have an event list");
		return NULL;
	}

	if (!talloc_check_name(next, "fr_bio_fd_t")) {
		fr_strerror_const("The next bio must be an fd bio");
		return NULL;
	}

	my = talloc_zero(request, fr_bio_tls_t);
	if (!my) return NULL;

	my->el = el;
	my->ssl_ctx = ssl_ctx;
	my->client = client;
	my->client_cert = client_cert;
	my->fd = fr_bio_fd_info(next)->socket.fd;

	my->conn = fr_tls_connection_alloc(my, el->tl, fr_bio_tls_conn_write,
					   fr_bio_tls_conn_connected, fr_bio_tls_conn_close);
	if (!my->conn) {
		talloc_free(my);
		return NULL;
	}
	my->conn->uctx = my;
	my->conn->client = client;
	my->conn->request = request;

	my->bio.read = fr_bio_tls_read_wait;
	my->bio.write = fr_bio_tls_write_wait_connected;

	my->priv_cb.eof = fr_bio_tls_eof;
	my->priv_cb.shutdown = fr_bio_tls_shutdown;
	my->priv_cb.write_blocked = fr_bio_tls_write_blocked;
	my->priv_cb.write_resume = fr_bio_tls_write_resume;

	fr_bio_chain(&my->bio, next);

	talloc_set_destructor(my, fr_bio_tls_destructor);
	return my;
}

/** The TLS connection, so the caller can set `conn->name`
 *
 */
fr_tls_connection_t *fr_bio_tls_conn(fr_bio_tls_t *my)
{
	return my->conn;
}

/** Take the connection through every state which comes before application data
 *
 *  The connection connects the fd bio, runs the TLS handshake, and runs
 *  the policies which go with the handshake.  A stream socket can take some time to connect, and the TLS bio
 *  waits for the connect in the event list.  A datagram socket, or a socket which the caller accepted, is
 *  already connected, so the handshake starts before this function returns.
 *
 *  The caller must wait for the `connected` or `failed` callback.  A callback can run before this function
 *  returns.
 *
 * @param[in] my	the TLS bio.
 * @return
 *	- 0 the connection has started.
 *	- <0 the fd bio failed to connect.  The `failed` callback has already run.
 */
int fr_bio_tls_connect(fr_bio_tls_t *my)
{
	if (fr_bio_fd_connect_full(fr_bio_next(&my->bio), my->el,
				   fr_bio_tls_fd_connected, fr_bio_tls_fd_error, NULL, NULL) < 0) {
		return -1;
	}

	return 0;
}
