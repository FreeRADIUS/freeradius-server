/*
 *	We have an error, so we have common error handling code.
 */
switch (errno) {
case EINTR:
	/*
	 *	Try a few times before giving up.
	 */
	tries++;
	if (tries <= my->max_tries) goto retry;
	return fr_bio_error(IO);

#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
case EWOULDBLOCK:
#endif
case EAGAIN:
	/*
	 *	The operation would block, return that.
	 */
	if (!my->info.flag_blocked) {
		my->info.flag_blocked = true;

		if (my->cb.flag_blocked) {
			rcode = my->cb.flag_blocked((fr_bio_t *) my);
			if (rcode < 0) return rcode;
		}
	}
	return fr_bio_error(IO_WOULD_BLOCK);

	/*
	 *	We're reading / writing a connected UDP socket, and the other end has gone away.
	 */
case ENOTCONN:

	/*
	 *	The other end of a socket has closed the connection.
	 */
case ECONNRESET:

	/*
	 *	The other end of a pipe has closed the connection.
	 */
case EPIPE:
	/*
	 *	The connection is no longer usable, close it.
	 */
	fr_bio_eof(&my->bio);
	return 0;

#ifdef FR_FD_BIO_EMSGSIZE
	/*
	 *	PMTU has been exceeded.  Return a generic IO error.
	 *
	 *	@todo - do this only for connected UDP sockets.
	 */
	case EMSGSIZE:
		return fr_bio_error(IO);
#endif

default:
	/*
	 *	Some other error, it's fatal.
	 */
	break;
}

/*
 *	Shut down the BIO.  It's no longer useable.
 */
(void) fr_bio_shutdown(&my->bio);
