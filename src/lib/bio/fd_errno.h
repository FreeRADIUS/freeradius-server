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
	return 0;

#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
case EWOULDBLOCK:
#endif
case EAGAIN:
	/*
	 *	The operation would block, return that.
	 */
	if (!my->info.flag_blocked) {
		if (my->cb.flag_blocked) {
			rcode = my->cb.flag_blocked((fr_bio_t *) my);
			if (rcode < 0) return rcode;

			my->info.flag_blocked = true;
		}
	}
	return fr_bio_error(IO_WOULD_BLOCK);

default:
	/*
	 *	Some other error, it's fatal.
	 */
	break;
}
