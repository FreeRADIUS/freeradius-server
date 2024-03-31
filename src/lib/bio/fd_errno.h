/*
 *	Code snippet to avoid duplication.
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
	my->flag_blocked = true;
	return fr_bio_error(IO_WOULD_BLOCK);

default:
	/*
	 *	Some other error, it's fatal.
	 */
	break;
}
