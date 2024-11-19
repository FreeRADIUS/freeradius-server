/*
 *	Common finalization code for the read functions.
 *
 *	This is in a header file because of "goto retry" in fd_errno.h.
 *
 *	@todo - do we want the callbacks to notify the _previous_ BIO in the chain?  That way the top-level
 *	BIO can notify the application.
 */
if (rcode > 0) {
	/*
	 *	We weren't blocked, so we're still not blocked.
	 */
	if (!my->info.read_blocked) {
		return rcode;	
	}

	/*
	 *	We were blocked.  Since we just read data, we're now unblocked.
	 */
	my->info.read_blocked = false;

	/*
	 *	Call the "resume" function when we transition to being unblocked.
	 */
	if (my->cb.read_resume) {
		int error;

		error = my->cb.read_resume((fr_bio_t *) my);
		if (error < 0) return error;
	}

	return rcode;
}

/*
 *	Don't check for rcode==0, the caller has to do that.  This is because
 *	read of 0 is different for datagram and stream sockets.
 */

#undef flag_blocked
#define flag_blocked read_blocked
#include "fd_errno.h"
