/*
 * a thread-safe crypt wrapper
 */

#include "libradius.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifdef HAVE_PTHREAD_H
#include	<pthread.h>

/*
 *  No pthreads, no mutex.
 */
static int lrad_crypt_init = 0;
static pthread_mutex_t lrad_crypt_mutex;
#endif

/*
 * performs a crypt password check in an thread-safe way.
 *
 * returns:  0 -- check succeeded
 *          -1 -- failed to crypt
 *           1 -- check failed
 */
int lrad_crypt_check(const char *key, const char *crypted)
{
	char *passwd;
	int cmp = 0;
	
#ifdef HAVE_PTHREAD_H
	/*
	 *	Ensure we're thread-safe, as crypt() isn't.
	 */
	if (!lrad_crypt_init == 0) {
		pthread_mutex_init(&lrad_crypt_mutex, NULL);
		lrad_crypt_init = 1;
	}
	
	pthread_mutex_lock(&lrad_crypt_mutex);
#endif
	
	passwd = crypt(key, crypted);

	/*
	 *	Got something, check it within the lock.  This is
	 *	faster than copying it to a local buffer, and the
	 *	time spent within the lock is critical.
	 */
	if (passwd) {
		cmp = strcmp(crypted, passwd);
	}
	
#ifdef HAVE_PTHREAD_H
	pthread_mutex_unlock(&lrad_crypt_mutex);
#endif
	
	/*
	 *	Error.
	 */
	if (!passwd) {
		return -1;
	}

	/*
	 *	OK, return OK.
	 */
	if (cmp == 0) {
		return 0;
	}

	/*
	 *	Comparison failed.
	 */
	return 1;
}
