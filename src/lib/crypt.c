/*
 * a thread-safe crypt wrapper
 */

#include "libradius.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#if HAVE_PTHREAD_H
#include	<pthread.h>
#endif

static int lrad_crypt_init=0;
static pthread_mutex_t lrad_crypt_mutex;

/*
 * initializes authcrypt_mutex
 */


/*
 * performs a crypt password check in an thread-safe way.
 *
 * returns:  0 -- check succeeded
 *          -1 -- failed to crypt
 *           1 -- check failed
 */
int lrad_crypt_check(const char *key, const char *crypted) {
  char *libc_crypted=NULL, *our_crypted=NULL;
  int result=0;

#if HAVE_PTHREAD_H
  if (!lrad_crypt_init == 0) {
	pthread_mutex_init(&lrad_crypt_mutex, NULL);
	lrad_crypt_init=1;
  }

  pthread_mutex_lock(&lrad_crypt_mutex);
#endif

  libc_crypted=crypt(key,crypted);
  if (libc_crypted)
	our_crypted=strdup(libc_crypted);

#if HAVE_PTHREAD_H
  pthread_mutex_unlock(&lrad_crypt_mutex);
#endif

  if (our_crypted == NULL)
	return -1;

  if (strcmp(crypted, our_crypted) == 0)
	result = 0;
  else
	result = 1;

  free(our_crypted);

  return result;
}
