/*
 * $Id$
 *
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
 *
 * Copyright 2001,2002  Google, Inc.
 * Copyright 2005,2006 TRI-D Systems, Inc.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include "extern.h"

#include <inttypes.h>
#include <pthread.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

/*
 * Return some random bytes.
 */
void
otp_get_random(char *rnd_data, size_t len)
{
  size_t bytes_read = 0;

  while (bytes_read < len) {
    int n;
    unsigned int bytes_left = len - bytes_read;
    uint32_t r = fr_rand();

    n = sizeof(r) < bytes_left ? sizeof(r) : bytes_left;
    (void) memcpy(rnd_data + bytes_read, &r, n);
    bytes_read += n;
  }
}

/*
 * Return a random challenge.
 * NOTE: This is really cryptocard-specific (automatic ASCII conversion
 *        and null termination).
 */
void
otp_async_challenge(char challenge[OTP_MAX_CHALLENGE_LEN + 1], int len)
{
  unsigned char rawchallenge[OTP_MAX_CHALLENGE_LEN];
  int i;

  otp_get_random(rawchallenge, len);

  /* Convert the raw bytes to ASCII decimal. */
  for (i = 0; i < len; ++i)
    challenge[i] = '0' + rawchallenge[i] % 10;
  challenge[len] = '\0';
}

/* ascii to hex; returns HEXlen on success or -1 on error */
int
otp_a2x(const char *s, unsigned char x[])
{
  unsigned i;
  size_t l = strlen(s);

  /*
   * We could just use sscanf, but we do this a lot, and have very
   * specific needs, and it's easy to implement, so let's go for it!
   */
  for (i = 0; i < l / 2; ++i) {
    unsigned int n[2];
    int j;

    /* extract 2 nibbles */
    n[0] = *s++;
    n[1] = *s++;

    /* verify range */
    for (j = 0; j < 2; ++j) {
      if ((n[j] >= '0' && n[j] <= '9') ||
          (n[j] >= 'A' && n[j] <= 'F') ||
          (n[j] >= 'a' && n[j] <= 'f'))
        continue;
      return -1;
    }

    /* convert ASCII hex digits to numeric values */
    n[0] -= '0';
    n[1] -= '0';
    if (n[0] > 9) {
      if (n[0] > 'F' - '0')
        n[0] -= 'a' - '9' - 1;
      else
        n[0] -= 'A' - '9' - 1;
    }
    if (n[1] > 9) {
      if (n[1] > 'F' - '0')
        n[1] -= 'a' - '9' - 1;
      else
        n[1] -= 'A' - '9' - 1;
    }

    /* store as octets */
    x[i]  = n[0] << 4;
    x[i] += n[1];
  } /* for (each octet) */

  return l/2;
}

/* Character maps for generic hex and vendor specific decimal modes */
static const char otp_hex_conversion[]         = "0123456789abcdef";
#if 0	/* just for reference */
static const char otp_cc_dec_conversion[]      = "0123456789012345";
static const char otp_snk_dec_conversion[]     = "0123456789222333";
static const char otp_sc_friendly_conversion[] = "0123456789ahcpef";
#endif

/*
 * hex to ascii
 * Fills in s, which must point to at least len*2+1 bytes of space.
 */
void
otp_x2a(const unsigned char *x, size_t len, char *s)
{
  unsigned i;

  for (i = 0; i < len; ++i) {
    unsigned n[2];

    n[0] = (x[i] >> 4) & 0x0f;
    n[1] = x[i] & 0x0f;
    s[2 * i + 0] = otp_hex_conversion[n[0]];
    s[2 * i + 1] = otp_hex_conversion[n[1]];
  }
  s[2 * len] = '\0';
}

/* guaranteed initialization */
void
_otp_pthread_mutex_init(pthread_mutex_t *mutexp,
                        const pthread_mutexattr_t *attr, const char *caller)
{
  int rc;

  if ((rc = pthread_mutex_init(mutexp, attr))) {
    (void) radlog(L_ERR|L_CONS,
                  "rlm_otp: %s: pthread_mutex_init: %s", caller, strerror(rc));
    exit(1);
  }
}

/* guaranteed lock */
void
_otp_pthread_mutex_lock(pthread_mutex_t *mutexp, const char *caller)
{
  int rc;

  if ((rc = pthread_mutex_lock(mutexp))) {
    (void) radlog(L_ERR|L_CONS,
                  "rlm_otp: %s: pthread_mutex_lock: %s", caller, strerror(rc));
    exit(1);
  }
}

/* guaranteed trylock */
int
_otp_pthread_mutex_trylock(pthread_mutex_t *mutexp, const char *caller)
{
  int rc;

  rc = pthread_mutex_trylock(mutexp);
  if (rc && rc != EBUSY) {
    (void) radlog(L_ERR|L_CONS,
                  "rlm_otp: %s: pthread_mutex_trylock: %s",
                  caller, strerror(rc));
    exit(1);
  }

  return rc;
}

/* guaranteed unlock */
void
_otp_pthread_mutex_unlock(pthread_mutex_t *mutexp, const char *caller)
{
  int rc;

  if ((rc = pthread_mutex_unlock(mutexp))) {
    (void) radlog(L_ERR|L_CONS,
                  "rlm_otp: %s: pthread_mutex_unlock: %s",
                  caller, strerror(rc));
    exit(1);
  }
}
