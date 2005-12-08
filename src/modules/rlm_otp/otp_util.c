/*
 * otp_util.c	
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001,2002  Google, Inc.
 * Copyright 2005 TRI-D Systems, Inc.
 */

#include "otp.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/des.h> /* des_cblock */


static const char rcsid[] = "$Id$";


/*
 * Return some number of random bytes.
 * rnd_data must be allocated by the caller.
 * Returns 0 on success, -1 on failure, rnd_data is filled in.
 */
int
otp_get_random(
#ifdef FREERADIUS
#ifdef __GNUC__
__attribute__ ((unused))
#endif
#endif
               int fd,
               unsigned char *rnd_data, int req_bytes,
#ifdef FREERADIUS
#ifdef __GNUC__
__attribute__ ((unused))
#endif
#endif
               const char *log_prefix)
{
  int bytes_read = 0;

  while (bytes_read < req_bytes) {
    int n;
#ifdef FREERADIUS
    /* Use goofy libradius interface to avoid fd init issues. */
    unsigned int bytes_left = req_bytes - bytes_read;
    uint32_t r = lrad_rand();

    n = sizeof(r) < bytes_left ? sizeof(r) : bytes_left;
    memcpy(rnd_data + bytes_read, &r, n);
#else
    n = read(fd, rnd_data + bytes_read, req_bytes - bytes_read);
    if (n <= 0) {
      otp_log(OTP_LOG_ERR, "%s: %s: error reading from %s: %s",
              log_prefix, __func__, OTP_DEVURANDOM, strerror(errno));
      return -1;
    }
#endif /* !FREERADIUS */

    bytes_read += n;
  }

  return 0;
}


/*
 * Return a random challenge.
 * fd must be either -1 or an open fd to the random device.
 * challenge is filled in on successful return (must be at least size len+1).
 * Returns 0 on success, -1 on failure.
 * NOTE: This is really cryptocard-specific (automatic ASCII conversion
 * and null termination).
 */
int
otp_async_challenge(int fd, char challenge[OTP_MAX_CHALLENGE_LEN + 1], int len,
                    const char *log_prefix)
{
  unsigned char rawchallenge[OTP_MAX_CHALLENGE_LEN];
  int i;

  if (fd == -1) {
    if ((fd = open(OTP_DEVURANDOM, O_RDONLY)) == -1) {
      otp_log(OTP_LOG_ERR, "%s: %s: error opening %s: %s",
              log_prefix, __func__, OTP_DEVURANDOM, strerror(errno));
      return -1;
    }
  }

  if (otp_get_random(fd, rawchallenge, len, log_prefix) == -1) {
    otp_log(OTP_LOG_ERR, "%s: %s: failed to obtain random data",
            log_prefix, __func__);
    return -1;
  }
  /* Convert the raw bytes to ASCII decimal. */
  for (i = 0; i < len; ++i)
    challenge[i] = '0' + rawchallenge[i] % 10;
  challenge[len] = '\0';

  return 0;
}


/*
 * Convert the ASCII string representation of a key to raw octets.
 * keyblock is filled in.  Returns keylen on success, -1 otherwise.
 */
ssize_t
otp_keystring2keyblock(const char *s, unsigned char keyblock[OTP_MAX_KEY_LEN])
{
  unsigned i;
  size_t l = strlen(s);

  /* overflow sanity check */
  if (l > OTP_MAX_KEY_LEN * 2)
    return -1;

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
    keyblock[i]  = n[0] << 4;
    keyblock[i] += n[1];
  } /* for (each octet) */

  return l/2;
}


/* Character maps for generic hex and vendor specific decimal modes */
const char otp_hex_conversion[]         = "0123456789abcdef";
const char otp_cc_dec_conversion[]      = "0123456789012345";
const char otp_snk_dec_conversion[]     = "0123456789222333";
const char otp_sc_friendly_conversion[] = "0123456789ahcpef";

/*
 * Convert a keyblock to an ASCII string.
 * Fills in s, which must point to at least len*2+1 bytes of space.
 */
char *
otp_keyblock2keystring(char *s, const unsigned char *keyblock, size_t len,
                       const char conversion[17])
{
  unsigned i;

  for (i = 0; i < len; ++i) {
    unsigned n[2];

    n[0] = (keyblock[i] >> 4) & 0x0f;
    n[1] = keyblock[i] & 0x0f;
    s[2 * i + 0] = conversion[n[0]];
    s[2 * i + 1] = conversion[n[1]];
  }
  s[2 * len] = '\0';

  return s;
}


/*
 * fill in card_info from our database (key file)
 * returns 0 on success, -1 for user not found, -2 for other errors.
 * TODO: mmap and use pointers in otp_card_info_t?
 */
int
otp_get_card_info(const char *pwdfile, const char *username,
                  otp_card_info_t *card_info, const char *log_prefix)
{
  FILE *fp;
  char s[80];
  char *p, *q;
  int found;
  struct stat st;

  /* Verify permissions first. */
  if (stat(pwdfile, &st) != 0) {
    otp_log(OTP_LOG_ERR, "%s: %s: pwdfile %s error: %s",
            log_prefix, __func__, pwdfile, strerror(errno));
    return -2;
  }
  if ((st.st_mode & (S_IXUSR|S_IRWXG|S_IRWXO)) != 0) {
    otp_log(OTP_LOG_ERR, "%s: %s: pwdfile %s has loose permissions",
            log_prefix, __func__, pwdfile);
    return -2;
  }

  if ((fp = fopen(pwdfile, "r")) == NULL) {
    otp_log(OTP_LOG_ERR, "%s: %s: error opening %s: %s", log_prefix, __func__,
            pwdfile, strerror(errno));
    return -2;
  }

  /*
   * Find the requested user.
   * Add a ':' to the username to make sure we don't match shortest prefix.
   */
  p = malloc(strlen(username) + 2);
  if (!p) {
    otp_log(OTP_LOG_CRIT, "%s: %s: out of memory", log_prefix, __func__);
    return -2;
  }
  (void) sprintf(p, "%s:", username);
  found = 0;
  while (!feof(fp)) {
    if (fgets(s, sizeof(s), fp) == NULL) {
      if (!feof(fp)) {
        otp_log(OTP_LOG_ERR, "%s: %s: error reading from %s: %s",
                log_prefix, __func__, pwdfile, strerror(errno));
        (void) fclose(fp);
        free(p);
        return -2;
      }
    } else if (!strncmp(s, p, strlen(p))) {
      found = 1;
      break;
    }
  }
  (void) fclose(fp);
  free(p);
  if (!found) {
    otp_log(OTP_LOG_AUTH, "%s: %s: [%s] not found in %s", log_prefix, __func__,
            username, pwdfile);
    return -1;
  }

  /* Found him, skip to next field (card). */
  if ((p = strchr(s, ':')) == NULL) {
    otp_log(OTP_LOG_ERR, "%s: %s: invalid format for [%s] in %s",
            log_prefix, __func__, username, pwdfile);
    return -2;
  }
  p++;
  if ((q = strchr(p, ':')) == NULL) {
    otp_log(OTP_LOG_ERR, "%s: %s: invalid format for [%s] in %s",
            log_prefix, __func__, username, pwdfile);
    return -2;
  }
  *q++ = '\0';
  /* p: card_type, q: key */

  /*
   * Unfortunately, we can't depend on having strl*, which would allow
   * us to check for buffer overflow and copy the string in the same step.
   * TODO: implement our own strlcpy().
   */
  if (strlen(p) > OTP_MAX_CARDNAME_LEN)
    otp_log(OTP_LOG_ERR, "%s: %s: invalid format for [%s] in %s",
            log_prefix, __func__, username, pwdfile);
  (void) strcpy(card_info->card, p);

  p = q;
  /* optional PIN field */
  if ((q = strchr(p, ':')) == NULL)
    card_info->pin[0] = '\0';
  else
    *q++ = '\0';
  /* p: key, q: PIN */

  {
    size_t l = strlen(p);

    /* OTP_MAX_KEY_LEN keys with trailing newline won't work */
    if (l > OTP_MAX_KEY_LEN * 2) {
      otp_log(OTP_LOG_ERR, "%s: %s: invalid format for [%s] in %s",
              log_prefix, __func__, username, pwdfile);
      return -2;
    }
    (void) strcpy(card_info->keystring, p);
    /* strip possible trailing newline */
    if (l && card_info->keystring[l - 1] == '\n')
      card_info->keystring[--l] = '\0';
    /* check for empty key or odd len */
    if (!l || l & 1) {
      otp_log(OTP_LOG_ERR, "%s: %s: invalid format for [%s] in %s",
              log_prefix, __func__, username, pwdfile);
      return -2;
    }
  }

  if (q) {
    size_t l = strlen(q);

    if (l > OTP_MAX_PIN_LEN) {
      otp_log(OTP_LOG_ERR, "%s: %s: invalid format for [%s] in %s",
              log_prefix, __func__, username, pwdfile);
    }
    (void) strcpy(card_info->pin, q);
    /* strip possible trailing newline */
    if (l && card_info->pin[l - 1] == '\n')
      card_info->pin[--l] = '\0';
  }

  return 0;
}

