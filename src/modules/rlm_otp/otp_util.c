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
 * Copyright 2005 Frank Cusack
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
otp_get_random(int fd, unsigned char *rnd_data, int req_bytes)
{
    int bytes_read = 0;

    while (bytes_read < req_bytes) {
	int n;

	n = read(fd, rnd_data + bytes_read, req_bytes - bytes_read);
	if (n <= 0) {
	    otp_log(OTP_LOG_ERR, "otp_get_random: error reading from %s: %s",
		    OTP_DEVURANDOM, strerror(errno));
	    return -1;
	}
	bytes_read += n;
    }

    return 0;
}


/*
 * Return a random challenge.
 * fd must be either -1 or an open fd to the random device.
 * challenge is filled in on successful return (must be size len+1).
 * Returns 0 on success, -1 on failure.
 */
int
otp_get_challenge(int fd, char *challenge, int len)
{
    unsigned char rawchallenge[OTP_MAX_CHALLENGE_LEN];
    int i;

    if (fd == -1) {
	if ((fd = open(OTP_DEVURANDOM, O_RDONLY)) == -1) {
	    otp_log(OTP_LOG_ERR, "otp_get_challenge: error opening %s: %s",
		    OTP_DEVURANDOM, strerror(errno));
	    return -1;
	}
    }

    if (otp_get_random(fd, rawchallenge, len) == -1) {
	otp_log(OTP_LOG_ERR, "otp_get_challenge: failed to obtain random data");
	return -1;
    }
    /* Convert the raw bytes to a decimal string. */
    for (i = 0; i < len; ++i)
	challenge[i] = '0' + rawchallenge[i] % 10;
    challenge[i] = '\0';

    return 0;
}


/*
 * Convert the ASCII string representation of a key to raw octets.
 * keyblock is filled in.  Returns 0 on success, -1 otherwise.
 */
int
otp_keystring2keyblock(const char *s, unsigned char keyblock[])
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
	keyblock[i]  = n[0] << 4;
	keyblock[i] += n[1];
    }
    return 0;
}


/* Character maps for generic hex and vendor specific decimal modes */
const char otp_hex_conversion[]         = "0123456789abcdef";
const char otp_cc_dec_conversion[]      = "0123456789012345";
const char otp_snk_dec_conversion[]     = "0123456789222333";
const char otp_sc_friendly_conversion[] = "0123456789ahcpef";

/*
 * Convert a DES keyblock to an ASCII string.
 * Fills in s, which must point to at least 17 bytes of space.
 * Note that each octet expands into 2 hex digits in ASCII (0xAA -> 0x4141);
 * add a NULL string terminator and you get the 17 byte requirement.
 */
void
otp_keyblock2keystring(char *s, const des_cblock keyblock,
		       const char conversion[17])
{
    int i;

    for (i = 0; i < 8; ++i) {
	unsigned n[2];

	n[0] = (keyblock[i] >> 4) & 0x0f;
	n[1] = keyblock[i] & 0x0f;
	s[2 * i + 0] = conversion[n[0]];
	s[2 * i + 1] = conversion[n[1]];
    }
    s[16] = '\0';
}


/*
 * fill in user_info from our database (key file)
 * returns 0 on success, -1 for user not found, -2 for other errors.
 * TODO: mmap and use pointers in otp_user_info_t?
 */
int
otp_get_user_info(const char *pwdfile, const char *username,
		  otp_user_info_t *user_info)
{
    FILE *fp;
    char s[80];
    char *p, *q;
    int found;
    struct stat st;

    /* Verify permissions first. */
    if (stat(pwdfile, &st) != 0) {
	otp_log(OTP_LOG_ERR, "otp_get_user_info: pwdfile %s error: %s",
		pwdfile, strerror(errno));
	return -2;
    }
    if ((st.st_mode & (S_IXUSR|S_IRWXG|S_IRWXO)) != 0) {
	otp_log(OTP_LOG_ERR,
		"otp_get_user_info: pwdfile %s has loose permissions", pwdfile);
	return -2;
    }

    if ((fp = fopen(pwdfile, "r")) == NULL) {
	otp_log(OTP_LOG_ERR, "otp_get_user_info: error opening %s: %s",
		pwdfile, strerror(errno));
	return -2;
    }

    /*
     * Find the requested user.
     * Add a ':' to the username to make sure we don't match shortest prefix.
     */
    p = malloc(strlen(username) + 2);
    if (!p) {
	otp_log(OTP_LOG_CRIT, "otp_get_user_info: out of memory");
	return -2;
    }
    (void) sprintf(p, "%s:", username);
    found = 0;
    while (!feof(fp)) {
	if (fgets(s, sizeof(s), fp) == NULL) {
	    if (!feof(fp)) {
		otp_log(OTP_LOG_ERR,
			"otp_get_user_info: error reading from %s: %s",
			pwdfile, strerror(errno));
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
#if 0
	/* Noisy ... let the caller report this. */
	otp_log(OTP_LOG_AUTH, "otp_get_user_info: [%s] not found in %s",
		username, pwdfile);
#endif
	return -1;
    }

    /* Found him, skip to next field (card). */
    if ((p = strchr(s, ':')) == NULL) {
	otp_log(OTP_LOG_ERR,
		"otp_get_user_info: invalid format for [%s] in %s",
		username, pwdfile);
	return -2;
    }
    p++;
    if ((q = strchr(p, ':')) == NULL) {
	otp_log(OTP_LOG_ERR,
		"otp_get_user_info: invalid format for [%s] in %s",
		username, pwdfile);
	return -2;
    }
    *q++ = '\0';
    /* p: card_type, q: key */

    /*
     * Unfortunately, we can't depend on having strl*, which would allow
     * us to check for buffer overflow and copy the string in the same step.
     * TODO: implement our own strlcpy().
     */
    if (strlen(p) > OTP_MAX_CARDNAME_LEN) {
	otp_log(OTP_LOG_ERR,
		"otp_get_user_info: invalid format for [%s] in %s",
		username, pwdfile);
    }
    (void) strcpy(user_info->card, p);

    p = q;
    /* optional PIN field */
    if ((q = strchr(p, ':')) == NULL)
	user_info->pin[0] = '\0';
    else
	*q++ = '\0';
    /* p: key, q: PIN */

    {
	size_t l = strlen(p);

	/* OTP_MAX_KEY_LEN keys with trailing newline won't work */
	if (l > OTP_MAX_KEY_LEN * 2) {
	    otp_log(OTP_LOG_ERR,
		    "otp_get_user_info: invalid format for [%s] in %s",
		    username, pwdfile);
	}
	(void) strcpy(user_info->keystring, p);
	/* strip possible trailing newline */
	if (l && user_info->keystring[l-1] == '\n')
	    user_info->keystring[--l] = '\0';
	/* check for empty key or odd len */
	if (!l || l & 1) {
	    otp_log(OTP_LOG_ERR,
		    "otp_get_user_info: invalid format for [%s] in %s",
		    username, pwdfile);
	    return -2;
	}
    }

    if (q) {
	size_t l = strlen(q);

	if (l > OTP_MAX_PIN_LEN) {
	    otp_log(OTP_LOG_ERR,
		    "otp_get_user_info: invalid format for [%s] in %s",
		    username, pwdfile);
	}
	(void) strcpy(user_info->pin, q);
	/* strip possible trailing newline */
	if (l && user_info->pin[l-1] == '\n')
	    user_info->pin[--l] = '\0';
    }

    return 0;
}

