/*
 * x99_util.c	
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
 */

#ifdef FREERADIUS
#include "radiusd.h"
#endif
#include "x99.h"

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


/* Card name to int mappings */
static struct {
    const char *name;
    uint32_t id;
} card[] = {
    { "x9.9",             CRYPTOCARD_H8_RC },
    { "generic",          CRYPTOCARD_H8_RC },

    { "cryptocard-h8-rc", CRYPTOCARD_H8_RC },
    { "cryptocard-d8-rc", CRYPTOCARD_D8_RC },
    { "cryptocard-h7-rc", CRYPTOCARD_H7_RC },
    { "cryptocard-d7-rc", CRYPTOCARD_D7_RC },
    { "cryptocard-h8-es", CRYPTOCARD_H8_ES },
    { "cryptocard-d8-es", CRYPTOCARD_D8_ES },
    { "cryptocard-h7-es", CRYPTOCARD_H7_ES },
    { "cryptocard-d7-es", CRYPTOCARD_D7_ES },
    { "cryptocard-h8-rs", CRYPTOCARD_H8_RS },
    { "cryptocard-d8-rs", CRYPTOCARD_D8_RS },
    { "cryptocard-h7-rs", CRYPTOCARD_H7_RS },
    { "cryptocard-d7-rs", CRYPTOCARD_D7_RS },

    { NULL, 0 }				/* end of list */
};


/*
 * Return a random challenge.
 * fd must be either -1 or an open fd to the random device.
 * challenge is filled in on successful return (must be size len+1).
 * Returns 0 on success, -1 on failure.
 */
int
x99_get_challenge(int fd, char *challenge, int len)
{
    unsigned char rawchallenge[MAX_CHALLENGE_LEN];
    int i;

    if (fd == -1) {
	if ((fd = open(DEVURANDOM, O_RDONLY)) == -1) {
	    x99_log(X99_LOG_ERR, "error opening %s: %s", DEVURANDOM,
		    strerror(errno));
	    return -1;
	}
    }

    if (x99_get_random(fd, rawchallenge, len) == -1) {
	x99_log(X99_LOG_ERR, "failed to obtain random data");
	return -1;
    }
    /* Convert the raw bytes to a decimal string. */
    for (i = 0; i < len; ++i)
	challenge[i] = '0' + rawchallenge[i] % 10;
    challenge[i] = '\0';

    return 0;
}

/*
 * Return some number of random bytes.
 * rnd_data must be allocated by the caller.
 * Returns 0 on success, -1 on failure, rnd_data is filled in.
 */
int
x99_get_random(int fd, unsigned char *rnd_data, int req_bytes)
{
    int bytes_read = 0;

    while (bytes_read < req_bytes) {
	int n;

	n = read(fd, rnd_data + bytes_read, req_bytes - bytes_read);
	if (n <= 0) {
	    x99_log(X99_LOG_ERR, "x99_get_random: error reading from %s: %s",
		    DEVURANDOM, strerror(errno));
	    return -1;
	}
	bytes_read += n;
    }

    return 0;
}


/*
 * Convert the ASCII string representation of a DES key to raw octets.
 * keyblock is filled in.  Returns 0 on success, -1 otherwise.
 */
int
x99_string_to_keyblock(const char *s, des_cblock keyblock)
{
    int i;

    if (s == NULL || strlen(s) < 16)
	return -1;

    /*
     * We could just use sscanf, but we do this a lot, and have very
     * specific needs, and it's easy to implement, so let's go for it!
     */
    for (i = 0; i < 8; ++i) {
	unsigned int n[2];

	n[0] = *s++ - '0';
	n[1] = *s++ - '0';
	if (n[0] > 9) {
	    n[0] -= 'a' - '9' - 1;
	}
	if (n[1] > 9) {
	    n[1] -= 'a' - '9' - 1;
	}

	keyblock[i]  = n[0] << 4;
	keyblock[i] += n[1];
    }
    return 0;
}


/* Character maps for generic hex and vendor specific decimal modes */
const char x99_hex_conversion[]         = "0123456789abcdef";
const char x99_cc_dec_conversion[]      = "0123456789012345";
const char x99_snk_dec_conversion[]     = "0123456789222333";
const char x99_sc_friendly_conversion[] = "0123456789ahcpef";

/*
 * Convert a DES keyblock to an ASCII string.
 * Fills in s, which must point to at least 17 bytes of space.
 * Note that each octet expands into 2 hex digits in ASCII (0xAA -> 0x4141);
 * add a NULL string terminator and you get the 17 byte requirement.
 */
void
x99_keyblock_to_string(char *s, const des_cblock keyblock,
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
 * fillin user_info from our database (key file)
 * returns 0 on success, -1 for user not found, -2 for other errors.
 */
int
x99_get_user_info(const char *pwdfile, const char *username,
		  x99_user_info_t *user_info)
{
    FILE *fp;
    char s[80];
    char *p, *q;
    int found, i;
    struct stat st;

    /* Verify permissions first. */
    if (stat(pwdfile, &st) != 0) {
	x99_log(X99_LOG_ERR, "x99_get_user_info: pwdfile %s error: %s",
		pwdfile, strerror(errno));
	return -2;
    }
    if ((st.st_mode & (S_IXUSR|S_IRWXG|S_IRWXO)) != 0) {
	x99_log(X99_LOG_ERR,
		"x99_get_user_info: pwdfile %s has loose permissions", pwdfile);
	return -2;
    }

    if ((fp = fopen(pwdfile, "r")) == NULL) {
	x99_log(X99_LOG_ERR, "x99_get_user_info: error opening %s: %s",
		pwdfile, strerror(errno));
	return -2;
    }

    /*
     * Find the requested user.
     * Add a ':' to the username to make sure we don't match shortest prefix.
     */
    p = malloc(strlen(username) + 2);
    if (!p) {
	x99_log(X99_LOG_ERR, "x99_get_user_info: out of memory");
	return -2;
    }
    (void) sprintf(p, "%s:", username);
    found = 0;
    while (!feof(fp)) {
	if (fgets(s, sizeof(s), fp) == NULL) {
	    if (!feof(fp)) {
		x99_log(X99_LOG_ERR,
			"x99_get_user_info: error reading from %s: %s",
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
	x99_log(X99_LOG_AUTH, "x99_get_user_info: [%s] not found in %s",
		username, pwdfile);
	return -1;
    }

    /* Found him, skip to next field (card). */
    if ((p = strchr(s, ':')) == NULL) {
	x99_log(X99_LOG_ERR,
		"x99_get_user_info: invalid format for [%s] in %s",
		username, pwdfile);
	return -2;
    }
    p++;
    /* strtok() */
    if ((q = strchr(p, ':')) == NULL) {
	x99_log(X99_LOG_ERR,
		"x99_get_user_info: invalid format for [%s] in %s",
		username, pwdfile);
	return -2;
    }
    *q++ = '\0';
    /* p: card_type, q: key */

    /* Match against card types. */
    found = 0;
    for (i = 0; card[i].name; ++i) {
	if (!strcasecmp(p, card[i].name)) {
	    found = 1;
	    user_info->card_id = card[i].id;
	    break;
	}
    }
    if (!found) {
	x99_log(X99_LOG_ERR,
		"x99_get_user_info: unknown card %s for [%s] in %s",
		p, username, pwdfile);
	return -2;
    }

    if (!(strlen(q) == 16 || (strlen(q) == 17 && q[16] == '\n'))) {
	/* 8 octets + possible trailing newline */
	x99_log(X99_LOG_ERR, "x99_get_user_info: invalid key for [%s] in %s",
		username, pwdfile);
	return -2;
    }

    /* Convert the key from ASCII to a keyblock. (+translate error code) */
    return x99_string_to_keyblock(q, user_info->keyblock) * -2;
}

