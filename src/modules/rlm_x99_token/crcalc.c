/*
 * crcalc.c
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
 * Copyright 2001,2002 Google, Inc.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/des.h>

/*
 * Convert the ASCII string representation of a DES key to raw octets.
 * keyblock is filled in.  Returns 0 on success, -1 otherwise.
 */
static
int string_to_keyblock(const char *s, des_cblock keyblock)
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
static const char ascii_conversion[]  = "0123456789abcdef";
static const char cc_dec_conversion[] = "0123456789012345";

/*
 * Convert a DES keyblock to an ASCII string.
 * Fills in s, which must point to at least 17 bytes of space.
 * Note that each octet expands into 2 hex digits in ASCII (0xAA -> 0x4141);
 * add a NULL string terminator and you get the 17 byte requirement.
 */
static
void keyblock_to_string(char *s, const des_cblock keyblock,
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


int
main(int argc, char *argv[])
{
    /* ARGSUSED */
    char ascii_key[17];
    char challenge[10], response[9], response_long[17];
    char buf[BUFSIZ];
    des_cblock keyblock;
    des_key_schedule ks;
    char *p;
    int i, rc;

    memset(ascii_key, 0, sizeof(ascii_key));

    /* get the key */
    fprintf(stdout, "Enter a DES key as 16 hex digits (spaces allowed): ");
    fgets(buf, sizeof(buf), stdin);
    buf[strlen(buf) - 1] = '\0'; /* strip '\n' */
    p = buf;

    /* setup key */
    if (buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X'))
	p += 2;
    i = 0;
    while (*p) {
	if (*p == ' ') {
	    p++;
	    continue;
	}
	if (*p < '0' || *p > '9') {
	    if (*p < 'a' || *p > 'f') {
		if (*p < 'A' || *p > 'F') {
		    fprintf(stderr, "bad key\n");
		    exit(1);
		}
	    }
	}
	if (i > 15) {
	    fprintf(stderr, "key too long\n");
	    exit(1);
	}
	ascii_key[i++] = tolower((int) *p++);
    }
    if (strlen(ascii_key) < 16) {
	fprintf(stderr, "key too short\n");
	exit(1);
    }
    string_to_keyblock(ascii_key, keyblock);

    /* verify the key. */
key_verify:
    if ((rc = des_set_key_checked(&keyblock, ks)) != 0) {
	fprintf(stderr, "key %s\n",
	       rc == -1 ? "has incorrect parity" : "is weak");
	if (rc == -1) {
	    des_set_odd_parity(&keyblock);
	    goto key_verify;
	}
	else {
	    exit(1);
	}
    }

    fprintf(stdout, "Enter the challenge: ");
    fgets(challenge, sizeof(challenge), stdin);
    challenge[strlen(challenge) - 1] = '\0'; /* strip '\n' */
    /* encrypt null block if no challenge */

    /*
     * Calculate the response.  The algorithm is:
     * 1. Convert the challenge to ASCII bytes (eg "12345" -> 0x3132333435).
     * 2. Pad LSB of a 64-bit block w/ 0 bytes if challenge < 8 bytes (digits).
     * 3. Encrypt w/ DES (whose block size is 64 bits).
     * 4. Convert the most significant 32 bits of the ciphertext
     *    to 8 hex digits as a string (eg 0x1234567f -> "1234567f").
     */
    {
	des_cblock input, output;

	/* Step 1, 2 (conversion is already done, just copy and pad) */
	(void) memset(input, 0, sizeof(input));
	(void) memcpy(input, challenge, strlen(challenge));

	/* Step 3 */
	des_ecb_encrypt(&input, &output, ks, 1);

	/* Step 4, 5 */
	keyblock_to_string(response_long, output, ascii_conversion);
	(void) memcpy(response, response_long, 8);
	response[8] = '\0';
	memcpy(challenge, output, 8);
	challenge[8] = '\0';
    }

    /* calculate the next challenge for cryptocard */
    for (i = 0; i < 8; ++i) {
	challenge[i] &= 0x0f;
	if (challenge[i] > 9)
	    challenge[i] -= 10;
	challenge[i] |= 0x30;
    }

    fprintf(stdout, "response is %s [%s]\n", response, &response_long[8]);
    fprintf(stdout, "next challenge is %s\n", challenge);
    exit(0);
}


