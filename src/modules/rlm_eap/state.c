/*
 * state.c  To generate and verify State attribute
 *
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
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include "rlm_eap.h"

static const char rcsid[] = "$Id$";

/*
 *	Global key to generate & verify State
 *
 *	This is needed only once per instance of the server,
 *	and putting it in the rlm_eap_t is just too much effort.
 *
 *	Putting it here is ugly, but it works.
 */
static int key_initialized = 0;
static unsigned char state_key[AUTH_VECTOR_LEN];

/*
 *	Generate & Verify the State attribute
 *
 *	In the simplest implementation, we would just use the
 *	challenge as state.  Unfortunately, the RADIUS secret protects
 *	only the User-Password attribute; an attacker that can remove
 *	packets from the wire and insert new ones can simply insert a
 *	replayed state without having to know the secret.
 *
 *	However, RADIUS packets containing EAP conversations MUST be
 *	signed with Message-Authenticator, at which point, they MUST
 *	know the secret, in order to get to the EAP module.  And if
 *	they know the secret, they can do many worse things than
 *	re-playing a State attribute.  Their only alternative is to
 *	re-play entire packets, which is caught by the server core.
 *
 *	In any case, we sign our state with data unique to this
 *	specific request.  A NAS would use the Request Authenticator,
 *	we don't know what that will be when the State is returned to
 *	us, so we'll use a time stamp.
 *
 *	Our replay prevention is limited to a time interval
 *	(inst->maxdelay).  We could keep track of all challenges
 *	issued over that time interval, to ensure that the challenges
 *	were unique.  However, they're 8-bytes of data from a good
 *	PRNG, which means that it's pretty damn unlikely that they'll
 *	be re-used.
 *
 *	Our state, then, is (challenge + hmac(challenge + time, key)),
 *	where '+' denotes concatentation, 'challenge' is the octets
 *	of the challenge, 'time' is the 'time_t' in host byte order,
 *	and 'key' is a random key, generated once in eap_init().
 *
 *	This means that only the server which generates a challenge
 *	can verify it; this should be OK if your NAS's load balance
 *	across RADIUS servers by a "first available" algorithm.  If
 *	your NAS's round-robin (ugh), you could use the RADIUS
 *	secret instead, but read RFC 2104 first, and make very sure
 *	you really want to do this.
 */
void generate_key(void)
{
	unsigned int i;

	if (key_initialized) return;

	/*
	 *	Use a cryptographically strong method to generate
	 *	pseudo-random numbers.
	 */
	for (i = 0; i < sizeof(state_key); i++) {
		state_key[i] = lrad_rand();
	}

	key_initialized = 1;
}

/*
 *	For clarity.  Also, to avoid giving away
 *	too much information, we only put 8 octets of the HMAC
 *	into the State attribute, instead of all 16.
 *
 *	As a security feature, it's a little hokey, but WTF.
 *
 *	Also, ensure that EAP_CHALLENGE_LEN + EAP_USE_OF_HMAC = EAP_STATE_LEN
 */
#define EAP_CHALLENGE_LEN (8)
#define EAP_HMAC_SIZE (16)
#define EAP_USE_OF_HMAC (8)

/*
 * Our state, is (challenge + time + hmac(challenge + time, key))
 *
 *  If it's too long, then some clients chop it (sigh)
 */
VALUE_PAIR *generate_state(time_t timestamp)
{
	unsigned int i;
	unsigned char challenge[EAP_CHALLENGE_LEN];
	unsigned char hmac[EAP_HMAC_SIZE];
	unsigned char value[EAP_CHALLENGE_LEN + sizeof(timestamp)];
	VALUE_PAIR    *state;

	/* Generate challenge (a random value).  */
	for (i = 0; i < sizeof(challenge); i++) {
		challenge[i] = lrad_rand();
	}

	memcpy(value, challenge, sizeof(challenge));
	memcpy(value + sizeof(challenge), &timestamp, sizeof(timestamp));

	/*
	 *	hmac(challenge + timestamp)
	 */
	lrad_hmac_md5(value, sizeof(value),
		      state_key, sizeof(state_key), hmac);

	/*
	 *	Create the state attribute.
	 *
	 *	Note that the timestamp is used internally, but is NOT
	 *	sent to the client!
	 */
	state = paircreate(PW_STATE, PW_TYPE_OCTETS);
	if (state == NULL) {
		radlog(L_ERR, "rlm_eap: out of memory");
		return NULL;
	}
	memcpy(state->strvalue, challenge, sizeof(challenge));
	memcpy(state->strvalue + sizeof(challenge), hmac,
	       EAP_USE_OF_HMAC);

	state->length = sizeof(challenge) + EAP_USE_OF_HMAC;

	return state;
}

/*
 * Returns 0 on success, non-zero otherwise.
 */
int verify_state(VALUE_PAIR *state, time_t timestamp)
{
	unsigned char hmac[EAP_HMAC_SIZE];
	unsigned char value[EAP_CHALLENGE_LEN + sizeof(timestamp)];

	/*
	 *	The length is wrong.  Don't do anything.
	 */
	if (state->length != EAP_STATE_LEN) {
		return -1;
	}

	/*
	 *	The first 16 octets of the State attribute constains
	 *	the random challenge.
	 */
	memcpy(value, state->strvalue, EAP_CHALLENGE_LEN);
	memcpy(value + EAP_CHALLENGE_LEN, &timestamp, sizeof(timestamp));

	/* Generate hmac.  */
	lrad_hmac_md5(value, sizeof(value),
		      state_key, sizeof(state_key), hmac);

	/*
	 *	Compare the hmac we calculated to the one in the
	 *	packet.
	 */
	return memcmp(hmac, state->strvalue + EAP_CHALLENGE_LEN,
		      EAP_USE_OF_HMAC);
}

