/*
 * rlm_eap_md5.c    Handles that are called from eap
 *
 * Version:     $Id$
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
 * Copyright 2000,2001,2006  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>

#include "eap_md5.h"

#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/md5.h>

/*
 *	Initiate the EAP-MD5 session by sending a challenge to the peer.
 */
static int mod_session_init(UNUSED void *instance, eap_handler_t *handler)
{
	int		i;
	MD5_PACKET	*reply;
	REQUEST		*request = handler->request;

	/*
	 *	Allocate an EAP-MD5 packet.
	 */
	reply = talloc(handler, MD5_PACKET);
	if (!reply)  {
		return 0;
	}

	/*
	 *	Fill it with data.
	 */
	reply->code = PW_MD5_CHALLENGE;
	reply->length = 1 + MD5_CHALLENGE_LEN; /* one byte of value size */
	reply->value_size = MD5_CHALLENGE_LEN;

	/*
	 *	Allocate user data.
	 */
	reply->value = talloc_array(reply, uint8_t, reply->value_size);
	if (!reply->value) {
		talloc_free(reply);
		return 0;
	}

	/*
	 *	Get a random challenge.
	 */
	for (i = 0; i < reply->value_size; i++) {
		reply->value[i] = fr_rand();
	}
	RDEBUG2("Issuing MD5 Challenge");

	/*
	 *	Keep track of the challenge.
	 */
	handler->opaque = talloc_array(handler, uint8_t, reply->value_size);
	rad_assert(handler->opaque != NULL);
	memcpy(handler->opaque, reply->value, reply->value_size);
	handler->free_opaque = NULL;

	/*
	 *	Compose the EAP-MD5 packet out of the data structure,
	 *	and free it.
	 */
	eapmd5_compose(handler->eap_ds, reply);

	/*
	 *	We don't need to authorize the user at this point.
	 *
	 *	We also don't need to keep the challenge, as it's
	 *	stored in 'handler->eap_ds', which will be given back
	 *	to us...
	 */
	handler->stage = PROCESS;

	return 1;
}

/*
 *	Authenticate a previously sent challenge.
 */
static int mod_process(UNUSED void *arg, eap_handler_t *handler)
{
	MD5_PACKET	*packet;
	MD5_PACKET	*reply;
	VALUE_PAIR	*password;
	REQUEST		*request = handler->request;

	/*
	 *	Get the Cleartext-Password for this user.
	 */
	rad_assert(handler->request != NULL);
	rad_assert(handler->stage == PROCESS);

	password = fr_pair_find_by_num(handler->request->config, PW_CLEARTEXT_PASSWORD, 0, TAG_ANY);
	if (!password) {
		REDEBUG2("Cleartext-Password is required for EAP-MD5 authentication");
		return 0;
	}

	/*
	 *	Extract the EAP-MD5 packet.
	 */
	if (!(packet = eapmd5_extract(handler->eap_ds)))
		return 0;

	/*
	 *	Create a reply, and initialize it.
	 */
	reply = talloc(packet, MD5_PACKET);
	if (!reply) {
		talloc_free(packet);
		return 0;
	}
	reply->id = handler->eap_ds->request->id;
	reply->length = 0;

	/*
	 *	Verify the received packet against the previous packet
	 *	(i.e. challenge) which we sent out.
	 */
	if (eapmd5_verify(packet, password, handler->opaque)) {
		reply->code = PW_MD5_SUCCESS;
	} else {
		reply->code = PW_MD5_FAILURE;
	}

	/*
	 *	Compose the EAP-MD5 packet out of the data structure,
	 *	and free it.
	 */
	eapmd5_compose(handler->eap_ds, reply);
	talloc_free(packet);
	return 1;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_md5;
rlm_eap_module_t rlm_eap_md5 = {
	.name		= "eap_md5",
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process		/* Process next round of EAP method */
};
