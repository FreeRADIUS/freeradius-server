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
 * @copyright 2000,2001,2006  The FreeRADIUS server project
 * @copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>

#include "eap_md5.h"

#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/md5.h>

static fr_dict_t *dict_freeradius;

extern fr_dict_autoload_t rlm_eap_md5_dict[];
fr_dict_autoload_t rlm_eap_md5_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_cleartext_password;

extern fr_dict_attr_autoload_t rlm_eap_md5_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_md5_dict_attr[] = {
	{ .out = &attr_cleartext_password, .name = "Cleartext-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL }
};

static rlm_rcode_t mod_process(UNUSED void *instance, eap_session_t *eap_session);

/*
 *	Initiate the EAP-MD5 session by sending a challenge to the peer.
 */
static rlm_rcode_t mod_session_init(UNUSED void *instance, eap_session_t *eap_session)
{
	int		i;
	MD5_PACKET	*reply;
	REQUEST		*request = eap_session->request;

	/*
	 *	Allocate an EAP-MD5 packet.
	 */
	MEM(reply = talloc(eap_session, MD5_PACKET));

	/*
	 *	Fill it with data.
	 */
	reply->code = FR_MD5_CHALLENGE;
	reply->length = 1 + MD5_CHALLENGE_LEN; /* one byte of value size */
	reply->value_size = MD5_CHALLENGE_LEN;

	/*
	 *	Allocate user data.
	 */
	MEM(reply->value = talloc_array(reply, uint8_t, reply->value_size));
	/*
	 *	Get a random challenge.
	 */
	for (i = 0; i < reply->value_size; i++) reply->value[i] = fr_rand();
	RDEBUG2("Issuing MD5 Challenge");

	/*
	 *	Keep track of the challenge.
	 */
	MEM(eap_session->opaque = talloc_array(eap_session, uint8_t, reply->value_size));
	memcpy(eap_session->opaque, reply->value, reply->value_size);

	/*
	 *	Compose the EAP-MD5 packet out of the data structure,
	 *	and free it.
	 */
	eap_md5_compose(eap_session->this_round, reply);

	/*
	 *	We don't need to authorize the user at this point.
	 *
	 *	We also don't need to keep the challenge, as it's
	 *	stored in 'eap_session->this_round', which will be given back
	 *	to us...
	 */
	eap_session->process = mod_process;

	return RLM_MODULE_HANDLED;
}

/*
 *	Authenticate a previously sent challenge.
 */
static rlm_rcode_t mod_process(UNUSED void *instance, eap_session_t *eap_session)
{
	MD5_PACKET	*packet;
	MD5_PACKET	*reply;
	VALUE_PAIR	*password;
	REQUEST		*request = eap_session->request;

	/*
	 *	Get the Cleartext-Password for this user.
	 */
	rad_assert(eap_session->request != NULL);

	password = fr_pair_find_by_da(eap_session->request->control, attr_cleartext_password, TAG_ANY);
	if (!password) {
		REDEBUG2("Cleartext-Password is required for EAP-MD5 authentication");
		return RLM_MODULE_REJECT;
	}

	/*
	 *	Extract the EAP-MD5 packet.
	 */
	packet = eap_md5_extract(eap_session->this_round);
	if (!packet) return RLM_MODULE_INVALID;

	/*
	 *	Create a reply, and initialize it.
	 */
	reply = talloc(packet, MD5_PACKET);
	if (!reply) {
		talloc_free(packet);
		return RLM_MODULE_FAIL;
	}
	reply->id = eap_session->this_round->request->id;
	reply->length = 0;

	/*
	 *	Verify the received packet against the previous packet
	 *	(i.e. challenge) which we sent out.
	 */
	if (eap_md5_verify(packet, password, eap_session->opaque)) {
		reply->code = FR_MD5_SUCCESS;
	} else {
		reply->code = FR_MD5_FAILURE;
	}

	/*
	 *	Compose the EAP-MD5 packet out of the data structure,
	 *	and free it.
	 */
	eap_md5_compose(eap_session->this_round, reply);
	talloc_free(packet);

	return RLM_MODULE_OK;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_md5;
rlm_eap_submodule_t rlm_eap_md5 = {
	.name		= "eap_md5",

	.provides	= { FR_EAP_MD5 },
	.magic		= RLM_MODULE_INIT,
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.entry_point	= mod_process		/* Process next round of EAP method */
};
