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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000,2001  The FreeRADIUS server project
 * Copyright 2001  hereUare Communications, Inc. <raghud@hereuare.com>
 */

#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "eap_md5.h"


static int md5_attach(CONF_SECTION *conf, void **arg)
{
	return 0;
}

/*
 * send an initial eap-md5 request
 * ie access challenge to the user/peer.

 * Frame eap reply packet.
 * len = header + type + md5_typedata
 * md5_typedata = value_size + value
 */
static int md5_initiate(void *type_arg, EAP_HANDLER *handler)
{
	MD5_PACKET	*reply;

	reply = eapmd5_initiate(handler->eap_ds);
	if (reply == NULL)
		return 0;

	eapmd5_compose(handler->eap_ds, reply);

	eapmd5_free(&reply);
	return 1;
}

static int md5_authenticate(void *arg, EAP_HANDLER *handler)
{
	MD5_PACKET	*packet;
	MD5_PACKET	*reply;
	md5_packet_t	*request;
	char*		username;
	VALUE_PAIR	*password;
	EAP_DS		*temp;

	if (!(packet = eapmd5_extract(handler->eap_ds)))
		return 0;

	username = (char *)handler->username->strvalue;

	/*
	 * Password is never sent over the wire.
	 * Always get the configured password, for each user.
	 */
	password = paircopy2(handler->configured, PW_PASSWORD);
	if (password == NULL) {
		radlog(L_INFO, "rlm_eap_md5: No password configured for this user");
		eapmd5_free(&packet);
		return 0;
	}

	temp = (EAP_DS *)handler->prev_eapds;
	request = temp?(md5_packet_t *)(temp->request->type.data):NULL;
	reply = eapmd5_process(packet, handler->eap_ds->request->id,
			 handler->username, password, request);
	if (!reply) {
		eapmd5_free(&packet);
		return 0;
	}

	eapmd5_compose(handler->eap_ds, reply);

	eapmd5_free(&reply);
	eapmd5_free(&packet);
	return 1;
}

static int md5_detach(void **arg)
{
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
EAP_TYPE rlm_eap_md5 = {
	"eap_md5",
	md5_attach,			/* attach */
	md5_initiate,			/* Start the initial request, after Identity */
	md5_authenticate,		/* authentication */
	md5_detach			/* detach */
};
