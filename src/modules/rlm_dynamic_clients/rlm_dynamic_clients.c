/*
 * rlm_dynamic_clients.c
 *
 * Version:	$Id$
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
 * Copyright 2008  The FreeRADIUS server project
 * Copyright 2008  Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

/*
 *	Find the client definition.
 */
static int dynamic_client_authorize(UNUSED void *instance, REQUEST *request)
{
	size_t length;
	const char *value;
	CONF_PAIR *cp;
	RADCLIENT *c;
	char buffer[2048];

	/*
	 *	Ensure we're only being called from the main thread,
	 *	with fake packets.
	 */
	if ((request->packet->src_port != 0) || (request->packet->vps != NULL) ||
	    (request->parent != NULL)) {
		RDEBUG("Improper configuration");
		return RLM_MODULE_NOOP;
	}

	if (!request->client || !request->client->cs) {
		RDEBUG("Unknown client definition");
		return RLM_MODULE_NOOP;
	}

	cp = cf_pair_find(request->client->cs, "directory");
	if (!cp) {
		RDEBUG("No directory configuration in the client");
		return RLM_MODULE_NOOP;
	}

	value = cf_pair_value(cp);
	if (!value) {
		RDEBUG("No value given for the directory entry in the client.");
		return RLM_MODULE_NOOP;
	}

	length = strlen(value);
	if (length > (sizeof(buffer) - 256)) {
		RDEBUG("Directory name too long");
		return RLM_MODULE_NOOP;
	}

	memcpy(buffer, value, length + 1);
	ip_ntoh(&request->packet->src_ipaddr,
		buffer + length, sizeof(buffer) - length - 1);

	/*
	 *	Read the buffer and generate the client.
	 */
	c = client_read(buffer, (request->client->server != NULL), TRUE);
	if (!c) return RLM_MODULE_FAIL;

	/*
	 *	Replace the client.  This is more than a bit of a
	 *	hack.
	 */
	request->client = c;

	return RLM_MODULE_OK;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_dynamic_clients = {
	RLM_MODULE_INIT,
	"dynamic_clients",
	RLM_TYPE_THREAD_SAFE,		/* type */
	NULL,				/* instantiation */
	NULL,				/* detach */
	{
		NULL,			/* authentication */
		dynamic_client_authorize,	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
