/*
 * auth.c	User authentication.
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Jeff Carneal <jeff@apex.net>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

/*
 *	Return a short string showing the terminal server, port
 *	and calling station ID.
 */
char *auth_name(char *buf, size_t buflen, REQUEST *request, int do_cli)
{
	VALUE_PAIR	*cli;
	VALUE_PAIR	*pair;
	int		port = 0;

	if ((cli = pairfind(request->packet->vps, PW_CALLING_STATION_ID)) == NULL)
		do_cli = 0;
	if ((pair = pairfind(request->packet->vps, PW_NAS_PORT)) != NULL)
		port = pair->vp_integer;

	snprintf(buf, buflen, "from client %.128s port %u%s%.128s%s",
			request->client->shortname, port,
		 (do_cli ? " cli " : ""), (do_cli ? (char *)cli->vp_strvalue : ""),
		 (request->packet->dst_port == 0) ? " via TLS tunnel" : "");

	return buf;
}


/*
 *	Post-authentication step processes the response before it is
 *	sent to the NAS. It can receive both Access-Accept and Access-Reject
 *	replies.
 */
int rad_postauth(REQUEST *request)
{
	int	result;
	int	postauth_type = 0;
	VALUE_PAIR *vp;

	/*
	 *	Do post-authentication calls. ignoring the return code.
	 */
	vp = pairfind(request->config_items, PW_POST_AUTH_TYPE);
	if (vp) {
		RDEBUG2("Using Post-Auth-Type %s", vp->vp_strvalue);
		postauth_type = vp->vp_integer;
	}
	result = module_post_auth(postauth_type, request);
	switch (result) {
		/*
		 *	The module failed, or said to reject the user: Do so.
		 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			request->reply->code = PW_AUTHENTICATION_REJECT;
			result = RLM_MODULE_REJECT;
			break;
		/*
		 *	The module handled the request, cancel the reply.
		 */
		case RLM_MODULE_HANDLED:
			/* FIXME */
			break;
		/*
		 *	The module had a number of OK return codes.
		 */
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			result = RLM_MODULE_OK;
			break;
	}
	return result;
}
