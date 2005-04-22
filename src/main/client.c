/*
 * files.c	Read config files into memory.
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
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <sys/stat.h>

#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>

#include "radiusd.h"
#include "conffile.h"
#include "rad_assert.h"


/*
 *	Free a RADCLIENT list.
 */
void clients_free(RADCLIENT *cl)
{
	RADCLIENT *next;

	while (cl) {
		next = cl->next;
		free(cl->longname);
		free(cl->secret);
		free(cl->shortname);
		free(cl->nastype);
		free(cl->login);
		free(cl->password);

		free(cl);
		cl = next;
	}
}


/*
 *	Read the clients file.
 */
int read_clients_file(const char *file)
{
	FILE *fp;
	RADCLIENT *c;
	char buffer[256];
	char hostnm[256];
	char secret[256];
	char shortnm[256];
	uint32_t mask;
	int lineno = 0;
	char *p;
	int got_clients = FALSE;

	clients_free(mainconfig.clients);
	mainconfig.clients = NULL;

	if ((fp = fopen(file, "r")) == NULL) {
		/* The clients file is no longer required.  All configuration
		   information is read from radiusd.conf and friends.  If
		   clients exists it will be used, but if it doesn't no harm
		   done. */
		return 0;
	}

	while(fgets(buffer, 256, fp) != NULL) {
		lineno++;
		if (!feof(fp) && (strchr(buffer, '\n') == NULL)) {
			radlog(L_ERR, "%s[%d]: line too long", file, lineno);
			return -1;
		}

		/*
		 *	Skip whitespace.
		 */
		p = buffer;
		while (*p &&
				((*p == ' ') || (*p == '\t')))
			p++;

		/*
		 *	Skip comments and blank lines.
		 */
		if ((*p == '#') || (*p == '\n') || (*p == '\r'))
			continue;

		if (!getword(&p, hostnm, sizeof(hostnm)) ||
				!getword(&p, secret, sizeof(secret))) {
			radlog(L_ERR, "%s[%d]: unexpected end of line",
					file, lineno);
			return -1;
		}

		(void)getword(&p, shortnm, sizeof(shortnm));

		/*
		 *	Look for a mask in the hostname
		 */
		p = strchr(hostnm, '/');
		mask = ~0;

		if (p) {
			int mask_length;

			*p = '\0';
			p++;

			mask_length = atoi(p);
			if ((mask_length < 0) || (mask_length > 32)) {
				radlog(L_ERR, "%s[%d]: Invalid value '%s' for IP network mask.",
				       file, lineno, p);
				return -1;
			}

			if (mask_length == 0) {
				mask = 0;
			} else {
				mask = ~0 << (32 - mask_length);
			}
		}

		/*
		 *	It should be OK now, let's create the buffer.
		 */
		got_clients = TRUE;
		c = rad_malloc(sizeof(RADCLIENT));
		memset(c, 0, sizeof(*c));

		if (ip_hton(hostnm, AF_INET, &c->ipaddr) < 0) {
			radlog(L_CONS|L_ERR, "%s[%d]: Failed to look up hostname %s",
					file, lineno, hostnm);
			return -1;
		}
		c->netmask = htonl(mask);
		c->ipaddr.ipaddr.ip4addr.s_addr &= c->netmask; /* addr & mask are in network order */

		c->secret = strdup(secret);
		c->shortname = strdup(shortnm);

		/*
		 *	Only do DNS lookups for machines.  Just print
		 *	the network as the long name.
		 */
		if ((~mask) == 0) {
			ip_ntoh(&c->ipaddr, buffer, sizeof(buffer));
			c->longname = strdup(buffer);
		} else {
			hostnm[strlen(hostnm)] = '/';
			c->longname = strdup(hostnm);
		}

		c->next = mainconfig.clients;
		mainconfig.clients = c;
	}
	fclose(fp);

	if (got_clients) {
		radlog(L_INFO, "Using deprecated clients file.  Support for this will go away soon.");
	}

	return 0;
}


/*
 *	Find a client in the RADCLIENTS list.
 */
RADCLIENT *client_find(const lrad_ipaddr_t *ipaddr)
{
	RADCLIENT *cl;
	RADCLIENT *match = NULL;

	for (cl = mainconfig.clients; cl; cl = cl->next) {
		/*
		 *	Catch IPv6-mapped IPv4 addresses.
		 */
		if ((cl->ipaddr.af == AF_INET) &&
		    (ipaddr->af == AF_INET6) &&
		    IN6_IS_ADDR_V4MAPPED(&ipaddr->ipaddr.ip6addr) &&
		    (((const uint32_t *) &cl->ipaddr.ipaddr.ip4addr)[0] ==
		     ((const uint32_t *) &ipaddr->ipaddr.ip6addr)[3]) &&
		    ((((const uint32_t *) &ipaddr->ipaddr.ip6addr)[3] & cl->netmask) == cl->ipaddr.ipaddr.ip4addr.s_addr)) {
			if ((!match) ||
			    (ntohl(cl->netmask) > ntohl(match->netmask))) {
				match = cl;
			}
		}

		if (cl->ipaddr.af != ipaddr->af) continue;

		if ((ipaddr->af == AF_INET) &&
		    ((ipaddr->ipaddr.ip4addr.s_addr & cl->netmask) == cl->ipaddr.ipaddr.ip4addr.s_addr)) {
			if ((!match) ||
			    (ntohl(cl->netmask) > ntohl(match->netmask))) {
				match = cl;
			}
		}
	}

	return match;
}


/*
 *	Find the name of a client (prefer short name).
 */
const char *client_name(const lrad_ipaddr_t *ipaddr)
{
	/* We don't call this unless we should know about the client. */
	RADCLIENT *cl;
	char host_ipaddr[128];

	if ((cl = client_find(ipaddr)) != NULL) {
		if (cl->shortname[0])
			return cl->shortname;
		else
			return cl->longname;
	}

	/*
	 * this isn't normally reachable, but if a loggable event happens just
	 * after a client list change and a HUP, then we may not know this
	 * information any more.
	 *
	 * If you see lots of these, then there's something wrong.
	 */
	radlog(L_ERR, "Trying to look up name of unknown client %s.\n",
	       ip_ntoh(ipaddr, host_ipaddr, sizeof(host_ipaddr)));

	return "UNKNOWN-CLIENT";
}
