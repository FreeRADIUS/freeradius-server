/*
 * files.c	Read config files into memory.
 *
 * Version:     $Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/stat.h>

#if HAVE_NETINET_IN_H
#include	<netinet/in.h>
#endif

#include	<stdlib.h>
#include	<string.h>
#include	<netdb.h>
#include	<ctype.h>
#include	<fcntl.h>

#include	"radiusd.h"
#include	"conffile.h"

RADCLIENT	*clients;

/*
 *	Free a RADCLIENT list.
 */
static void clients_free(RADCLIENT *cl)
{
	RADCLIENT *next;

	while(cl) {
		next = cl->next;
		free(cl);
		cl = next;
	}
}


/*
 *	Read the clients file.
 */
int read_clients_file(const char *file)
{
	FILE	*fp;
	RADCLIENT	*c;
	char	buffer[256];
	char	hostnm[256];
	char	secret[256];
	char	shortnm[256];
	uint32_t mask;
	int	lineno = 0;
	char	*p;

	clients_free(clients);
	clients = NULL;

	if ((fp = fopen(file, "r")) == NULL) {
		radlog(L_CONS|L_ERR, "cannot open %s", file);
		return -1;
	}

	while(fgets(buffer, 256, fp) != NULL) {
		lineno++;
		if (strchr(buffer, '\n') == NULL) {
			radlog(L_ERR, "%s[%d]: line too long", file, lineno);
			return -1;
		}

		/*
		 *	Skip whitespace.
		 */
		p = buffer;
		while (*p &&
		       ((*p == ' ') || (*p == '\t'))) p++;

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
			int i, mask_length;

			*p = '\0';
			p++;

			mask_length = atoi(p);
			if ((mask_length <= 0) || (mask_length > 32)) {
				radlog(L_ERR, "%s[%d]: Invalid value '%s' for IP network mask.",
				       file, lineno, p);
				return -1;
			}

			mask = (1 << 31);
			for (i = 1; i < mask_length; i++) {
				mask |= (mask >> 1);
			}
		}

		/*
		 *	Double-check lengths to be sure they're sane
		 */
		if (strlen(hostnm) >= sizeof(c->longname)) {
			radlog(L_ERR, "%s[%d]: host name of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(hostnm), sizeof(c->longname) - 1);
			return -1;
		}
		if (strlen(secret) >= sizeof(c->secret)) {
			radlog(L_ERR, "%s[%d]: secret of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(secret), sizeof(c->secret) - 1);
			return -1;
		}
		if (strlen(shortnm) > sizeof(c->shortname)) {
			radlog(L_ERR, "%s[%d]: short name of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(shortnm), sizeof(c->shortname) - 1);
			return -1;
		}
		
		/*
		 *	It should be OK now, let's create the buffer.
		 */
		c = rad_malloc(sizeof(RADCLIENT));

		c->ipaddr = ip_getaddr(hostnm);
		if (c->ipaddr == INADDR_NONE) {
			radlog(L_CONS|L_ERR, "%s[%d]: Failed to look up hostname %s",
			    file, lineno, hostnm);
			return -1;
		}
		c->netmask = htonl(mask);
		c->ipaddr &= mask;

		strcpy((char *)c->secret, secret);
		strcpy(c->shortname, shortnm);

		/*
		 *	Only do DNS lookups for machines.  Just print
		 *	the network as the long name.
		 */
		if (c->netmask == ~0) {
		  ip_hostname(c->longname, sizeof(c->longname), c->ipaddr);
		} else {
		  hostnm[strlen(hostnm)] = '/';
		  strNcpy(c->longname, hostnm, sizeof(c->longname));
		}

		c->next = clients;
		clients = c;
	}
	fclose(fp);

	return 0;
}


/*
 *	Find a client in the RADCLIENTS list.
 */
RADCLIENT *client_find(uint32_t ipaddr)
{
	RADCLIENT *cl;
	RADCLIENT *match = NULL;

	for(cl = clients; cl; cl = cl->next) {
		if ((ipaddr & cl->netmask) == cl->ipaddr) {
			if ((!match) ||
			    (ntohl(cl->netmask) > ntohl(match->netmask))) {
				match = cl;
			}
		}
	}

	return match;
}

/*
 *	Walk the RADCLIENT list displaying the clients.  This function
 *	is for debugging purposes.
 */
void client_walk(void) 
{
	RADCLIENT	*cl;
	char		host_ipaddr[16];

	for(cl = clients; cl; cl = cl->next)
		radlog(L_ERR, "client: client_walk: %s\n",
			ip_ntoa(host_ipaddr, cl->ipaddr));
}

/*
 *	Find the name of a client (prefer short name).
 */
const char *client_name(uint32_t ipaddr)
{
	RADCLIENT *cl;

	if ((cl = client_find(ipaddr)) != NULL) {
		if (cl->shortname[0])
			return cl->shortname;
		else
			return cl->longname;
	}

	/*
	 *	FIXME!
	 *
	 *	We should NEVER reach this piece of code, as we should
	 *	NEVER be looking up client names for clients we don't know!
	 */
	return "UNKNOWN-CLIENT";
}
