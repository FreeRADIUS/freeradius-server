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

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

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
		if (buffer[0] == '#' || buffer[0] == '\n')
			continue;

		p = buffer;

		if (!getword(&p, hostnm, sizeof(hostnm)) ||
		    !getword(&p, secret, sizeof(secret))) {
			radlog(L_ERR, "%s[%d]: unexpected end of line",
			    file, lineno);
			return -1;
		}

		(void)getword(&p, shortnm, sizeof(shortnm));

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
		if ((c = malloc(sizeof(RADCLIENT))) == NULL) {
			radlog(L_CONS|L_ERR, "%s[%d]: out of memory",
				file, lineno);
			return -1;
		}

		c->ipaddr = ip_getaddr(hostnm);
		if (c->ipaddr == 0) {
			radlog(L_CONS|L_ERR, "%s[%d]: Failed to look up hostname %s",
			    file, lineno, hostnm);
			return -1;
		}
		strcpy((char *)c->secret, secret);
		strcpy(c->shortname, shortnm);
		ip_hostname(c->longname, sizeof(c->longname), c->ipaddr);

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

	for(cl = clients; cl; cl = cl->next)
		if (ipaddr == cl->ipaddr)
			break;

	return cl;
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
