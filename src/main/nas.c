/*
 * nas.c	Functions to do with a NASLIST. This is here because
 *		radzap needs it as well.
 *
 * Version:     $Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/stat.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"

NAS		*naslist;

/*
 *	Free a NAS list.
 */
static void nas_free(NAS *cl)
{
	NAS *next;

	while(cl) {
		next = cl->next;
		free(cl);
		cl = next;
	}
}

/*
 *	Read the nas file.
 */
int read_naslist_file(char *file)
{
	FILE	*fp;
	char	buffer[256];
	char	hostnm[256];
	char	shortnm[256];
	char	nastype[256];
	int	lineno = 0;
	char	*p;
	NAS	*c;

	nas_free(naslist);
	naslist = NULL;

	if ((fp = fopen(file, "r")) == NULL) {
		log(L_CONS|L_ERR, "cannot open %s", file);
		return -1;
	}
	while(fgets(buffer, 256, fp) != NULL) {
		lineno++;
		if (strchr(buffer, '\n') == NULL) {
			log(L_ERR, "%s[%d]: line too long", file, lineno);
			return -1;
		}
		if (buffer[0] == '#' || buffer[0] == '\n')
			continue;

		p = buffer;
		if (!getword(&p, hostnm, sizeof(hostnm)) ||
		    !getword(&p, shortnm, sizeof(shortnm))) {
			log(L_ERR, "%s[%d]: unexpected end of line", file, lineno);
			continue;
		}
		(void)getword(&p, nastype, sizeof(nastype));

		/*
		 *	Double-check lengths to be sure they're sane
		 */
		if (strlen(hostnm) >= sizeof(c->longname)) {
			log(L_ERR, "%s[%d]: host name of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(hostnm), sizeof(c->longname) - 1);
			return -1;
		}
		if (strlen(shortnm) > sizeof(c->shortname)) {
			log(L_ERR, "%s[%d]: short name of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(shortnm), sizeof(c->shortname) - 1);
			return -1;
		}
		if (strlen(nastype) >= sizeof(c->nastype)) {
			log(L_ERR, "%s[%d]: NAS type of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(nastype), sizeof(c->nastype) - 1);
			return -1;
		}
		
		/*
		 *	It should be OK now, let's create the buffer.
		 */
		if ((c = malloc(sizeof(NAS))) == NULL) {
			log(L_CONS|L_ERR, "%s[%d]: out of memory",
				file, lineno);
			return -1;
		}

		strcpy(c->nastype, nastype);
		strcpy(c->shortname, shortnm);

		if (strcmp(hostnm, "DEFAULT") == 0) {
			c->ipaddr = 0;
			strcpy(c->longname, hostnm);
		} else {
			c->ipaddr = ip_getaddr(hostnm);
			ip_hostname(c->longname, sizeof(c->longname),
				    c->ipaddr);
		}

		c->next = naslist;
		naslist = c;
	}
	fclose(fp);

	return 0;
}


/*
 *	Find a nas by IP address.
 *	If it can't be found, return the DEFAULT nas, instead.
 */
NAS *nas_find(uint32_t ipaddr)
{
	NAS *nas;
	NAS *default_nas;

	default_nas = NULL;

	for (nas = naslist; nas; nas = nas->next) {
		if (ipaddr == nas->ipaddr)
			return nas;
		if (strcmp(nas->longname, "DEFAULT") == 0)
			default_nas = nas;
	}

	return default_nas;
}


/*
 *	Find a nas by name.
 *	If it can't be found, return the DEFAULT nas, instead.
 */
NAS *nas_findbyname(char *nasname)
{
	NAS	*nas;
	NAS	*default_nas;

	default_nas = NULL;

	for (nas = naslist; nas; nas = nas->next) {
		if (strcmp(nasname, nas->shortname) == 0 ||
		    strcmp(nasname, nas->longname) == 0)
			return nas;
		if (strcmp(nas->longname, "DEFAULT") == 0)
			default_nas = nas;
	}

	return default_nas;
}


/*
 *	Find the name of a nas (prefer short name).
 */
char *nas_name(uint32_t ipaddr)
{
	NAS *cl;
	char buf[256];

	if ((cl = nas_find(ipaddr)) != NULL) {
		if (cl->shortname[0])
			return cl->shortname;
		else
			return cl->longname;
	}

	/*
	 *	FIXME!
	 *
	 *	This isn't multi-threaded safe!
	 */
	return ip_hostname(buf, sizeof(buf), ipaddr);
}

/*
 *	Find the name of a nas (prefer short name) based on the request.
 */
char *nas_name2(RADIUS_PACKET *packet)
{
	uint32_t	ipaddr;
	NAS	        *cl;
	VALUE_PAIR	*pair;
	char		buf[256];

	if ((pair = pairfind(packet->vps, PW_NAS_IP_ADDRESS)) != NULL)
		ipaddr = pair->lvalue;
	else
		ipaddr = packet->src_ipaddr;

	if ((cl = nas_find(ipaddr)) != NULL) {
		if (cl->shortname[0])
			return cl->shortname;
		else
			return cl->longname;
	}

	/*
	 *	FIXME!!!
	 *
	 *	This isn't multi-threaded safe!
	 */
	return ip_hostname(buf, sizeof(buf), ipaddr);
}

