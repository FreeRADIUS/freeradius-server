/*
 * nas.c	Functions to do with a NASLIST. This is here because
 *		radzap needs it as well.
 *
 * Version:     @(#)nas.c  1.00  08-Aug-1999  miquels@cistron.nl
 *
 */

char nas_sccsid[] =
"@(#)nas.c	1.00 Copyright 1999 Cistron Internet Services B.V.";

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
	char	hostnm[128];
	char	shortnm[32];
	char	nastype[32];
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
		if (buffer[0] == '#' || buffer[0] == '\n')
			continue;
		p = buffer;
		if (!getword(&p, hostnm, sizeof(hostnm)) ||
		    !getword(&p, shortnm, sizeof(shortnm))) {
			log(L_ERR, "%s[%d]: syntax error", file, lineno);
			continue;
		}
		(void)getword(&p, nastype, sizeof(nastype));

		if ((c = malloc(sizeof(NAS))) == NULL) {
			log(L_CONS|L_ERR, "%s[%d]: out of memory",
				file, lineno);
			return -1;
		}

		c->ipaddr = ip_getaddr(hostnm);
		strcpy(c->nastype, nastype);
		strcpy(c->shortname, shortnm);
		strcpy(c->longname, ip_hostname(c->ipaddr));

		c->next = naslist;
		naslist = c;
	}
	fclose(fp);

	return 0;
}


/*
 *	Find a nas in the NAS list.
 */
NAS *nas_find(UINT4 ipaddr)
{
	NAS *cl;

	for (cl = naslist; cl; cl = cl->next)
		if (ipaddr == cl->ipaddr)
			break;

	return cl;
}


/*
 *	Find a nas by name.
 */
NAS *nas_findbyname(char *nasname)
{
	NAS	*nas;

	for (nas = naslist; nas; nas = nas->next) {
		if (strcmp(nasname, nas->shortname) == 0 ||
		    strcmp(nasname, nas->longname) == 0)
			break;
	}

	return nas;
}


/*
 *	Find the name of a nas (prefer short name).
 */
char *nas_name(UINT4 ipaddr)
{
	NAS *cl;

	if ((cl = nas_find(ipaddr)) != NULL) {
		if (cl->shortname[0])
			return cl->shortname;
		else
			return cl->longname;
	}
	return ip_hostname(ipaddr);
}

/*
 *	Find the name of a nas (prefer short name) based on the request.
 */
char *nas_name2(RADIUS_PACKET *packet)
{
	UINT4	ipaddr;
	NAS	*cl;
	VALUE_PAIR	*pair;

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
	return ip_hostname(ipaddr);
}

