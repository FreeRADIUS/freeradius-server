/*
 * nas.c	Functions to do with a NASLIST. This is here because
 *		radzap needs it as well.
 *
 * Version:     $Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include	<sys/stat.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#include	"radiusd.h"

static NAS	*naslist = NULL;

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
	NAS	*nas;

	nas_free(naslist);
	naslist = NULL;

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
		    !getword(&p, shortnm, sizeof(shortnm))) {
			radlog(L_ERR, "%s[%d]: unexpected end of line", file, lineno);
			continue;
		}
		(void)getword(&p, nastype, sizeof(nastype));

		/*
		 *	Double-check lengths to be sure they're sane
		 */
		if (strlen(hostnm) >= sizeof(nas->longname)) {
			radlog(L_ERR, "%s[%d]: host name of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(hostnm), sizeof(nas->longname) - 1);
			return -1;
		}
		if (strlen(shortnm) > sizeof(nas->shortname)) {
			radlog(L_ERR, "%s[%d]: short name of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(shortnm), sizeof(nas->shortname) - 1);
			return -1;
		}
		if (strlen(nastype) >= sizeof(nas->nastype)) {
			radlog(L_ERR, "%s[%d]: NAS type of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(nastype), sizeof(nas->nastype) - 1);
			return -1;
		}
		
		/*
		 *	It should be OK now, let's create the buffer.
		 */
		nas = rad_malloc(sizeof(NAS));

		strcpy(nas->nastype, nastype);
		strcpy(nas->shortname, shortnm);

		if (strcmp(hostnm, "DEFAULT") == 0) {
			nas->ipaddr = 0;
			strcpy(nas->longname, hostnm);
		} else {
			nas->ipaddr = ip_getaddr(hostnm);
			ip_hostname(nas->longname, sizeof(nas->longname),
				    nas->ipaddr);
		}

		nas->next = naslist;
		naslist = nas;
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
const char *nas_name(uint32_t ipaddr)
{
	NAS *nas;

	if ((nas = nas_find(ipaddr)) != NULL) {
		if (nas->shortname[0])
			return nas->shortname;
		else
			return nas->longname;
	}

	return client_name(ipaddr);
}

/*
 *	Find the name of a nas (prefer short name) based on the request.
 */
const char *nas_name2(RADIUS_PACKET *packet)
{
	uint32_t	ipaddr;
	NAS	        *nas;
	VALUE_PAIR	*pair;

	if ((pair = pairfind(packet->vps, PW_NAS_IP_ADDRESS)) != NULL)
		ipaddr = pair->lvalue;
	else
		ipaddr = packet->src_ipaddr;

	if ((nas = nas_find(ipaddr)) != NULL) {
		if (nas->shortname[0])
			return nas->shortname;
		else
			return nas->longname;
	}

	return client_name(ipaddr);
}

