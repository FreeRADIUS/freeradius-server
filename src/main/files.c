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

#if HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>

#include "radiusd.h"

REALM *realms;

/*
 *	Free a PAIR_LIST
 */
void pairlist_free(PAIR_LIST **pl)
{
	PAIR_LIST *p, *next;

	for (p = *pl; p; p = next) {
		if (p->name) free(p->name);
		if (p->check) pairfree(&p->check);
		if (p->reply) pairfree(&p->reply);
		next = p->next;
		free(p);
	}
	*pl = NULL;
}


/*
 *	Fixup a check line.
 *	If Password or Crypt-Password is set, but there is no
 *	Auth-Type, add one (kludge!).
 */
static void auth_type_fixup(VALUE_PAIR *check)
{
	VALUE_PAIR *vp;
	VALUE_PAIR *c = NULL;
	int n = 0;

	/*
	 *	See if a password is present. Return right away
	 *	if we see Auth-Type.
	 */
	for (vp = check; vp; vp = vp->next) {
		if (vp->attribute == PW_AUTHTYPE)
			return;
		if (vp->attribute == PW_PASSWORD) {
			c = vp;
			n = PW_AUTHTYPE_LOCAL;
		}
		if (vp->attribute == PW_CRYPT_PASSWORD) {
			c = vp;
			n = PW_AUTHTYPE_CRYPT;
		}
	}

	if (c == NULL)
		return;

	/*
	 *	Add an Auth-Type attribute.
	 *	
	 */
	if ((vp = paircreate(PW_AUTHTYPE, PW_TYPE_INTEGER)) == NULL) {
		radlog(L_CONS|L_ERR, "no memory");
		exit(1);
	}
	vp->lvalue = n;
	vp->operator = T_OP_ADD;

#if 0
	vp->next = c->next;
	c->next = vp;
#endif
	vp->next = check;
	check = vp;

	for(vp = check; vp; vp = vp->next) {
		DEBUG2("  auth_type_fixup: %s [%d]", vp->name, vp->attribute);
	}

}


#define FIND_MODE_NAME  0
#define FIND_MODE_REPLY 1

/*
 *	Read the users, huntgroups or hints file.
 *	Return a PAIR_LIST.
 */
int pairlist_read(const char *file, PAIR_LIST **list, int complain)
{
	FILE *fp;
	int mode = FIND_MODE_NAME;
	char entry[256];
	char buffer[256];
	char *ptr, *s;
	VALUE_PAIR *check_tmp;
	VALUE_PAIR *reply_tmp;
	PAIR_LIST *pl = NULL, *last = NULL, *t;
	int lineno = 0;
	int old_lineno = 0;
	int parsecode;
	char newfile[8192];

	/*
	 *	Open the file.  The error message should be a little
	 *	more useful...
	 */
	if ((fp = fopen(file, "r")) == NULL) {
		if (!complain) 
			return -1;
		radlog(L_CONS|L_ERR, "Couldn't open %s for reading: %s",
				file, strerror(errno));
		return -1;
	}

	parsecode = T_EOL;
	/*
	 *	Read the entire file into memory for speed.
	 */
	while(fgets(buffer, sizeof(buffer), fp) != NULL) {
		lineno++;
		if (strchr(buffer, '\n') == NULL) {
			radlog(L_ERR, "%s[%d]: line too long", file, lineno);
			pairlist_free(&pl);
			return -1;
		}
		if (buffer[0] == '#' || buffer[0] == '\n') continue;
parse_again:
		if(mode == FIND_MODE_NAME) {
			/*
			 *	Find the entry starting with the users name
			 */
			if (isspace(buffer[0]))  {
				if (parsecode != T_EOL) {
					radlog(L_ERR|L_CONS,
							"%s[%d]: Unexpected trailing comma for entry %s",
							file, lineno, entry);
					fclose(fp);
					return -1;
				}
				continue;
			}

			ptr = buffer;
			getword(&ptr, entry, sizeof(entry));

			/*
			 *	Include another file if we see
			 *	$INCLUDE filename
			 */
			if (strcasecmp(entry, "$include") == 0) {
				while(isspace(*ptr))
					ptr++;
				s = ptr;
				while (!isspace(*ptr))
					ptr++;
				*ptr = 0;

				/*
				 *	If it's an absolute pathname,
				 *	then use it verbatim.
				 *
				 *	If not, then make the $include
				 *	files *relative* to the current
				 *	file.
				 */
				if (*s != '/') {
					strNcpy(newfile, file,
						sizeof(newfile));
					ptr = strrchr(newfile, '/');
					strcpy(ptr + 1, s);
					s = newfile;
				}

				t = NULL;
				if (pairlist_read(s, &t, 0) != 0) {
					pairlist_free(&pl);
					radlog(L_ERR|L_CONS,
							"%s[%d]: Could not open included file %s: %s",
							file, lineno, s, strerror(errno));
					fclose(fp);
				return -1;
				}
				if (last)
					last->next = t;
				else
					pl = t;
				last = t;
				while (last && last->next)
					last = last->next;
				continue;
			}

			/*
			 *	Parse the check values
			 */
			check_tmp = NULL;
			reply_tmp = NULL;
			old_lineno = lineno;
			parsecode = userparse(ptr, &check_tmp);
			if (parsecode < 0) {
				pairlist_free(&pl);
				radlog(L_ERR|L_CONS,
				"%s[%d]: Parse error (check) for entry %s: %s",
					file, lineno, entry, librad_errstr);
				fclose(fp);
				return -1;
			} else if (parsecode == T_COMMA) {
				radlog(L_ERR|L_CONS,
						"%s[%d]: Unexpected trailing comma in check item list for entry %s",
						file, lineno, entry);
				fclose(fp);
				return -1;
			}
			mode = FIND_MODE_REPLY;
			parsecode = T_COMMA;
		}
		else {
			if(*buffer == ' ' || *buffer == '\t') {
				if (parsecode != T_COMMA) {
					radlog(L_ERR|L_CONS,
							"%s[%d]: Syntax error: Previous line is missing a trailing comma for entry %s",
							file, lineno, entry);
					fclose(fp);
					return -1;
				}

				/*
				 *	Parse the reply values
				 */
				parsecode = userparse(buffer, &reply_tmp);
				if (parsecode < 0) {
					pairlist_free(&pl);
					radlog(L_ERR|L_CONS,
							"%s[%d]: Parse error (reply) for entry %s: %s",
							file, lineno, entry, librad_errstr);
					fclose(fp);
					return -1;
				}
			}
			else {
				/*
				 *	Done with this entry...
				 */
				t = rad_malloc(sizeof(PAIR_LIST));

				auth_type_fixup(check_tmp);
				memset(t, 0, sizeof(*t));
				t->name = strdup(entry);
				t->check = check_tmp;
				t->reply = reply_tmp;
				t->lineno = old_lineno;
				check_tmp = NULL;
				reply_tmp = NULL;
				if (last)
					last->next = t;
				else
					pl = t;
				last = t;

				mode = FIND_MODE_NAME;
				if (buffer[0] != 0)
					goto parse_again;
			}
		}
	}
	/*
	 *	Make sure that we also read the last line of the file!
	 */
	if (mode == FIND_MODE_REPLY) {
		buffer[0] = 0;
		goto parse_again;
	}
	fclose(fp);

	*list = pl;
	return 0;
}


/*
 *	Debug code.
 */
#if 0
static void debug_pair_list(PAIR_LIST *pl)
{
	VALUE_PAIR *vp;

	while(pl) {
		printf("Pair list: %s\n", pl->name);
		printf("** Check:\n");
		for(vp = pl->check; vp; vp = vp->next) {
			printf("    ");
			fprint_attr_val(stdout, vp);
			printf("\n");
		}
		printf("** Reply:\n");
		for(vp = pl->reply; vp; vp = vp->next) {
			printf("    ");
			fprint_attr_val(stdout, vp);
			printf("\n");
		}
		pl = pl->next;
	}
}
#endif

#ifndef BUILDDBM /* HACK HACK */

/*
 *	Free a REALM list.
 */
static void realm_free(REALM *cl)
{
	REALM *next;

	while(cl) {
		next = cl->next;
		free(cl);
		cl = next;
	}
}

/*
 *	Read the realms file.
 */
int read_realms_file(const char *file)
{
	FILE *fp;
	char buffer[256];
	char realm[256];
	char hostnm[256];
	char opts[256];
	char *s, *p;
	int lineno = 0;
	REALM *c;
	RADCLIENT *client;

	realm_free(realms);
	realms = NULL;

	if ((fp = fopen(file, "r")) == NULL) {
		/* The realms file is not mandatory.  If it exists it will
		   be used, however, since the new style config files are
		   more robust and flexible they are more likely to get used.
		   So this is a non-fatal error.  */
		return 0;
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
		if (!getword(&p, realm, sizeof(realm)) ||
				!getword(&p, hostnm, sizeof(hostnm))) {
			radlog(L_ERR, "%s[%d]: syntax error", file, lineno);
			continue;
		}

		c = rad_malloc(sizeof(REALM));
		memset(c, 0, sizeof(REALM));

		if ((s = strchr(hostnm, ':')) != NULL) {
			*s++ = 0;
			c->auth_port = atoi(s);
			c->acct_port = c->auth_port + 1;
		} else {
			c->auth_port = auth_port;
			c->acct_port = acct_port;
		}

		if (strcmp(hostnm, "LOCAL") == 0) {
			c->ipaddr = htonl(INADDR_LOOPBACK);
		} else {
			c->ipaddr = ip_getaddr(hostnm);
		}

		if (c->ipaddr == 0) {
			radlog(L_CONS|L_ERR, "%s[%d]: Failed to look up hostname %s",
					file, lineno, hostnm);
			return -1;
		}

		/*
		 *	Find the remote server in the "clients" list.
		 *	If we can't find it, there's a big problem...
		 */
		client = client_find(c->ipaddr);
		if (client == NULL) {
			radlog(L_CONS|L_ERR, "%s[%d]: Cannot find 'clients' file entry of remote server %s for realm \"%s\"",
					file, lineno, hostnm, realm);
			return -1;
		}
		memcpy(c->secret, client->secret, sizeof(c->secret));

		/*
		 *	Double-check lengths to be sure they're sane
		 */
		if (strlen(hostnm) >= sizeof(c->server)) {
			radlog(L_ERR, "%s[%d]: server name of length %d is greater than the allowed maximum of %d.",
					file, lineno,
					strlen(hostnm), sizeof(c->server) - 1);
			return -1;
		}
		if (strlen(realm) > sizeof(c->realm)) {
			radlog(L_ERR, "%s[%d]: realm of length %d is greater than the allowed maximum of %d.",
					file, lineno,
					strlen(realm), sizeof(c->realm) - 1);
			return -1;
		}

		/*
		 *	OK, they're sane, copy them over.
		 */
		strcpy(c->realm, realm);
		strcpy(c->server, hostnm);
		c->striprealm = TRUE;

		while (getword(&p, opts, sizeof(opts))) {
			if (strcmp(opts, "nostrip") == 0)
				c->striprealm = FALSE;
			if (strstr(opts, "noacct") != NULL)
				c->acct_port = 0;
			if (strstr(opts, "trusted") != NULL)
				c->trusted = 1;
			if (strstr(opts, "notrealm") != NULL)
				c->notrealm = 1;
			if (strstr(opts, "notsuffix") != NULL)
				c->notrealm = 1;
		}

		c->next = realms;
		realms = c;
	}
	fclose(fp);

	return 0;
}
#endif /* BUILDDBM */

/*
 *	Find a realm in the REALM list.
 */
REALM *realm_find(const char *realm)
{
	REALM *cl;

	/*
	 *	If we're passed a NULL realm pointer,
	 *	then look for a "NULL" realm string.
	 */
	if (realm == NULL) {
		realm = "NULL";
	}

	for(cl = realms; cl; cl = cl->next)
		if (strcmp(cl->realm, realm) == 0)
			break;
	if (cl != NULL) 
		return cl;
	for(cl = realms; cl; cl = cl->next)
		if (strcmp(cl->realm, "DEFAULT") == 0)
			break;
	return cl;
}


/*
 *	Find a realm for a proxy reply by proxy's IP
 */
REALM *realm_findbyaddr(uint32_t ipaddr)
{
	REALM *cl;

	for(cl = realms; cl != NULL; cl = cl->next)
		if (ipaddr == cl->ipaddr)
			break;

	return cl;
}
