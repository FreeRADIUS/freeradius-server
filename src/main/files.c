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

extern int proxy_dead_time;
int maximum_proxies;

REALM *realms = NULL;

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
 *	If User-Password or Crypt-Password is set, but there is no
 *	Auth-Type, add one (kludge!).
 */
static void auth_type_fixup(VALUE_PAIR **check)
{
	VALUE_PAIR *vp;
	VALUE_PAIR *c = NULL;
	int n = 0;

	/*
	 *	See if a password is present. Return right away
	 *	if we see Auth-Type.
	 */
	for (vp = *check; vp; vp = vp->next) {
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
	strcpy(vp->strvalue, "Local");

	vp->next = *check;
	*check = vp;

	for(vp = *check; vp; vp = vp->next) {
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
	LRAD_TOKEN parsecode;
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
		if (!feof(fp) && (strchr(buffer, '\n') == NULL)) {
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
			if (isspace((int) buffer[0]))  {
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
				while(isspace((int) *ptr))
					ptr++;
				s = ptr;
				while (!isspace((int) *ptr))
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
			if (parsecode == T_INVALID) {
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
				/* valid tokens are 1 or greater */
				if (parsecode < 1) {
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

				auth_type_fixup(&check_tmp);
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
	REALM *c, **tail;

	realm_free(realms);
	realms = NULL;
	tail = &realms;

	if ((fp = fopen(file, "r")) == NULL) {
		/* The realms file is not mandatory.  If it exists it will
		   be used, however, since the new style config files are
		   more robust and flexible they are more likely to get used.
		   So this is a non-fatal error.  */
		return 0;
	}
	while(fgets(buffer, 256, fp) != NULL) {
		lineno++;
		if (!feof(fp) && (strchr(buffer, '\n') == NULL)) {
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
			c->auth_port = PW_AUTH_UDP_PORT;
			c->acct_port = PW_ACCT_UDP_PORT;
		}

		if (strcmp(hostnm, "LOCAL") == 0) {
			/*
			 *	Local realms don't have an IP address,
			 *	secret, or port.
			 */
			c->acct_ipaddr = c->ipaddr = htonl(INADDR_NONE);
			c->secret[0] = '\0';
			c->auth_port = auth_port;
			c->acct_port = acct_port;

		} else {
			RADCLIENT *client;
			c->ipaddr = ip_getaddr(hostnm);
			c->acct_ipaddr = c->ipaddr;

			if (c->ipaddr == htonl(INADDR_NONE)) {
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
		}

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
		c->active = TRUE;
		c->acct_active = TRUE;

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

		c->next = NULL;
		*tail = c;
		tail = &c->next;
	}
	fclose(fp);

	return 0;
}
#endif /* BUILDDBM */

/*
 * Mark a host inactive
 */
void realm_disable(uint32_t ipaddr, int port)
{
	REALM *cl;
	time_t now;

	now = time(NULL);
	for(cl = realms; cl; cl = cl->next)
		if ((ipaddr == cl->ipaddr) && (port == cl->auth_port)) {
			cl->active = FALSE;
			cl->wakeup = now + proxy_dead_time;
			radlog(L_PROXY, "marking authentication server %s:%d for realm %s dead",
				cl->server, port, cl->realm);
		} else if ((ipaddr == cl->acct_ipaddr) && (port == cl->acct_port)) {
			cl->acct_active = FALSE;
			cl->acct_wakeup = now + proxy_dead_time;
			radlog(L_PROXY, "marking accounting server %s:%d for realm %s dead",
				cl->server, port, cl->realm);
		}
}

/*
 *	Find a realm in the REALM list.
 */
REALM *realm_find(const char *realm, int acct)
{
	REALM *cl, *realmptr;
	REALM *default_realm = NULL;
	REALM *rr_array[maximum_proxies];
	time_t now;
	int dead_match = 0, efform = 0, p = 0, i = 0;
	static int proxy_return;

	now = time(NULL);
	/*
	 *	If we're passed a NULL realm pointer,
	 *	then look for a "NULL" realm string.
	 */
	if (realm == NULL) {
		realm = "NULL";
	}
	
	for (cl = realms; cl; cl = cl->next) {
		/*
		 *	Wake up any sleeping realm.
		 */
		if (cl->wakeup <= now) {
			cl->active = TRUE;
		}
		if (cl->acct_wakeup <= now) {
			cl->acct_active = TRUE;
		}

		/*
		 *	Asked for auth/acct, and the auth/acct server
		 *	is not active.  Skip it.
		 */
		if ((!acct && !cl->active) ||
		    (acct && !cl->acct_active)) {

			/*
			 *	We've been asked to NOT fall through
			 *	to the DEFAULT realm if there are
			 *	exact matches for this realm which are
			 *	dead.
			 */
			if ((!proxy_fallback) &&
			    (strcasecmp(cl->realm, realm) == 0)) {
				dead_match = 1;
			}
			continue;
		}

		/*
		 *	If it matches exactly, return it.
		 */
		if (strcasecmp(cl->realm, realm) == 0) {
                        /*
                         *    Seperate parsing of list for round-robin
                         */
			if(cl->total > 1 && cl->ldflag == 1) {
				/*Get all of the realms from initial list*/
				for(i = 1; i <= cl->total; i++) {
					for(realmptr = realms; realmptr; 
                                            realmptr = realmptr->next) {
						if((strcasecmp(realmptr->realm,
                                                   cl->realm)) == 0 &&
						   (realmptr->node == i)) {
							rr_array[i] = realmptr;
							if(realmptr->active == TRUE)
								p++;
							break;
						}
						else {
							continue;
						}
					}
				}
				/*if only one realm active, return it*/
				if(p == 1) {
					for (p = 1; p < i; p++) {
						realmptr = rr_array[p];
						if(realmptr->active == TRUE) {
							return realmptr;
						}
					}
				}
				for(p = 1; p < i; p++) {
					realmptr = rr_array[p];
					if(realmptr->chose == 1) {
						efform++;
					}
				}

				/*    
                                 *    if none available, 
				 *    and last realm has
				 *    been returned as access-reply
                                 */

				if(efform == cl->total && proxy_return == 0) {
					for(p = 1; p < i; p++) {
						realmptr = rr_array[p];
						realmptr->chose = 0;
					}
				}

				/*    
                                 *    if this realm hasn't been chosen and 
				 *    this is not being returned for
                                 *    access reply
				 *    else if the realm has been chosen 
                                 *    and this is for access-reply
                                 *    else this realm is dead (reset if
				 *    this is the last realm in the list)
				 */

                                for(p = 1; p < i; p++) {
					realmptr = rr_array[p];
					if((realmptr->chose == 0) &&
                                           (proxy_return < realmptr->node) &&
					   (realmptr->active == TRUE && realmptr->acct_active == TRUE)
                                        ) {
						proxy_return = realmptr->node;
						realmptr->chose = 1;
						return realmptr;
					}
					else if ((realmptr->chose == 1) &&
						 (proxy_return == realmptr->node)
                                        ) {
						if(proxy_return + 1 > realmptr->total) {
							proxy_return = 0;
						}
						realmptr->chose = 0;
						return realmptr;
					}
					else 
					{
						if((realmptr->active == FALSE ||
						    realmptr->acct_active == FALSE ) &&
						   (realmptr->node == realmptr->total)
                                                ) {
							proxy_return = 0;
						}
						continue;
					}
				}
			}
			
			/*    
			 *    else we have single 
                         *    realm or non-rr realm
                         */
			
			else {
				return cl;
			}
		}

		/*
		 *	No default realm, try to set one.
		 */
		if ((default_realm == NULL) &&
		    (strcmp(cl->realm, "DEFAULT") == 0)) {
		  default_realm = cl;
		}
	} /* loop over all realms */

	/*
	 *	There WAS one or more matches which were marked dead,
	 *	AND there were NO live matches, AND we've been asked
	 *	to NOT fall through to the DEFAULT realm.  Therefore,
	 *	we return NULL, which means "no match found".
	 */
	if (!proxy_fallback && dead_match) {
		return NULL;
	}

	/*
	 *	Didn't find anything that matched exactly, return the
	 *	DEFAULT realm.  We also return the DEFAULT realm if
	 *	all matching realms were marked dead, and we were
	 *	asked to fall through to the DEFAULT realm in this
	 *	case.
	 */
	return default_realm;
}

/*
 *	Find a realm for a proxy reply by proxy's IP
 */
REALM *realm_findbyaddr(uint32_t ipaddr, int port)
{
	REALM *cl;

	/*
	 *	Note that we do NOT check for inactive realms!
	 *
	 *	If we get a packet from an end server, then we mark it
	 *	as active, and return the realm.
	 */
	for(cl = realms; cl != NULL; cl = cl->next)
		if ((ipaddr == cl->ipaddr) && (port == cl->auth_port)) {
			cl->active = TRUE;
			return cl;
		} else if ((ipaddr == cl->acct_ipaddr) && (port == cl->acct_port)) {
			cl->acct_active = TRUE;
			return cl;
		}

	return NULL;
}

/*
 *    Catch any errors in set-up of RR list or exceeding max_proxies
 */
void check_proxies(int max_config) {
	REALM *next, *rptr;
	if(max_config > 0) {
		maximum_proxies = max_config;
		for(rptr=realms; rptr; rptr = rptr->next) {
			if(rptr->total > max_config || rptr->total >= 1) {
				for(next = realms; next; next = next->next) {
					if(next->ldflag != 0 &&
                                           next->ldflag != 1) {
						radlog(L_ERR,
						    "Invalid load balance flag on realm: %s entry %d\n",
                                                     next->realm, next->node);
						exit(1);
					}
					else if((strcasecmp(rptr->realm, next->realm) == 0) && 
                                            rptr->ldflag != next->ldflag){ 
                                               radlog(L_ERR,
                                                   "Inconsistent ldflag for realm: %s entries %d and %d.\n", 
                                                    rptr->realm, rptr->node, next->node);
					       exit(1);
					}
				        else if (next->total > max_config) {
				            radlog(L_ERR,
				                "Too many entries (%d) for realm: %s. Max is %d.\n",
 				 	         next->total, next->realm, max_config);
				            exit(1);
				        }
				}
			}
		}
		maximum_proxies++;
	}
}
