/*
 * files.c	Read config files into memory.
 *
 * Version:     $Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/time.h>
#include	<sys/stat.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<netdb.h>
#include	<time.h>
#include	<ctype.h>
#include	<fcntl.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"
#include	"modules.h"

CLIENT			*clients;
#ifndef WITH_NEW_CONFIG
static
#endif
REALM			*realms;

#ifdef WITH_NEW_CONFIG
extern int read_new_config_files(void);
#endif



/*
 *	Free a PAIR_LIST
 */
void pairlist_free(PAIR_LIST **pl)
{
	PAIR_LIST *p, *next;

	for (p = *pl; p; p = next) {
		if (p->name) free(p->name);
		if (p->check) pairfree(p->check);
		if (p->reply) pairfree(p->reply);
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
	VALUE_PAIR	*vp;
	VALUE_PAIR	*c = NULL;
	int		n = 0;

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
	 *	FIXME: put Auth-Type _first_ (doesn't matter now,
	 *	might matter some day).
	 *	
	 */
	if ((vp = paircreate(PW_AUTHTYPE, PW_TYPE_INTEGER)) == NULL) {
		log(L_CONS|L_ERR, "no memory");
		exit(1);
	}
	vp->lvalue = n;
	vp->operator = T_OP_SET;

	vp->next = c->next;
	c->next = vp;

}


#define FIND_MODE_NAME	0
#define FIND_MODE_REPLY	1

/*
 *	Read the users, huntgroups or hints file.
 *	Return a PAIR_LIST.
 */
PAIR_LIST *pairlist_read(const char *file, int complain)
{
	FILE		*fp;
	int		mode = FIND_MODE_NAME;
	char		entry[256];
	char		buffer[256];
	char		*ptr, *s;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	PAIR_LIST	*pl = NULL, *last = NULL, *t;
	int		lineno = 0;
	int		old_lineno = 0;

	/*
	 *	Open the table
	 */
	if ((fp = fopen(file, "r")) == NULL) {
		if (!complain) return NULL;
		log(L_CONS|L_ERR, "Couldn't open %s for reading", file);
		return NULL;
	}

	/*
	 *	Read the entire file into memory for speed.
	 */
	while(fgets(buffer, sizeof(buffer), fp) != NULL) {
		lineno++;
		if (strchr(buffer, '\n') == NULL) {
			log(L_ERR, "%s[%d]: line too long", file, lineno);
			pairlist_free(&pl);
			return NULL;
		}
		if (buffer[0] == '#' || buffer[0] == '\n') continue;
parse_again:
		if(mode == FIND_MODE_NAME) {
			/*
			 *	Find the entry starting with the users name
			 */
			if (isspace(buffer[0])) continue;

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
				if ((t = pairlist_read(s, 1)) == NULL)
					continue;
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
			if(userparse(ptr, &check_tmp) != 0) {
				pairlist_free(&pl);
				log(L_ERR|L_CONS,
				"%s[%d]: Parse error (check) for entry %s: %s",
					file, lineno, entry, librad_errstr);
				fclose(fp);
				return NULL;
			}
			mode = FIND_MODE_REPLY;
		}
		else {
			if(*buffer == ' ' || *buffer == '\t') {
				/*
				 *	Parse the reply values
				 */
				if (userparse(buffer, &reply_tmp)!=0) {
					pairlist_free(&pl);
					log(L_ERR|L_CONS,
				"%s[%d]: Parse error (reply) for entry %s: %s",
					    file, lineno, entry, librad_errstr);
					fclose(fp);
					return NULL;
				}
			}
			else {
				/*
				 *	Done with this entry...
				 */
				if ((t = malloc(sizeof(PAIR_LIST))) == NULL) {
					perror(progname);
					exit(1);
				}
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

	return pl;
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

/*
 *	Free a CLIENT list.
 */
static void clients_free(CLIENT *cl)
{
	CLIENT *next;

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
	CLIENT	*c;
	char	buffer[256];
	char	hostnm[256];
	char	secret[256];
	char	shortnm[256];
	int	lineno = 0;
	char	*p;

	clients_free(clients);
	clients = NULL;

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
		    !getword(&p, secret, sizeof(secret))) {
			log(L_ERR, "%s[%d]: unexpected end of line",
			    file, lineno);
			return -1;
		}

		(void)getword(&p, shortnm, sizeof(shortnm));

		/*
		 *	Double-check lengths to be sure they're sane
		 */
		if (strlen(hostnm) >= sizeof(c->longname)) {
			log(L_ERR, "%s[%d]: host name of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(hostnm), sizeof(c->longname) - 1);
			return -1;
		}
		if (strlen(secret) >= sizeof(c->secret)) {
			log(L_ERR, "%s[%d]: secret of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(secret), sizeof(c->secret) - 1);
			return -1;
		}
		if (strlen(shortnm) > sizeof(c->shortname)) {
			log(L_ERR, "%s[%d]: short name of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(shortnm), sizeof(c->shortname) - 1);
			return -1;
		}
		
		/*
		 *	It should be OK now, let's create the buffer.
		 */
		if ((c = malloc(sizeof(CLIENT))) == NULL) {
			log(L_CONS|L_ERR, "%s[%d]: out of memory",
				file, lineno);
			return -1;
		}

		c->ipaddr = ip_getaddr(hostnm);
		if (c->ipaddr == 0) {
			log(L_CONS|L_ERR, "%s[%d]: Failed to look up hostname %s",
			    file, lineno, hostnm);
			return -1;
		}
		strcpy(c->secret, secret);
		strcpy(c->shortname, shortnm);
		strcpy(c->longname, ip_hostname(c->ipaddr));

		c->next = clients;
		clients = c;
	}
	fclose(fp);

	return 0;
}


/*
 *	Find a client in the CLIENTS list.
 */
CLIENT *client_find(UINT4 ipaddr)
{
	CLIENT *cl;

	for(cl = clients; cl; cl = cl->next)
		if (ipaddr == cl->ipaddr)
			break;

	return cl;
}


/*
 *	Find the name of a client (prefer short name).
 */
char *client_name(UINT4 ipaddr)
{
	CLIENT *cl;

	if ((cl = client_find(ipaddr)) != NULL) {
		if (cl->shortname[0])
			return cl->shortname;
		else
			return cl->longname;
	}
	return ip_hostname(ipaddr);
}

#ifndef BUILDDBM /* HACK HACK */

/*
 *	Free a REALM list.
 */
#ifndef WITH_NEW_CONFIG
static
#endif
void realm_free(REALM *cl)
{
	REALM *next;

	while(cl) {
		next = cl->next;
		free(cl);
		cl = next;
	}
}

#ifndef WITH_NEW_CONFIG
/*
 *	Read the realms file.
 */
static int read_realms_file(const char *file)
{
	FILE	*fp;
	char	buffer[256];
	char	realm[256];
	char	hostnm[256];
	char	opts[256];
	char	*s, *p;
	int	lineno = 0;
	REALM	*c;

	realm_free(realms);
	realms = NULL;

	if ((fp = fopen(file, "r")) == NULL) {
#if 1 /* For now - realms file is not obligatory */
		return 0;
#else
		log(L_CONS|L_ERR, "cannot open %s", file);
		return -1;
#endif
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
		if (!getword(&p, realm, sizeof(realm)) ||
		    !getword(&p, hostnm, sizeof(hostnm))) {
			log(L_ERR, "%s[%d]: syntax error", file, lineno);
			continue;
		}

		if ((c = malloc(sizeof(REALM))) == NULL) {
			log(L_CONS|L_ERR, "%s[%d]: out of memory",
				file, lineno);
			return -1;
		}
		memset(c, 0, sizeof(REALM));

		if ((s = strchr(hostnm, ':')) != NULL) {
			*s++ = 0;
			c->auth_port = atoi(s);
			c->acct_port = c->auth_port + 1;
		} else {
			c->auth_port = auth_port;
			c->acct_port = acct_port;
		}
		if (strcmp(hostnm, "LOCAL") != 0)
			c->ipaddr = ip_getaddr(hostnm);
		if (c->ipaddr == 0) {
			log(L_CONS|L_ERR, "%s[%d]: Failed to look up hostname %s",
			    file, lineno, hostnm);
			return -1;
		}

		/*
		 *	Double-check lengths to be sure they're sane
		 */
		if (strlen(hostnm) >= sizeof(c->server)) {
			log(L_ERR, "%s[%d]: server name of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(hostnm), sizeof(c->server) - 1);
			return -1;
		}
		if (strlen(realm) > sizeof(c->realm)) {
			log(L_ERR, "%s[%d]: realm of length %d is greater than the allowed maximum of %d.",
			    file, lineno,
			    strlen(realm), sizeof(c->realm) - 1);
			return -1;
		}

		/*
		 *	OK, they're sane, copy them over.
		 */
		strcpy(c->realm, realm);
		strcpy(c->server, hostnm);
		c->striprealm = 1;

		while (getword(&p, opts, sizeof(opts))) {
			if (strcmp(opts, "nostrip") == 0)
				c->striprealm = 0;
			if (strstr(opts, "noacct") != NULL)
				c->acct_port = 0;
			if (strstr(opts, "trusted") != NULL)
				c->trusted = 1;
			if (strstr(opts, "notsuffix") != NULL)
				c->notsuffix = 1;
		}

		c->next = realms;
		realms = c;
	}
	fclose(fp);

	return 0;
}
#endif /* WITH_NEW_CONFIG */
#endif /* BUILDDBM */

/*
 *	Find a realm in the REALM list.
 */
REALM *realm_find(const char *realm)
{
	REALM *cl;

	for(cl = realms; cl; cl = cl->next)
		if (strcmp(cl->realm, realm) == 0)
			break;
	if (cl) return cl;
	for(cl = realms; cl; cl = cl->next)
		if (strcmp(cl->realm, "DEFAULT") == 0)
			break;
	return cl;
}


#ifndef BUILDDBM /* HACK HACK */

/*
 *	(Re-) read the configuration files.
 */
int read_config_files()
{
	char buffer[256];

        /* Initialize the dictionary */
	if (dict_init(radius_dir, RADIUS_DICTIONARY) != 0) {
	        log(L_ERR|L_CONS, "Errors reading dictionary: %s",
		    librad_errstr);
		return -1;
	}

	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_MODULES);
	if (read_modules_file(buffer) < 0) {
	        log(L_ERR|L_CONS, "Errors reading modules");
		return -1;
	}

	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_NASLIST);
	if (read_naslist_file(buffer) < 0) {
	        log(L_ERR|L_CONS, "Errors reading naslist");
		return -1;
	}

#ifndef WITH_NEW_CONFIG
	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_CLIENTS);
	if (read_clients_file(buffer) < 0) {
	        log(L_ERR|L_CONS, "Errors reading clients");
		return -1;
	}

	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_REALMS);
	if (read_realms_file(buffer) < 0) {
	        log(L_ERR|L_CONS, "Errors reading realms");
		return -1;
	}
#else
	read_new_config_files();
#endif
	return 0;
}

#endif

