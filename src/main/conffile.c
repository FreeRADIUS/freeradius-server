/*
 * conffile.c	Read the radius.conf file.
 *
 *		Yep I should learn to use lex & yacc, or at least
 *		write a decent parser. I know how to do that, really :)
 *		miquels@cistron.nl
 *
 * Version:	$Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "radiusd.h"
#include "conffile.h"
#include "token.h"
#include "modules.h"

#ifdef WITH_NEW_CONFIG

#define xalloc malloc
#define xstrdup strdup

CONF_SECTION	*config;
extern RADCLIENT  *clients;
extern REALM	*realms;
extern void realm_free(REALM *cl);

static int generate_realms();
static int generate_clients();

#ifndef RADIUS_CONFIG
#define RADIUS_CONFIG "radius.conf"
#endif

/*
 *	Create a new CONF_PAIR
 */
CONF_PAIR *cf_pair_alloc(const char *attr, const char *value, int operator)
{
	CONF_PAIR	*cp;

	cp = (CONF_PAIR *)xalloc(sizeof(CONF_PAIR));
	memset(cp, 0, sizeof(CONF_PAIR));
	cp->attr = xstrdup(attr);
	cp->value = xstrdup(value);
	cp->operator = operator;

	return cp;
}

/*
 *	Add a pair to a configuration section.
 */
void cf_pair_add(CONF_SECTION *cs, CONF_PAIR *cp_new)
{
	CONF_PAIR *cp;
	
	for (cp = cs->cps; cp && cp->next; cp = cp->next)
		;

	if (cp == NULL)
		cs->cps = cp_new;
	else
		cp->next = cp_new;
}

/*
 *	Free a CONF_PAIR
 */
void cf_pair_free(CONF_PAIR *cp)
{
	if (cp == NULL) return;

	if (cp->attr)  free(cp->attr);
	if (cp->value) free(cp->value);
	free(cp);
}

/*
 *	Allocate a CONF_SECTION
 */
CONF_SECTION *cf_section_alloc(const char *name1, const char *name2)
{
	CONF_SECTION	*cs;

	if (name1 == NULL) name1 = "main";
	if (name2 == NULL) name2 = "main";

	cs = (CONF_SECTION *)xalloc(sizeof(CONF_SECTION));
	memset(cs, 0, sizeof(CONF_SECTION));
	cs->name1 = xstrdup(name1);
	cs->name2 = xstrdup(name2);

	return cs;
}

/*
 *	Free a CONF_SECTION
 */
void cf_section_free(CONF_SECTION *cs)
{
	CONF_PAIR	*cp, *next;
	CONF_SECTION *sub, *next_sub;

	if (cs == NULL) return;

	for (cp = cs->cps; cp; cp = next) {
		next = cp->next;
		cf_pair_free(cp);
	}

	/*
	 * Clear out any possible subsections aswell
	 */
	for (sub = cs->sub; sub; sub = next_sub) {
		next_sub = sub->next;
		cf_section_free(sub);
	}

	if (cs->name1) free(cs->name1);
	if (cs->name2) free(cs->name2);

	/*
	 * And free the section
	 */
	free(cs);
}

/*
 * Free _all_ in a CONF_SECTION and below
 */

void cf_section_free_all(CONF_SECTION *cs)
{

}
/*
 *	Read a part of the config file.
 */
static CONF_SECTION *conf_readsection(const char *cf, int *lineno, FILE *fp,
				const char *name1, const char *name2)
{
	CONF_SECTION	*cs, *csn, *csp, *css;
	CONF_PAIR	*cpn;
	char		*ptr;
	char		buf[1024];
	char		buf1[256];
	char		buf2[256];
	char		buf3[256];
	int		t1, t2, t3;

	/*
	 *	Ensure that the user can't add CONF_SECTIONs
	 *	with 'internal' names;
	 */
	if ((name1 != NULL) && (name1[0] == '_')) {
		log(L_ERR, "%s[%d]: Illegal configuration section name",
		    cf, *lineno);
		return NULL;
	}

	/*
	 *	Allocate new section.
	 */
	cs = cf_section_alloc(name1, name2);

	/*
	 *	Read.
	 */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		(*lineno)++;
		ptr = buf;

		t1 = gettoken(&ptr, buf1, sizeof(buf1));
		t2 = gettoken(&ptr, buf2, sizeof(buf2));
		t3 = gettoken(&ptr, buf3, sizeof(buf3));

		if (buf1[0] == 0 || buf1[0] == '#')
			continue;

		/*
		 *	See if it's the end of a section.
		 */
		if (t1 == T_RCBRACE) {
			if (name1 == NULL || buf2[0]) {
				log(L_ERR, "%s[%d]: syntax error #1",
					cf, *lineno);
				return NULL;
			}
			return cs;
		}

		/*
		 * Perhaps a subsection.
		 */

		if (t2 == T_LCBRACE) {
			css = conf_readsection(cf, lineno, fp, name2, buf1);
			if (css == NULL)
				return NULL;
			for (csp = cs->sub; csp && csp->next; csp = csp->next)
				;
			if (csp == NULL)
				cs->sub = css;
			else
				csp->next = css;

			continue;		
		}

		/*
		 *	Or, the beginning of a new section.
		 */
		if (t3 == T_LCBRACE) {
			csn = conf_readsection(cf, lineno, fp, buf1, buf2);
			if (csn == NULL)
				return NULL;
			/*
			 *	Add this section after all others.
			 */
			for (csp = cs; csp && csp->next; csp = csp->next)
				;
			if (csp == NULL)
				cs = csn;
			else
				csp->next = csn;
			continue;
		}

		/*
		 *	Must be a normal attr = value line.
		 */
		if (buf1[0] != 0 && buf2[0] == 0 && buf3[0] == 0) {
			t2 = T_OP_EQ;
		} else if (buf1[0] == 0 || buf2[0] == 0 || buf3[0] == 0 ||
			  (t2 < T_EQSTART || t2 > T_EQEND)) {
			log(L_ERR, "%s[%d]: syntax error #2",
				cf, *lineno);
			return NULL;
		}

		/*
		 *	Ensure that the user can't add CONF_PAIRs
		 *	with 'internal' names;
		 */
		if (buf1[0] == '_') {
			log(L_ERR, "%s[%d]: Illegal configuration pair name",
				cf, *lineno);
			return NULL;
		}

		/*
		 *	Add this CONF_PAIR to our CONF_SECTION
		 */
		cpn = cf_pair_alloc(buf1, buf3, t2);
		cf_pair_add(cs, cpn);
	}

	/*
	 *	See if EOF was unexpected ..
	 */
	if (name1 != NULL) {
		log(L_ERR,	
			"%s[%d]: unexpected end of file", cf, *lineno);
		return NULL;
	}

	return cs;
}

/*
 *	Read the config file.
 */
CONF_SECTION *conf_read(const char *conffile)
{
	FILE		*fp;
	int		lineno = 0;

	cf_section_free(config);
	config = NULL;	

	if ((fp = fopen(conffile, "r")) == NULL) {
		log(L_ERR, "cannot open %s: %s",
			conffile, strerror(errno));
		return NULL;
	}

	config = conf_readsection(conffile, &lineno, fp, NULL, NULL);
	fclose(fp);

	return config;
}

/* JLN
 * Read the configuration and library
 * This uses the new kind of configuration file as defined by
 * Miquel at http://www.miquels.cistron.nl/radius/
 */

int read_new_config_files(void)
{
	char buffer[256];

	/* Lets go for the new configuration files */

	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_CONFIG);
	if (conf_read(buffer) == NULL) {
		log(L_ERR|L_CONS, "Error reading new-style configuration file");
		return -1;
	}

	/* JLN
	 * After this we should run
	 * generate_realms() and generate_clients()
	 *
	 * Fail if we can't generate list of clients
	 */

	if (generate_clients() < 0) {
		log(L_ERR|L_CONS, "Error generation clients list");
		return -1;
	}

	/*
	 * If there isn't any realms it isn't fatal..
	 */
	if (generate_realms() < 0) {
		log(L_ERR|L_CONS, "Error generation realms list");
	}


	return 0;	
}

/* JLN
 * Create the linked list of realms from the new configuration type
 * This way we don't have to change to much in the other source-files
 */

static int generate_realms() 
{
	CONF_SECTION	*cs;
	REALM			*c;
	char			*s, *authhost, *accthost;

	realm_free(realms);
	realms = NULL;

	for (cs = config; cs; cs = cs->next) {
		if (strcmp(cs->name1, "realm") == 0) {
			/*
			 * We've found a realm, allocate space for it
			 */
			if ((c = malloc(sizeof(REALM))) == NULL) {
				log(L_CONS|L_ERR, "Out of memory while generating realms list");
				return -1;
			}
			memset(c, 0, sizeof(REALM));
			/*
			 * An authhost must exist in the configuration
			 */
			if ((authhost = cf_section_value_find(cs, "authhost")) == NULL) {
				log(L_CONS|L_ERR, 
					"No authhost entry for realm: %s", 
					cs->name2);
				return -1;
			}
			if ((s = strchr(authhost, ':')) != NULL) {
				*s++ = 0;
				c->auth_port = atoi(s);
			} else {
				c->auth_port = auth_port;
			}
			accthost = cf_section_value_find(cs, "accthost");
			if ((s =strchr(accthost, ':')) != NULL) {
				*s++ = 0;
				c->acct_port = atoi(s);	
			} else {
				c->acct_port = acct_port;
			}
			if (strcmp(authhost, "LOCAL") != 0)
				c->ipaddr = ip_getaddr(authhost);

			/* 
			 * Double check length, just to be sure!
			 */

			if (strlen(authhost) >= sizeof(c->server)) {
				log(L_ERR, "[%s] servername of length %d is greater that allowed: %d",
					authhost, strlen(authhost), 
					sizeof(c->server) - 1);
				return -1;
			}
			if (strlen(cs->name2) >= sizeof(c->realm)) {
				log(L_ERR, "[%s] realm of length %d is greater that allowed: %d",
					cs->name2, strlen(cs->name2), 
					sizeof(c->server) - 1);
				return -1;
			}
			
			strcpy(c->realm, cs->name2);
			strcpy(c->server, authhost);	
			c->striprealm = 1;
			
			if ((cf_section_value_find(cs, "nostrip")) != NULL)
				c->striprealm = 0;
			if ((cf_section_value_find(cs, "noacct")) != NULL)
				c->acct_port = 0;
			if ((cf_section_value_find(cs, "trusted")) != NULL)
				c->acct_port = 0;

			c->next = realms;
			realms = c;

		}
	}

	return 0;
}

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

/* JLN
 * Create the linked list of realms from the new configuration type
 * This way we don't have to change to much in the other source-files
 */

static int generate_clients() 
{
	CONF_SECTION	*cs;
	RADCLIENT	*c;
	char		*hostnm, *secret, *shortnm;

	clients_free(clients);
	clients = NULL;

	for (cs = config; cs; cs = cs->next) {
		if (strcmp(cs->name1, "client") == 0) {
			/*
			 * Check the lengths, we don't want any core dumps
			 */
			hostnm = cs->name2;
			secret = cf_section_value_find(cs, "secret");
			shortnm = cf_section_value_find(cs, "shortname");

			if (strlen(secret) >= sizeof(c->secret)) {
				log(L_ERR, "[%s]: secret of length %d is greater than the allowed maximum of %d.",
				    hostnm,
				    strlen(secret), sizeof(c->secret) - 1);
				return -1;
			}
			if (strlen(shortnm) > sizeof(c->shortname)) {
				log(L_ERR, "[%s]: short name of length %d is greater than the allowed maximum of %d.",
				    hostnm,
				    strlen(shortnm), sizeof(c->shortname) - 1);
				return -1;
			}
			/*
			 * The size is fine.. Let's create the buffer
			 */
			if ((c = malloc(sizeof(RADCLIENT))) == NULL) {
				log(L_CONS|L_ERR, "[%s]: out of memory while doint client",
					hostnm);
				return -1;
			}

			c->ipaddr = ip_getaddr(hostnm);
			strcpy(c->secret, secret);
			strcpy(c->shortname, shortnm);
			strcpy(c->longname, ip_hostname(c->ipaddr));

			c->next = clients;
			clients = c;
		}
	}

	return 0;
}

/* 
 * Return a CONF_PAIR within a CONF_SECTION.
 */

CONF_PAIR *cf_pair_find(CONF_SECTION *section, const char *name)
{
	CONF_PAIR	*cp;

	for (cp = section->cps; cp; cp = cp->next)
		if (strcmp(cp->attr, name) == 0)
			break;

	return cp;
}

/*
 * Return the value of a CONF_PAIR
 */

char *cf_pair_value(CONF_PAIR *pair)
{
	return (pair ? pair->value : NULL);
}


/* 
 * Find a value in a CONF_SECTION
 */
char *cf_section_value_find(CONF_SECTION *section, const char *attr)
{
	CONF_PAIR	*cp;

	cp = cf_pair_find(section, attr);

	return (cp ? cp->value : NULL);
}

/*
 * Return the next pair after a CONF_PAIR
 * with a certain name (char *attr)
 */

CONF_PAIR *cf_pair_find_next(CONF_SECTION *section, CONF_PAIR *pair, const char *attr)
{
	CONF_PAIR	*cp;

	/*
	 * If pair is NULL this must be a first time run
	 * Find the pair with correct name
	 */

	if (pair == NULL){
		cp = cf_pair_find(section, attr);
	} else {
		cp = pair->next;
	}

	for (; cp; cp = cp->next)
		if (strcmp(cp->attr, attr) == 0)
			break;

	return cp;
}

/*
 * Find a CONF_SECTION
 */

CONF_SECTION *cf_section_find(const char *name)
{
	CONF_SECTION *cs;
	
	for (cs = config; cs; cs = cs->next)
		if (strcmp(cs->name1, name) == 0)
			break;

	return cs;
}

/*
 * Find a sub-section in a section
 */

CONF_SECTION *cf_section_sub_find(CONF_SECTION *section, const char *name) {

	CONF_SECTION *cs;
	for (cs = section->sub; cs; cs = cs->next)
		if (strcmp(cs->name2, name) == 0)
			break;
	
	return cs;

}

/*
 * Find the configuration section for a module
 */

CONF_SECTION *cf_module_config_find(const char *modulename)
{
	CONF_SECTION *cs;

	for (cs = config; cs; cs = cs->next)
		if ((strcmp(cs->name1, "module") == 0)
			&& (strcmp(cs->name2, modulename) == 0))
			break;

	return cs;
}
#endif
