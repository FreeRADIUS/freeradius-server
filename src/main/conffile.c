/*
 * conffile.c	Read the radiusd.conf file.
 *
 *		Yep I should learn to use lex & yacc, or at least
 *		write a decent parser. I know how to do that, really :)
 *		miquels@cistron.nl
 *
 * Version:	$Id$
 *
 */

#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "radiusd.h"
#include "conffile.h"
#include "token.h"
#include "modules.h"

static const char rcsid[] =
"$Id$";

#define xalloc malloc
#define xstrdup strdup

CONF_SECTION	*config = NULL;

extern RADCLIENT *clients;
extern REALM	 *realms;

static int generate_realms(const char *filename);
static int generate_clients(const char *filename);

#ifndef RADIUS_CONFIG
#define RADIUS_CONFIG "radiusd.conf"
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

	if (name1 == NULL || !name1[0]) name1 = "main";

	cs = (CONF_SECTION *)xalloc(sizeof(CONF_SECTION));
	memset(cs, 0, sizeof(CONF_SECTION));
	cs->name1 = xstrdup(name1);
	cs->name2 = (name2 && *name2) ? xstrdup(name2) : NULL;

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
 *	Parse a configuration section into user-supplied variables.
 */
int cf_section_parse(CONF_SECTION *cs, const CONF_PARSER *variables)
{
	int		i;
	char      	**q;
	CONF_PAIR	*cp;
	uint32_t	ipaddr;
	char		buffer[1024];

	/*
	 *	Handle the user-supplied variables.
	 */
	for (i = 0; variables[i].name != NULL; i++) {
		cp = cf_pair_find(cs, variables[i].name);
		if (!cp) {
			continue;
		}
		
		switch (variables[i].type)
		{
		case PW_TYPE_BOOLEAN:
			/*
			 *	Allow yes/no and on/off
			 */
			if ((strcasecmp(cp->value, "yes") == 0) ||
			    (strcasecmp(cp->value, "on") == 0)) {
				*(int *)variables[i].data = 1;
			} else if ((strcasecmp(cp->value, "no") == 0) ||
				   (strcasecmp(cp->value, "off") == 0)) {
				*(int *)variables[i].data = 0;
			} else {
				*(int *)variables[i].data = 0;
				log(L_ERR, "Bad value \"%s\" for boolean variable %s", cp->value, cp->attr);
				return -1;
			}
			DEBUG2("Config: %s.%s = %s",
			       cs->name1,
			       variables[i].name,
			       cp->value);
			break;

		case PW_TYPE_INTEGER:
			*(int *)variables[i].data = atoi(cp->value);
			DEBUG2("Config: %s.%s = %d",
			       cs->name1,
			       variables[i].name,
			       *(int *)variables[i].data);
			break;
			
		case PW_TYPE_STRING_PTR:
			q = (char **) variables[i].data;
			if (*q != NULL) {
				free(*q);
			}
			DEBUG2("Config: %s.%s = \"%s\"",
			       cs->name1,
			       variables[i].name,
			       cp->value);
			*q = strdup(cp->value);
			break;

		case PW_TYPE_IPADDR:
			/*
			 *	Allow '*' as any address
			 */
			if (strcmp(cp->value, "*") == 0) {
				*(uint32_t *) variables[i].data = 0;
				break;
			}
			ipaddr = ip_getaddr(cp->value);
			if (ipaddr == 0) {
				log(L_ERR, "Can't find IP address for host %s", cp->value);
				return -1;
			}
			DEBUG2("Config: %s.%s = %s IP address [%s]",
			       cs->name1,
			       variables[i].name,
			       cp->value, ip_ntoa(buffer, ipaddr));
			*(uint32_t *) variables[i].data = ipaddr;
			break;
			
		default:
			log(L_ERR, "type %d not supported yet", variables[i].type);
			return -1;
			break;
		} /* switch over variable type */
	} /* for all variables in the configuration section */
	
	return 0;
}


/*
 *	Read a part of the config file.
 */
static CONF_SECTION *cf_section_read(const char *cf, int *lineno, FILE *fp,
				     const char *name1, const char *name2)
{
	CONF_SECTION	*cs, *csp, *css;
	CONF_PAIR	*cpn;
	char		*ptr, *p, *q;
	char		buf[8192];
	char		buf1[1024];
	char		buf2[1024];
	char		buf3[1024];
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
	 *	Allow for $INCLUDE files???
	 *
	 *	This sure looks wrong. But it looked wrong before I touched
	 *	the file, so don't blame me. Please, just pass the config
	 *	file through cpp or m4 and cut out the bloat. --Pac.
	 */
	if (name1 && strcasecmp(name1, "$INCLUDE") == 0) {
	  return conf_read(name2);
	}

	/*
	 *	Allocate new section.
	 */
	cs = cf_section_alloc(name1, name2);
	cs->lineno = *lineno;

	/*
	 *	Read.
	 */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		(*lineno)++;
		ptr = buf;

		if (*ptr == '#')
			continue;

		/*
		 *	No '=': must be a section or sub-section.
		 */
		if (strchr(ptr, '=') == NULL) {
			t1 = gettoken(&ptr, buf1, sizeof(buf1));
			t2 = gettoken(&ptr, buf2, sizeof(buf2));
			t3 = gettoken(&ptr, buf3, sizeof(buf3));
		} else {
			t1 = gettoken(&ptr, buf1, sizeof(buf1));
			t2 = gettoken(&ptr, buf2, sizeof(buf2));
			t3 = getword(&ptr, buf3, sizeof(buf3));
		}

		if (buf1[0] == 0 || buf1[0] == '#')
			continue;

		/*
		 *	See if it's the end of a section.
		 */
		if (t1 == T_RCBRACE) {
			if (name1 == NULL || buf2[0]) {
				log(L_ERR, "%s[%d]: Unexpected end of section",
					cf, *lineno);
				cf_section_free(cs);
				return NULL;
			}
			return cs;
		}

		/*
		 * Perhaps a subsection.
		 */

		if (t2 == T_LCBRACE || t3 == T_LCBRACE) {
			css = cf_section_read(cf, lineno, fp, buf1,
						t2==T_LCBRACE ? NULL : buf2);
			if (css == NULL) {
				cf_section_free(cs);
				return NULL;
			}
			for (csp = cs->sub; csp && csp->next; csp = csp->next)
				;
			if (csp == NULL)
				cs->sub = css;
			else
				csp->next = css;

			continue;		
		}

		/*
		 *	Must be a normal attr = value line.
		 */
		if (buf1[0] != 0 && buf2[0] == 0 && buf3[0] == 0) {
			t2 = T_OP_EQ;
		} else if (buf1[0] == 0 || buf2[0] == 0 || buf3[0] == 0 ||
			  (t2 < T_EQSTART || t2 > T_EQEND)) {
			log(L_ERR, "%s[%d]: Line is not in 'attribute = value' format",
				cf, *lineno);
			cf_section_free(cs);
			return NULL;
		}

		/*
		 *	Ensure that the user can't add CONF_PAIRs
		 *	with 'internal' names;
		 */
		if (buf1[0] == '_') {
			log(L_ERR, "%s[%d]: Illegal configuration pair name \"%s\"",
				cf, *lineno, buf1);
			cf_section_free(cs);
			return NULL;
		}
		
		/*
		 *	Handle variable substitution via ${foo}
		 */
		p = buf;
		ptr = buf3;
		while (*ptr >= ' ') {
			/*
			 *	Ignore anything other than "${"
			 */
			if ((*ptr != '$') ||
			    (ptr[1] != '{')) {
				*(p++) = *(ptr++);
				continue;
			}

			/*
			 *	Look for trailing '}', and silently
			 *	ignore anything that doesn't match.
			 */
			q = strchr(ptr, '}');
			if (q == NULL) {
				*(p++) = *(ptr++);
				continue;
			}
			
			memcpy(buf2, ptr + 2, q - ptr - 2);
			buf2[q - ptr - 2] = '\0';
			cpn = cf_pair_find(cs, buf2);
			if (!cpn) {
				log(L_ERR, "%s[%d]: Unknown variable \"%s\"",
				    cf, *lineno, buf2);
				cf_section_free(cs);
				return NULL;
			}
			strcpy(p, cpn->value);
			p += strlen(p);
			ptr = q + 1;
		}
		*p = '\0';

		/*
		 *	Add this CONF_PAIR to our CONF_SECTION
		 */
		cpn = cf_pair_alloc(buf1, buf, t2);
		cpn->lineno = *lineno;
		cf_pair_add(cs, cpn);
	}

	/*
	 *	See if EOF was unexpected ..
	 */
	if (name1 != NULL) {
		log(L_ERR, "%s[%d]: unexpected end of file", cf, *lineno);
		cf_section_free(cs);
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
	CONF_SECTION	*cs;
	
	if ((fp = fopen(conffile, "r")) == NULL) {
		log(L_ERR, "cannot open %s: %s",
			conffile, strerror(errno));
		return NULL;
	}

	cs = cf_section_read(conffile, &lineno, fp, NULL, NULL);
	fclose(fp);

	return cs;
}

/* JLN
 * Read the configuration and library
 * This uses the new kind of configuration file as defined by
 * Miquel at http://www.miquels.cistron.nl/radius/
 */

int read_radius_conf_file(void)
{
	char buffer[256];
	CONF_SECTION *cs;

	/* Lets go for the new configuration files */

	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_CONFIG);
	if ((cs = conf_read(buffer)) == NULL) {
		return -1;
	}

	/*
	 *	Free the old configuration data, and replace it
	 *	with the new one.
	 */
	cf_section_free(config);
	config = cs;
	


	/*
	 * Fail if we can't generate list of clients
	 */

	if (generate_clients(buffer) < 0) {
		return -1;
	}

	/*
	 * If there isn't any realms it isn't fatal..
	 */
	if (generate_realms(buffer) < 0) {
		return -1;
	}

	return 0;	
}

/* JLN
 * Create the linked list of realms from the new configuration type
 * This way we don't have to change to much in the other source-files
 */

static int generate_realms(const char *filename)
{
	CONF_SECTION	*cs;
	REALM		*c;
	char		*s, *authhost, *accthost;

	for (cs = config->sub; cs; cs = cs->next) {
		if (strcmp(cs->name1, "realm") == 0) {
			if (!cs->name2) {
				log(L_CONS|L_ERR, "%s[%d]: Missing realm name", filename, cs->lineno);
				return -1;
			}
			/*
			 * We've found a realm, allocate space for it
			 */
			if ((c = malloc(sizeof(REALM))) == NULL) {
				log(L_CONS|L_ERR, "Out of memory");
				return -1;
			}
			memset(c, 0, sizeof(REALM));
			/*
			 * An authhost must exist in the configuration
			 */
			if ((authhost = cf_section_value_find(cs, "authhost")) == NULL) {
				log(L_CONS|L_ERR, 
				    "%s[%d]: No authhost entry in realm", 
				    filename, cs->lineno);
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
				log(L_ERR, "%s[%d]: Server name of length %d is greater that allowed: %d",
				    filename, cs->lineno,
				    strlen(authhost), sizeof(c->server) - 1);
				return -1;
			}
			if (strlen(cs->name2) >= sizeof(c->realm)) {
				log(L_ERR, "%s[%d]: Realm name of length %d is greater than allowed %d",
				    filename, cs->lineno,
				    strlen(cs->name2), sizeof(c->server) - 1);
				return -1;
			}
			
			strcpy(c->realm, cs->name2);
			strcpy(c->server, authhost);	

			s = cf_section_value_find(cs, "secret");
			if (s == NULL) {
				log(L_ERR, "%s[%d]: No shared secret supplied for realm",
				    filename, cs->lineno);
				return -1;
			}

			if (strlen(s) >= sizeof(c->secret)) {
			  log(L_ERR, "%s[%d]: Secret of length %d is greater than the allowed maximum of %d.",
			      filename, cs->lineno,
			      strlen(s), sizeof(c->secret) - 1);
			  return -1;
			}
			strNcpy(c->secret, s, sizeof(c->secret));

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

/* JLN
 * Create the linked list of realms from the new configuration type
 * This way we don't have to change to much in the other source-files
 */

static int generate_clients(const char *filename)
{
	CONF_SECTION	*cs;
	RADCLIENT	*c;
	char		*hostnm, *secret, *shortnm;

	for (cs = config->sub; cs; cs = cs->next) {
		if (strcmp(cs->name1, "client") == 0) {
			if (!cs->name2) {
				log(L_CONS|L_ERR, "%s[%d]: Missing client name", filename, cs->lineno);
				return -1;
			}
			/*
			 * Check the lengths, we don't want any core dumps
			 */
			hostnm = cs->name2;
			secret = cf_section_value_find(cs, "secret");
			shortnm = cf_section_value_find(cs, "shortname");

			if (strlen(secret) >= sizeof(c->secret)) {
				log(L_ERR, "%s[%d]: Secret of length %d is greater than the allowed maximum of %d.",
				    filename, cs->lineno,
				    strlen(secret), sizeof(c->secret) - 1);
				return -1;
			}
			if (strlen(shortnm) > sizeof(c->shortname)) {
				log(L_ERR, "%s[%d]: NAS short name of length %d is greater than the allowed maximum of %d.",
				    filename, cs->lineno,
				    strlen(shortnm), sizeof(c->shortname) - 1);
				return -1;
			}
			/*
			 * The size is fine.. Let's create the buffer
			 */
			if ((c = malloc(sizeof(RADCLIENT))) == NULL) {
				log(L_CONS|L_ERR, "Out of memory");
				return -1;
			}

			c->ipaddr = ip_getaddr(hostnm);
			strcpy(c->secret, secret);
			strcpy(c->shortname, shortnm);
			ip_hostname(c->longname, sizeof(c->longname),
				    c->ipaddr);

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

	if (section == NULL) {
	  section = config;
	}

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
 * Find a CONF_SECTION, or return the root if name is NULL
 */

CONF_SECTION *cf_section_find(const char *name)
{
	if (name)
		return cf_section_sub_find(config, name);
	else
		return config;
}

/*
 * Find a sub-section in a section
 */

CONF_SECTION *cf_section_sub_find(CONF_SECTION *section, const char *name)
{

	CONF_SECTION *cs;
	for (cs = section->sub; cs; cs = cs->next)
		if (strcmp(cs->name1, name) == 0)
			break;
	
	return cs;

}

/*
 * Return the next subsection after a CONF_SECTION
 * with a certain name1 (char *name1)
 */

CONF_SECTION *cf_subsection_find_next(CONF_SECTION *section,
				      CONF_SECTION *subsection,
				      const char *name1)
{
	CONF_SECTION	*cp;

	/*
	 * If subsection is NULL this must be a first time run
	 * Find the subsection with correct name
	 */

	if (subsection == NULL){
		cp = section->sub;
	} else {
		cp = subsection->next;
	}

	for (; cp; cp = cp->next)
		if (strcmp(cp->name1, name1) == 0)
			break;

	return cp;
}

/*
 * Find the configuration section for a module
 */

CONF_SECTION *cf_module_config_find(const char *modulename)
{
	CONF_SECTION *cs;

	for (cs = config->sub; cs; cs = cs->next)
		if ((strcmp(cs->name1, "module") == 0)
			&& (strcmp(cs->name2, modulename) == 0))
			break;

	return cs;
}

/* 
 * JMG dump_config tries to dump the config structure in a readable format
 * 
*/

static int dump_config_section(CONF_SECTION *cs, int indent)
{
	CONF_SECTION	*scs;

	CONF_PAIR	*cp;

	/* The DEBUG macro doesn't let me
	 *   for(i=0;i<indent;++i) debugputchar('\t');
	 * so I had to get creative. --Pac. */

	for (cp = cs->cps; cp; cp = cp->next) 
		DEBUG("%.*s%s = %s",
			indent, "\t\t\t\t\t\t\t\t\t\t\t", cp->attr, cp->value);

	for (scs = cs->sub; scs; scs = scs->next) {
		DEBUG("%.*s%s %s%s{",
			indent, "\t\t\t\t\t\t\t\t\t\t\t",
			scs->name1,
			scs->name2 ? scs->name2 : "",
			scs->name2 ?  " " : "");
		dump_config_section(scs, indent+1);
		DEBUG("%.*s}",
			indent, "\t\t\t\t\t\t\t\t\t\t\t");
	}

	return 0;
}

int dump_config(void)
{
	return dump_config_section(config, 0);
}
