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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "radiusd.h"
#include "conffile.h"
#include "token.h"
#include "modules.h"

static const char rcsid[] =
"$Id$";

#define xalloc malloc
#define xstrdup strdup

typedef enum conf_type {
	CONF_ITEM_PAIR,
	CONF_ITEM_SECTION
} CONF_ITEM_TYPE;

struct conf_item {
	struct conf_item	*next;
	struct conf_part	*parent;
	int			lineno;
	CONF_ITEM_TYPE		type;
};
struct conf_pair {
	CONF_ITEM	item;
	char		*attr;
	char		*value;
	int		operator;
};
struct conf_part {
	CONF_ITEM		item;
	char			*name1;
	char			*name2;
	struct conf_item	*children;
};

CONF_SECTION	*config = NULL;

/*
 *	Yucky hacks.
 */
extern RADCLIENT *clients;
extern REALM	 *realms;
extern int read_realms_file(const char *file);

static int generate_realms(const char *filename);
static int generate_clients(const char *filename);
static CONF_SECTION *conf_read(const char *fromfile, int fromline, const char *conffile);

#ifndef RADIUS_CONFIG
#define RADIUS_CONFIG "radiusd.conf"
#endif

/*
 *	Isolate the scary casts in these tiny provably-safe functions
 */
CONF_PAIR *cf_itemtopair(CONF_ITEM *ci)
{
	if (ci == NULL)
		return NULL;
	assert(ci->type == CONF_ITEM_PAIR);
	return (CONF_PAIR *)ci;
}
CONF_SECTION *cf_itemtosection(CONF_ITEM *ci)
{
	if (ci == NULL)
		return NULL;
	assert(ci->type == CONF_ITEM_SECTION);
	return (CONF_SECTION *)ci;
}
static CONF_ITEM *cf_pairtoitem(CONF_PAIR *cp)
{
	if (cp == NULL)
		return NULL;
	return (CONF_ITEM *)cp;
}
static CONF_ITEM *cf_sectiontoitem(CONF_SECTION *cs)
{
	if (cs == NULL)
		return NULL;
	return (CONF_ITEM *)cs;
}

/*
 *	Create a new CONF_PAIR
 */
static CONF_PAIR *cf_pair_alloc(const char *attr, const char *value,
				int operator, CONF_SECTION *parent)
{
	CONF_PAIR	*cp;

	cp = (CONF_PAIR *)xalloc(sizeof(CONF_PAIR));
	memset(cp, 0, sizeof(CONF_PAIR));
	cp->item.type = CONF_ITEM_PAIR;
	cp->item.parent = parent;
	cp->attr = xstrdup(attr);
	cp->value = xstrdup(value);
	cp->operator = operator;

	return cp;
}

/*
 *	Add an item to a configuration section.
 */
static void cf_item_add(CONF_SECTION *cs, CONF_ITEM *ci_new)
{
	CONF_ITEM *ci;
	
	for (ci = cs->children; ci && ci->next; ci = ci->next)
		;

	if (ci == NULL)
		cs->children = ci_new;
	else
		ci->next = ci_new;
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
static CONF_SECTION *cf_section_alloc(const char *name1, const char *name2,
                                      CONF_SECTION *parent)
{
	CONF_SECTION	*cs;

	if (name1 == NULL || !name1[0]) name1 = "main";

	cs = (CONF_SECTION *)xalloc(sizeof(CONF_SECTION));
	memset(cs, 0, sizeof(CONF_SECTION));
	cs->item.type = CONF_ITEM_SECTION;
        cs->item.parent = parent;
	cs->name1 = xstrdup(name1);
	cs->name2 = (name2 && *name2) ? xstrdup(name2) : NULL;

	return cs;
}

/*
 *	Free a CONF_SECTION
 */
void cf_section_free(CONF_SECTION *cs)
{
	CONF_ITEM	*ci, *next;

	if (cs == NULL) return;

	for (ci = cs->children; ci; ci = next) {
		next = ci->next;
		if (ci->type==CONF_ITEM_PAIR)
			cf_pair_free(cf_itemtopair(ci));
		else
			cf_section_free(cf_itemtosection(ci));
	}

	if (cs->name1) free(cs->name1);
	if (cs->name2) free(cs->name2);

	/*
	 * And free the section
	 */
	free(cs);
}

/*
 *	Expand the variables in an input string.
 */
static const char *cf_expand_variables(const char *cf, int *lineno,
				       CONF_SECTION *cs,
				       char *output, const char *input)
{
	char            *p;
	const char      *end, *ptr;
	char            name[1024];
	CONF_PAIR	*cpn;
	CONF_SECTION    *outercs;
	
	p = output;
	ptr = input;
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
		 *
		 *	FIXME!  This is probably wrong...
		 */
		end = strchr(ptr, '}');
		if (end == NULL) {
			*(p++) = *(ptr++);
			continue;
		}
		
		ptr += 2;

		memcpy(name, ptr, end - ptr);
		name[end - ptr] = '\0';

		cpn = cf_pair_find(cs, name);

		/*
		 *	Also look recursively up the section tree,
		 *	so things like ${confdir} can be defined
		 *	there and used inside the module config
		 *	sections.
		 */
		for (outercs=cs->item.parent
			     ; !cpn && outercs ;
		     outercs=outercs->item.parent) {
			cpn = cf_pair_find(outercs, name);
		}
		if (!cpn) {
			radlog(L_ERR, "%s[%d]: Unknown variable \"%s\"",
			       cf, *lineno, name);
			  cf_section_free(cs);
			  return NULL;
		}

		/*
		 *  Substitute the value of the variable.
		 */
		strcpy(p, cpn->value);
		p += strlen(p);
		ptr = end + 1;
	} /* loop over all of the input string. */

	*p = '\0';

	return output;
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
	const char	*value;

	/*
	 *	Handle the user-supplied variables.
	 */
	for (i = 0; variables[i].name != NULL; i++) {
		value = variables[i].dflt;

		cp = cf_pair_find(cs, variables[i].name);
		if (cp) {
			value = cp->value;
		}
		
		switch (variables[i].type)
		{
		case PW_TYPE_BOOLEAN:
			/*
			 *	Allow yes/no and on/off
			 */
			if ((strcasecmp(value, "yes") == 0) ||
			    (strcasecmp(value, "on") == 0)) {
				*(int *)variables[i].data = 1;
			} else if ((strcasecmp(value, "no") == 0) ||
				   (strcasecmp(value, "off") == 0)) {
				*(int *)variables[i].data = 0;
			} else {
				*(int *)variables[i].data = 0;
				radlog(L_ERR, "Bad value \"%s\" for boolean variable %s", value, variables[i].name);
				return -1;
			}
			DEBUG2("Config: %s.%s = %s",
			       cs->name1,
			       variables[i].name,
			       value);
			break;

		case PW_TYPE_INTEGER:
			*(int *)variables[i].data = strtol(value, 0, 0);
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

			/*
			 *	Expand variables while parsing.
			 */
			if (value) {
			  cf_expand_variables(NULL, 0, cs, buffer, value);
			  value = buffer;
			}

			DEBUG2("Config: %s.%s = \"%s\"",
			       cs->name1,
			       variables[i].name,
			       value ? value : "(null)");
			*q = value ? strdup(value) : NULL;
			break;

		case PW_TYPE_IPADDR:
			/*
			 *	Allow '*' as any address
			 */
			if (strcmp(value, "*") == 0) {
				*(uint32_t *) variables[i].data = 0;
				break;
			}
			ipaddr = ip_getaddr(value);
			if (ipaddr == 0) {
				radlog(L_ERR, "Can't find IP address for host %s", value);
				return -1;
			}
			DEBUG2("Config: %s.%s = %s IP address [%s]",
			       cs->name1,
			       variables[i].name,
			       value, ip_ntoa(buffer, ipaddr));
			*(uint32_t *) variables[i].data = ipaddr;
			break;
			
		default:
			radlog(L_ERR, "type %d not supported yet", variables[i].type);
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
				     const char *name1, const char *name2,
                                     CONF_SECTION *parent)
{
	CONF_SECTION	*cs, *css;
	CONF_PAIR	*cpn;
	char		*ptr;
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
		radlog(L_ERR, "%s[%d]: Illegal configuration section name",
		    cf, *lineno);
		return NULL;
	}

	/*
	 *	Allocate new section.
	 */
	cs = cf_section_alloc(name1, name2, parent);
	cs->item.lineno = *lineno;

	/*
	 *	Read.
	 */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		(*lineno)++;
		ptr = buf;

		t1 = gettoken(&ptr, buf1, sizeof(buf1));

		/*
		 *	Skip comments and blank lines immediately.
		 */
		if ((*buf1 == '#') || (*buf1 == '\0')) {
			continue;
		}

		/*
		 *	Allow for $INCLUDE files
		 *
		 *      Currently this allows for includes only at the top 
		 *      level of config.  IE you cannot have an $INCLUDE nested
		 *      inside section.  -cparker
		 */
		if ((strcasecmp(buf1, "$INCLUDE") == 0) &&
		    (name1 == NULL) && (name2 == NULL)) {

		       CONF_SECTION      *is;

		       t2 = getword(&ptr, buf2, sizeof(buf2));

		       cf_expand_variables(cf, lineno, cs, buf, buf2);

		       DEBUG2( "Config:   including file: %s", buf );
		       
		       if ((is = conf_read(cf, *lineno, buf)) == NULL) {
			       cf_section_free(cs);
			       return NULL;
		       }
		       
		       /*
			*	Add the included conf to our CONF_SECTION
			*/
		       if (is && is->children ) cf_item_add(cs, is->children);
		
		       continue;

		}

		/*
		 *	No '=': must be a section or sub-section.
		 */
		if (strchr(ptr, '=') == NULL) {
			t2 = gettoken(&ptr, buf2, sizeof(buf2));
			t3 = gettoken(&ptr, buf3, sizeof(buf3));
		} else {
			t2 = gettoken(&ptr, buf2, sizeof(buf2));
			t3 = getword(&ptr, buf3, sizeof(buf3));
		}

		/*
		 *	See if it's the end of a section.
		 */
		if (t1 == T_RCBRACE) {
			if (name1 == NULL || buf2[0]) {
				radlog(L_ERR, "%s[%d]: Unexpected end of section",
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
					      t2==T_LCBRACE ? NULL : buf2, cs);
			if (css == NULL) {
				cf_section_free(cs);
				return NULL;
			}
			cf_item_add(cs, cf_sectiontoitem(css));

			continue;		
		}

		/*
		 *	Ignore semi-colons.
		 */
		if (*buf2 == ';') *buf2 = '\0';

		/*
		 *	Must be a normal attr = value line.
		 */
		if (buf1[0] != 0 && buf2[0] == 0 && buf3[0] == 0) {
			t2 = T_OP_EQ;
		} else if (buf1[0] == 0 || buf2[0] == 0 || buf3[0] == 0 ||
			  (t2 < T_EQSTART || t2 > T_EQEND)) {
			radlog(L_ERR, "%s[%d]: Line is not in 'attribute = value' format",
				cf, *lineno);
			cf_section_free(cs);
			return NULL;
		}

		/*
		 *	Ensure that the user can't add CONF_PAIRs
		 *	with 'internal' names;
		 */
		if (buf1[0] == '_') {
			radlog(L_ERR, "%s[%d]: Illegal configuration pair name \"%s\"",
				cf, *lineno, buf1);
			cf_section_free(cs);
			return NULL;
		}
		
		/*
		 *	Handle variable substitution via ${foo}
		 */
		cf_expand_variables(cf, lineno, cs, buf, buf3);

		/*
		 *	Add this CONF_PAIR to our CONF_SECTION
		 */
		cpn = cf_pair_alloc(buf1, buf, t2, parent);
		cpn->item.lineno = *lineno;
		cf_item_add(cs, cf_pairtoitem(cpn));
	}

	/*
	 *	See if EOF was unexpected ..
	 */
	if (name1 != NULL) {
		radlog(L_ERR, "%s[%d]: Unexpected end of file", cf, *lineno);
		cf_section_free(cs);
		return NULL;
	}

	return cs;
}

/*
 *	Read the config file.
 */
static CONF_SECTION *conf_read(const char *fromfile, int fromline, const char *conffile)
{
	FILE		*fp;
	int		lineno = 0;
	CONF_SECTION	*cs;
	
	if ((fp = fopen(conffile, "r")) == NULL) {
		if (fromfile) {
			radlog(L_ERR|L_CONS, "%s[%d]: Unable to open file \"%s\": %s",
			       fromfile, fromline, conffile, strerror(errno));
		} else {
			radlog(L_ERR|L_CONS, "Unable to open file \"%s\": %s",
			       conffile, strerror(errno));
		}
		return NULL;
	}

	cs = cf_section_read(conffile, &lineno, fp, NULL, NULL, NULL);
	fclose(fp);

	return cs;
}

static CONF_PARSER directory_config[] = {
  { "logdir",             PW_TYPE_STRING_PTR, &radlog_dir,        RADLOG_DIR },
  { "libdir",             PW_TYPE_STRING_PTR, &radlib_dir,        LIBDIR },
  { "radacctdir",         PW_TYPE_STRING_PTR, &radacct_dir,       RADACCT_DIR },
  /*
   *	We don't allow re-defining this, as doing so will cause
   *	all sorts of confusion.
   */
#if 0
  { "confdir",            PW_TYPE_STRING_PTR, &radius_dir,        RADIUS_DIR },
#endif
  { NULL, -1, NULL, NULL }
};


/* JLN
 * Read the configuration and library
 * This uses the new kind of configuration file as defined by
 * Miquel at http://www.miquels.cistron.nl/radius/
 */

int read_radius_conf_file(void)
{
	char buffer[256];
	CONF_SECTION *cs;

	/* Lets go look for the new configuration files */
	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_CONFIG);
	if ((cs = conf_read(NULL, 0, buffer)) == NULL) {
		return -1;
	}

	/*
	 *	Free the old configuration data, and replace it
	 *	with the new one.
	 */
	cf_section_free(config);
	config = cs;
	
	/*
	 *	And parse the directory configuration values.
	 */
	cs = cf_section_find(NULL);
	if (!cs)
		return -1;

	/*
	 *	This allows us to figure out where, relative to
	 *	radiusd.conf, the other configuration files exist.
	 */
	cf_section_parse(cs, directory_config);

        /* Initialize the dictionary */
	DEBUG2("read_config_files:  reading dictionary");
	if (dict_init(radius_dir, RADIUS_DICTIONARY) != 0) {
	        radlog(L_ERR|L_CONS, "Errors reading dictionary: %s",
		    librad_errstr);
		return -1;
	}

	/* old-style clients file */
	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_CLIENTS);
	DEBUG2("read_config_files:  reading clients");
	if (read_clients_file(buffer) < 0) {
	        radlog(L_ERR|L_CONS, "Errors reading clients");
		return -1;
	}

	/*
	 *	Add to that, the *new* list of clients.
	 */
	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_CONFIG);
	if (generate_clients(buffer) < 0) {
		return -1;
	}

	/* old-style realms file */
	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_REALMS);
	DEBUG2("read_config_files:  reading realms");
	if (read_realms_file(buffer) < 0) {
	        radlog(L_ERR|L_CONS, "Errors reading realms");
		return -1;
	}

	/*
	 *	If there isn't any realms it isn't fatal..
	 */
	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_CONFIG);
	if (generate_realms(buffer) < 0) {
		return -1;
	}

	/* old-style naslist file */
	sprintf(buffer, "%.200s/%.50s", radius_dir, RADIUS_NASLIST);
	DEBUG2("read_config_files:  reading naslist");
	if (read_naslist_file(buffer) < 0) {
	        radlog(L_ERR|L_CONS, "Errors reading naslist");
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

	for (cs = cf_subsection_find_next(config, NULL, "realm")
	     ; cs ;
	     cs = cf_subsection_find_next(config, cs, "realm")) {
		if (!cs->name2) {
			radlog(L_CONS|L_ERR, "%s[%d]: Missing realm name", filename, cs->item.lineno);
			return -1;
		}
		/*
		 * We've found a realm, allocate space for it
		 */
		if ((c = malloc(sizeof(REALM))) == NULL) {
			radlog(L_CONS|L_ERR, "Out of memory");
			return -1;
		}
		memset(c, 0, sizeof(REALM));
		/*
		 * An authhost must exist in the configuration
		 */
		if ((authhost = cf_section_value_find(cs, "authhost")) == NULL) {
			radlog(L_CONS|L_ERR, 
			    "%s[%d]: No authhost entry in realm", 
			    filename, cs->item.lineno);
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
			radlog(L_ERR, "%s[%d]: Server name of length %d is greater that allowed: %d",
			    filename, cs->item.lineno,
			    strlen(authhost), sizeof(c->server) - 1);
			return -1;
		}
		if (strlen(cs->name2) >= sizeof(c->realm)) {
			radlog(L_ERR, "%s[%d]: Realm name of length %d is greater than allowed %d",
			    filename, cs->item.lineno,
			    strlen(cs->name2), sizeof(c->server) - 1);
			return -1;
		}
		
		strcpy(c->realm, cs->name2);
		strcpy(c->server, authhost);	

		s = cf_section_value_find(cs, "secret");
		if (s == NULL) {
			radlog(L_ERR, "%s[%d]: No shared secret supplied for realm",
			    filename, cs->item.lineno);
			return -1;
		}

		if (strlen(s) >= sizeof(c->secret)) {
		  radlog(L_ERR, "%s[%d]: Secret of length %d is greater than the allowed maximum of %d.",
		      filename, cs->item.lineno,
		      strlen(s), sizeof(c->secret) - 1);
		  return -1;
		}
		strNcpy((char *)c->secret, s, sizeof(c->secret));

		c->striprealm = 1;
		
		if ((cf_section_value_find(cs, "nostrip")) != NULL)
			c->striprealm = 0;
		if ((cf_section_value_find(cs, "noacct")) != NULL)
			c->acct_port = 0;
		if ((cf_section_value_find(cs, "trusted")) != NULL)
			c->trusted = 1;
		if ((cf_section_value_find(cs, "notrealm")) != NULL)
			c->notrealm = 1;
		if ((cf_section_value_find(cs, "notsuffix")) != NULL)
			c->notrealm = 1;


		c->next = realms;
		realms = c;

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

	for (cs = cf_subsection_find_next(config, NULL, "client")
	     ; cs ;
	     cs = cf_subsection_find_next(config, cs, "client")) {
		if (!cs->name2) {
			radlog(L_CONS|L_ERR, "%s[%d]: Missing client name", filename, cs->item.lineno);
			return -1;
		}
		/*
		 * Check the lengths, we don't want any core dumps
		 */
		hostnm = cs->name2;
		secret = cf_section_value_find(cs, "secret");
		shortnm = cf_section_value_find(cs, "shortname");

		if (strlen(secret) >= sizeof(c->secret)) {
			radlog(L_ERR, "%s[%d]: Secret of length %d is greater than the allowed maximum of %d.",
			    filename, cs->item.lineno,
			    strlen(secret), sizeof(c->secret) - 1);
			return -1;
		}
		if (strlen(shortnm) > sizeof(c->shortname)) {
			radlog(L_ERR, "%s[%d]: NAS short name of length %d is greater than the allowed maximum of %d.",
			    filename, cs->item.lineno,
			    strlen(shortnm), sizeof(c->shortname) - 1);
			return -1;
		}
		/*
		 * The size is fine.. Let's create the buffer
		 */
		if ((c = malloc(sizeof(RADCLIENT))) == NULL) {
			radlog(L_CONS|L_ERR, "Out of memory");
			return -1;
		}

		c->ipaddr = ip_getaddr(hostnm);
		strcpy((char *)c->secret, secret);
		strcpy(c->shortname, shortnm);
		ip_hostname(c->longname, sizeof(c->longname),
			    c->ipaddr);

		c->next = clients;
		clients = c;
	}

	return 0;
}

/* 
 * Return a CONF_PAIR within a CONF_SECTION.
 */

CONF_PAIR *cf_pair_find(CONF_SECTION *section, const char *name)
{
	CONF_ITEM	*ci;

	if (section == NULL) {
	  section = config;
	}

	for (ci = section->children; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_PAIR)
			continue;
		if (name == NULL || strcmp(cf_itemtopair(ci)->attr, name) == 0)
			break;
	}

	return cf_itemtopair(ci);
}

/*
 * Return the attr of a CONF_PAIR
 */

char *cf_pair_attr(CONF_PAIR *pair)
{
	return (pair ? pair->attr : NULL);
}

/*
 * Return the value of a CONF_PAIR
 */

char *cf_pair_value(CONF_PAIR *pair)
{
	return (pair ? pair->value : NULL);
}

/*
 * Return the first label of a CONF_SECTION
 */

char *cf_section_name1(CONF_SECTION *section)
{
	return (section ? section->name1 : NULL);
}

/*
 * Return the second label of a CONF_SECTION
 */

char *cf_section_name2(CONF_SECTION *section)
{
	return (section ? section->name2 : NULL);
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
 * with a certain name (char *attr) If the requested
 * attr is NULL, any attr matches.
 */

CONF_PAIR *cf_pair_find_next(CONF_SECTION *section, CONF_PAIR *pair, const char *attr)
{
	CONF_ITEM	*ci;

	/*
	 * If pair is NULL this must be a first time run
	 * Find the pair with correct name
	 */

	if (pair == NULL){
		return cf_pair_find(section, attr);
	}

	ci = cf_pairtoitem(pair)->next;

	for (; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_PAIR)
			continue;
		if (attr == NULL || strcmp(cf_itemtopair(ci)->attr, attr) == 0)
			break;
	}

	return cf_itemtopair(ci);
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

	CONF_ITEM *ci;
	for (ci = section->children; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_SECTION)
			continue;
		if (strcmp(cf_itemtosection(ci)->name1, name) == 0)
			break;
	}

	return cf_itemtosection(ci);

}

/*
 * Return the next subsection after a CONF_SECTION
 * with a certain name1 (char *name1). If the requested
 * name1 is NULL, any name1 matches.
 */

CONF_SECTION *cf_subsection_find_next(CONF_SECTION *section,
				      CONF_SECTION *subsection,
				      const char *name1)
{
	CONF_ITEM	*ci;

	/*
	 * If subsection is NULL this must be a first time run
	 * Find the subsection with correct name
	 */

	if (subsection == NULL){
		ci = section->children;
	} else {
		ci = cf_sectiontoitem(subsection)->next;
	}

	for (; ci; ci = ci->next) {
		if (ci->type != CONF_ITEM_SECTION)
			continue;
		if (name1 == NULL ||
		    strcmp(cf_itemtosection(ci)->name1, name1) == 0)
			break;
	}

	return cf_itemtosection(ci);
}

/*
 * Return the next item after a CONF_ITEM.
 */

CONF_ITEM *cf_item_find_next(CONF_SECTION *section, CONF_ITEM *item)
{
	/*
	 * If item is NULL this must be a first time run
	 * Return the first item
	 */

	if (item == NULL) {
		return section->children;
	} else {
		return item->next;
	}
}

int cf_section_lineno(CONF_SECTION *section)
{
	return cf_sectiontoitem(section)->lineno;
}

int cf_pair_lineno(CONF_PAIR *pair)
{
	return cf_pairtoitem(pair)->lineno;
}

int cf_item_is_section(CONF_ITEM *item)
{
	return item->type == CONF_ITEM_SECTION;
}


/* 
 * JMG dump_config tries to dump the config structure in a readable format
 * 
*/

static int dump_config_section(CONF_SECTION *cs, int indent)
{
	CONF_SECTION	*scs;
	CONF_PAIR	*cp;
	CONF_ITEM	*ci;

	/* The DEBUG macro doesn't let me
	 *   for(i=0;i<indent;++i) debugputchar('\t');
	 * so I had to get creative. --Pac. */

	for (ci = cs->children; ci; ci = ci->next) {
		if (ci->type == CONF_ITEM_PAIR) {
			cp=cf_itemtopair(ci);
			DEBUG("%.*s%s = %s",
				indent, "\t\t\t\t\t\t\t\t\t\t\t",
				cp->attr, cp->value);
		} else {
			scs=cf_itemtosection(ci);
			DEBUG("%.*s%s %s%s{",
				indent, "\t\t\t\t\t\t\t\t\t\t\t",
				scs->name1,
				scs->name2 ? scs->name2 : "",
				scs->name2 ?  " " : "");
			dump_config_section(scs, indent+1);
			DEBUG("%.*s}",
				indent, "\t\t\t\t\t\t\t\t\t\t\t");
		}
	}

	return 0;
}

int dump_config(void)
{
	return dump_config_section(config, 0);
}
