/*
 * ldap.c	Functions to access the LDAP database. 
 * 
 * This is mostly from a Mysql+Cistron patch from oyarzun@wilmington.net
 *
 * Much of the Mysql connection and accounting code was taken from 
 * Wim Bonis's (bonis@kiss.de) accounting patch to livingston radius
 * 2.01. His patch can be found at:
 *
 *       ftp://ftp.kiss.de/pub/unix/livingston/mysql-patches.tgz
 *
 * Version:	$Id$
 *
 */
static const char rcsid[] = "$Id$";

#include "autoconf.h"

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>
#include	<string.h>

#include	<lber.h>
#include        <ldap.h>

#include	"radiusd.h"
#include	"conffile.h"
#include	"modules.h"

#define MAX_AUTH_QUERY_LEN      256

static char	*make_filter(char *, char *);

/*
 *	These should really be in a module-specific data structure,
 *	which is passed to the module with every request.
 */
static char *ldap_server = NULL;
static int  ldap_port = 389;
static char *ldap_login = NULL;
static char *ldap_password = NULL;
static char *ldap_filter = NULL;
static char *ldap_basedn = NULL;
static int  use_ldap_auth = 0;
static int ldap_cache_timeout = 30;
static int ldap_cache_size = 0;
static LDAP *ld;

/*
 *	A mapping of configuration file names to internal variables
 */
static CONF_PARSER ldap_config[] = {
	{ "server",        PW_TYPE_STRING_PTR, &ldap_server },
	{ "port",          PW_TYPE_INTEGER,    &ldap_port },
	{ "login",         PW_TYPE_STRING_PTR, &ldap_login },
	{ "password",      PW_TYPE_STRING_PTR, &ldap_password },
	{ "basedn",        PW_TYPE_STRING_PTR, &ldap_basedn },
	{ "filter",        PW_TYPE_STRING_PTR, &ldap_filter },
	{ "cache_timeout", PW_TYPE_INTEGER,    &ldap_cache_timeout },
	{ "cache_size",    PW_TYPE_INTEGER,    &ldap_cache_size },
	{ NULL, -1, NULL}
};

/* LDAP attribute name that controls remote access */
#define LDAP_RADIUSACCESS "radiusAccess"

/* Fallback to default settings if no basic attributes defined in object
 * (An ugly hack to be replaced by profiles and policies)
 */
#define DEFAULT_CONF

#ifdef DEFAULT_CONF
#define DEFAULT_SERVICE_TYPE "Framed-User"
#define DEFAULT_FRAMED_PROTOCOL "PPP"
#define DEFAULT_FRAMED_MTU "576"
#define DEFAULT_FRAMED_COMPRESSION "Van-Jacobson-TCP-IP"
#define DEFAULT_IDLE_TIMEOUT "240"
#define DEFAULT_SIMULTANEOUS_USE "1"
#endif

typedef struct {
  char *attr;
  char *radius_attr;
} TLDAP_RADIUS;

/*
 *      Mappings of LDAP radius* attributes to RADIUS attributes
 *
 *	Hmm... these should really be read in from the configuration file
 */
static TLDAP_RADIUS check_item_map[] = {
        { "radiusAuthType", "Auth-Type" } ,
        {NULL, NULL}
};
static TLDAP_RADIUS reply_item_map[] = {
        { "radiusFilterID", "Filter-Id" },
        {NULL, NULL}
};

static VALUE_PAIR *ldap_pairget(LDAP *, LDAPMessage *, TLDAP_RADIUS *);

/*************************************************************************
 *
 *	Function: rlm_ldap_init
 *
 *	Purpose: Reads in radldap Config File 
 *
 *************************************************************************/
static int rlm_ldap_init (int argc, char **argv)
{
	CONF_SECTION  *ldap_cf;

	/*
	 *	Find the LDAP configuration.  If it isn't there,
	 *	then exit quietly.
	 */
	ldap_cf = cf_module_config_find("ldap");
	if (!ldap_cf) {
		return 0;
	}

	/*
	 *	Parse all of the configuration parameters.
	 */
	cf_section_parse(ldap_cf, ldap_config);

	/*
	 *	???
	 */
	if (ldap_server) {
		use_ldap_auth = 1;
	}
	
	if ( (ld = ldap_init(ldap_server,ldap_port)) == NULL)	
		return RLM_MODULE_FAIL;
	if ( ldap_bind_s(ld,ldap_login,ldap_password, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS) {
		log(L_ERR,"LDAP ldap_simple_bind_s failed");
		ldap_unbind_s(ld);
		return (-1);
	}

/* I don't know yet why, but this code doesn't work. */
#if 0
	if ( ldap_enable_cache(ld,ldap_cache_timeout,ldap_cache_size) != LDAP_SUCCESS) {
		log(L_ERR,"LDAP ldap_enable_cache failed");
		ldap_unbind_s(ld);
		return (-1);
	}
#endif
       
       log(L_INFO,"LDAP_init: using: %s:%d,%s,%s,%s,%d",
	   ldap_server,
	   ldap_port,
	   ldap_login,
	   ldap_filter,
	   ldap_basedn,
	   use_ldap_auth); 
       
       return 0;
}

/*************************************************************************
 *
 *      Function: rlm_ldap_authorize
 *
 *      Purpose: Check if user is authorized for remote access 
 *
 *************************************************************************/
static int rlm_ldap_authorize(REQUEST *request,
			      VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
	LDAPMessage *result, *msg;
	char *filter, **vals;
	VALUE_PAIR      *check_tmp;
	VALUE_PAIR      *reply_tmp;
	char *name;
	char *attrs[] = { "*", NULL }; /* REALLY 'const' */
	
	name = request->username->strvalue;
	
	/*
	 *      Check for valid input, zero length names not permitted
	 */
	if ((request->username->length == 0) ||
	    (*name == '\0')) {
		log(L_ERR, "zero length username not permitted\n");
		return -1;
	}
	
	DEBUG("LDAP Performing user authorization for %s", name);
	
	filter = make_filter(ldap_filter, name);
	if (ldap_search_s(ld, ldap_basedn, LDAP_SCOPE_SUBTREE, filter, attrs, 0, &result) != LDAP_SUCCESS) {
		DEBUG("LDAP search failed");
		return RLM_MODULE_FAIL;
	}
	
	if ((ldap_count_entries(ld, result)) != 1) {
		DEBUG("LDAP user object not found or got ambiguous search result");
		return RLM_MODULE_OK;
	}
	
	if ((msg = ldap_first_entry(ld, result)) == NULL) {
		return RLM_MODULE_FAIL;
	}
	
	/*
	 *	Remote access is controled by LDAP_RADIUSACCESS attribute of
	 *	user object
	 */
	if ((vals = ldap_get_values(ld, msg, LDAP_RADIUSACCESS)) != NULL ) {
		if (!strncmp(vals[0], "FALSE", 5)) {
			DEBUG("LDAP dialup access disabled");
			return RLM_MODULE_REJECT;
		}
	} else {
		DEBUG("LDAP no %s attribute - access denied by default", LDAP_RADIUSACCESS);
		return RLM_MODULE_REJECT;
	}
	
	DEBUG("LDAP looking for check items in directory..."); 
	if((check_tmp = ldap_pairget(ld, msg, check_item_map)) != (VALUE_PAIR *)0) {
		pairadd(check_pairs, check_tmp);
	}
	
	/*
	 *	Module should default to LDAP authentication if no
	 *	Auth-Type specified (???)
	 */
	if (!pairfind(*check_pairs, PW_AUTHTYPE)) {
		pairadd(check_pairs, pairmake("Auth-Type", "LDAP", T_OP_EQ));
	}
	
	DEBUG("LDAP looking for reply items in directory..."); 
	if((reply_tmp = ldap_pairget(ld,msg, reply_item_map)) != NULL) {
		pairadd(reply_pairs, reply_tmp);
	}
	
#ifdef DEFAULT_CONF
	if (!pairfind(*reply_pairs, PW_SERVICE_TYPE)) {
		pairadd(reply_pairs, pairmake("Service-Type", DEFAULT_SERVICE_TYPE, T_OP_EQ));
	}
	if (!pairfind(*reply_pairs, PW_FRAMED_PROTOCOL)) {
		pairadd(reply_pairs, pairmake("Framed-Protocol", DEFAULT_FRAMED_PROTOCOL, T_OP_EQ));
	}
	if (!pairfind(*reply_pairs, PW_FRAMED_MTU)) {
		pairadd(reply_pairs, pairmake("Framed-MTU", DEFAULT_FRAMED_MTU, T_OP_EQ));
	}
	if (!pairfind(*reply_pairs, PW_FRAMED_COMPRESSION)) {
		pairadd(reply_pairs, pairmake("Framed-Compression", DEFAULT_FRAMED_COMPRESSION, T_OP_EQ));
	}
	if (!pairfind(*reply_pairs, PW_IDLE_TIMEOUT)) {
		pairadd(reply_pairs, pairmake("Idle-Timeout", DEFAULT_IDLE_TIMEOUT, T_OP_EQ));       
	}
	if (!pairfind(*check_pairs, PW_SIMULTANEOUS_USE)) {
		pairadd(reply_pairs, pairmake("Simultaneous-Use", DEFAULT_SIMULTANEOUS_USE, T_OP_EQ));       
	}
#endif
	
	DEBUG("LDAP user %s authorized to use remote access", name);
	return RLM_MODULE_OK;
}

/*************************************************************************
 *
 *	Function: rlm_ldap_authenticate
 *
 *	Purpose: Check the user's password against ldap database 
 *
 *************************************************************************/
static int rlm_ldap_authenticate(REQUEST *request)
{
	static LDAP *ld_user;
	LDAPMessage *result, *msg;
	char *filter, *dn;
	char *attrs[] = { "uid", NULL }; /* REALLY 'const' */
	char *name, *passwd;

	/*
	 *	Ensure that we're being passed a plain-text password,
	 *	and not anything else.
	 */
	if (!request->password) {
		log(L_AUTH, "rlm_ldap: Attribute \"Password\" is required for authentication.");
	}

	if (request->password->attribute != PW_PASSWORD) {
		log(L_AUTH, "rlm_ldap: Attribute \"Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_REJECT;
	}

	if (request->password->length == 0) {
		log(L_AUTH, "rlm_ldap: Cannot use zero length password");
		return RLM_MODULE_REJECT;
	}
	
	name = request->username->strvalue;
	passwd = request->password->strvalue;
	
	/*
	 *	???
	 */
	if (use_ldap_auth == 0) {
		log(L_ERR,"LDAP Auth specified in users file, but not in ldapserver file");
		return RLM_MODULE_FAIL;
	}
	
	DEBUG("LDAP login attempt by '%s' with password '%s'", name, passwd);
	
	filter = make_filter(ldap_filter, name);
	
	if (ldap_search_s(ld, ldap_basedn, LDAP_SCOPE_SUBTREE, filter, attrs, 1, &result) != LDAP_SUCCESS) {
		return RLM_MODULE_FAIL;
	}
	
	if ((ldap_count_entries(ld, result)) != 1) {
		return RLM_MODULE_FAIL;
	}
	
	if ((msg = ldap_first_entry(ld,result)) == NULL) {
		return RLM_MODULE_FAIL;
	}
	
	if ((dn = ldap_get_dn(ld, msg)) == NULL) {
		return RLM_MODULE_FAIL;
	}
	
	DEBUG("LDAP user DN: %s", dn);
	
	if ( (ld_user = ldap_init(ldap_server, ldap_port)) == NULL)
		return RLM_MODULE_FAIL;
	
	if (ldap_simple_bind_s(ld_user, dn, passwd) != LDAP_SUCCESS) {
		ldap_unbind_s(ld_user);
		return RLM_MODULE_REJECT;
	}
	
	free(dn);
	ldap_unbind_s(ld_user);
	
	DEBUG("LDAP User %s authenticated succesfully", name);
	return RLM_MODULE_OK;
}

/*
 *	Detach from the ldap.
 */
static int rlm_ldap_detach(void)
{
  ldap_unbind_s(ld);
  return 0;
}

/*
 *	Replace %<whatever> in a string.
 *
 *	%u   User name
 *
 */
static char *make_filter(char *str, char *name)
{
	static char buf[MAX_AUTH_QUERY_LEN];
	int i = 0, c;
	char *p;

	for(p = str; *p; p++) {
		c = *p;
		if (c != '%' && c != '\\') {
			buf[i++] = *p;
			continue;
		}
		if (*++p == 0) break;
		if (c == '%') switch(*p) {
			case '%':
				buf[i++] = *p;
				break;
			case 'u': /* User name */
				if (name != NULL)
					strcpy(buf + i, name);
				else
					strcpy(buf + i, " ");
				i += strlen(buf + i);
				break;
			default:
				buf[i++] = '%';
				buf[i++] = *p;
				break;
		}
		if (c == '\\') switch(*p) {
			case 'n':
				buf[i++] = '\n';
				break;
			case 'r':
				buf[i++] = '\r';
				break;
			case 't':
				buf[i++] = '\t';
				break;
			default:
				buf[i++] = '\\';
				buf[i++] = *p;
				break;
		}
	}
	if (i >= MAX_AUTH_QUERY_LEN)
		i = MAX_AUTH_QUERY_LEN - 1;
	buf[i++] = 0;
	return buf;
}

/*
 *	Get RADIUS attributes from LDAP object
 *	( according to draft-adoba-radius-05.txt 
 *	  <http://www.ietf.org/internet-drafts/draft-adoba-radius-05.txt> )
 *
 */

static VALUE_PAIR *ldap_pairget(LDAP *ld, LDAPMessage *entry,
				TLDAP_RADIUS *item_map)
{
	BerElement *berptr;
	char *attr;
	char **vals;
	char *ptr;
	TLDAP_RADIUS *element;
	int token;
	char value[64];
	VALUE_PAIR *pairlist;
	VALUE_PAIR *newpair = NULL;
	pairlist = NULL;

	if ((attr = ldap_first_attribute(ld, entry, &berptr)) == NULL) {
		DEBUG("Object has no attributes");
		return NULL;
	}
	
	do {
		for (element=item_map; element->attr != NULL; element++) {
			DEBUG2("Comparing %s with %s", attr, element->attr);
			if (!strncasecmp(attr,element->attr,strlen(element->attr))) {
				if (((vals = ldap_get_values(ld, entry, attr)) == NULL) ||
				    (ldap_count_values(vals) > 1)) {
					DEBUG("Attribute %s has multiple values", attr);
					break;
				}
				ptr = vals[0];
				token = gettoken(&ptr, value, sizeof(value));
				if (token < T_EQSTART || token > T_EQEND) {
					token = T_OP_EQ;	
				} else {
					gettoken(&ptr, value, sizeof(value));
				}
				if (value[0] == 0) {
					DEBUG("Attribute %s has no value", attr);
					break;
				}
				DEBUG("LDAP Adding %s as %s, value %s & op=%d", attr, element->radius_attr, value, token);
				if ((newpair = pairmake(element->radius_attr, value, token)) == NULL)
					continue;
				pairadd(&pairlist, newpair);
				ldap_value_free(vals);
			}
		}
	} while ((attr = ldap_next_attribute(ld, entry, berptr)) != NULL);

	ber_free(berptr, 0);
	return(pairlist);
}

/* globally exported name */
module_t rlm_ldap = {
  "LDAP",
  0,				/* type: reserved */
  rlm_ldap_init,		/* initialization */
  rlm_ldap_authorize,           /* authorization */
  rlm_ldap_authenticate,        /* authentication */
  NULL,				/* preaccounting */
  NULL,				/* accounting */
  rlm_ldap_detach,              /* detach */
};
