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
 * Version:	@(#)ldap.c  1.10  29-Jan-1999  james@wwnet.net
 *
 */

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
#include	<strings.h>

#include	<lber.h>
#include        <ldap.h>

#include	"radiusd.h"
#include	"conffile.h"
#include	"modules.h"

#define MAX_AUTH_QUERY_LEN      256

static char	*make_filter(char *, char *);

static char ldap_server[40];
static int  ldap_port;
static char ldap_login[40];
static char ldap_password[20];
static char ldap_filter[256];
static char ldap_basedn[256];
static int  use_ldap_auth;
static LDAP *ld;

CONF_SECTION	*conf_main;

/* Keep LDAP search results for 30 seconds */
#define LDAP_CACHE_TIMEOUT 30
/* Let cache size be restricted only by timeout */
#define LDAP_CACHE_SIZE 0
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
  char* attr;
  char* radius_attr;
} TLDAP_RADIUS;

/*
 *      Mappings of LDAP radius* attributes to RADIUS attributes
 */

static TLDAP_RADIUS check_item_map[] = {
        "radiusAuthType", "Auth-Type",
        NULL, NULL
};
static TLDAP_RADIUS reply_item_map[] = {
        "radiusFilterID", "Filter-Id",
        NULL, NULL
};

VALUE_PAIR *ldap_pairget(LDAP *, LDAPMessage *, TLDAP_RADIUS *);

/*************************************************************************
 *
 *	Function: rlm_ldap_init
 *
 *	Purpose: Reads in radldap Config File 
 *
 *************************************************************************/

static int rlm_ldap_init (int argc, char **argv)
{
	conf_main = cf_module_config_find("ldap");       
		
/*       strcpy(ldap_server,"");
       strcpy(ldap_login,"");
       strcpy(ldap_password,"");
       strcpy(ldap_basedn,"");
       strcpy(ldap_filter,""); */
       ldap_port = 389;
       use_ldap_auth = 0;

	if (cf_pair_find(conf_main,"ldapserver") != NULL) {
		strcpy(ldap_server,cf_section_value_find(conf_main,"ldapserver"));
		use_ldap_auth = 1;
	}
	
	if (cf_pair_find(conf_main,"ldapport") != NULL)
		ldap_port = atoi(cf_section_value_find(conf_main,"ldapport")); 

	if (cf_pair_find(conf_main,"ldaplogin") != NULL)
		strcpy(ldap_login,cf_section_value_find(conf_main,"ldaplogin"));

	if (cf_pair_find(conf_main,"ldappassword") != NULL)
		strcpy(ldap_password,cf_section_value_find(conf_main,"ldappassword"));

	if (cf_pair_find(conf_main,"ldapbasedn") != NULL)
		strcpy(ldap_basedn,cf_section_value_find(conf_main,"ldapbasedn"));

	if (cf_pair_find(conf_main,"ldapfilter") != NULL)
		strcpy(ldap_filter,cf_section_value_find(conf_main,"ldapfilter"));

       if ( (ld = ldap_init(ldap_server,ldap_port)) == NULL)	
		return RLM_MODULE_FAIL;
       if ( ldap_bind_s(ld,ldap_login,ldap_password, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS){
	   log(L_ERR,"LDAP ldap_simple_bind_s failed");
           ldap_unbind_s(ld);
           return (-1);
       }
/* I don't know yet why, but this code doesn't work. */
/*
       if ( ldap_enable_cache(ld,LDAP_CACHE_TIMEOUT,LDAP_CACHE_SIZE) != LDAP_SUCCESS) {
           log(L_ERR,"LDAP ldap_enable_cache failed");
           ldap_unbind_s(ld);
           return (-1);
       }
*/
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
    char *filter,
        *attrs[] = { "*",
                     NULL },
        **vals;
    VALUE_PAIR      *check_tmp;
    VALUE_PAIR      *reply_tmp;
    char *name;

    name = request->username->strvalue;

    /*
     *      Check for valid input, zero length names not permitted
     */
    if (name[0] == 0) {
          log(L_ERR, "zero length username not permitted\n");
          return -1;
    }

    DEBUG("LDAP Performing user authorization for %s", name);

    filter = make_filter(ldap_filter, name);
    if (ldap_search_s(ld,ldap_basedn,LDAP_SCOPE_SUBTREE,filter,attrs,0,&result) != LDAP_SUCCESS) {
	DEBUG("LDAP search failed");
        return RLM_MODULE_FAIL;
    }
    
    if ((ldap_count_entries(ld,result)) != 1) {
	DEBUG("LDAP user object not found or got ambiguous search result");
	return RLM_MODULE_OK;
    }

    if ((msg = ldap_first_entry(ld,result)) == NULL) {
        return RLM_MODULE_FAIL;
    }
/* Remote access is controled by LDAP_RADIUSACCESS attribute of user object */ 
    if ((vals = ldap_get_values(ld, msg, LDAP_RADIUSACCESS)) != NULL ) {
        if(!strncmp(vals[0],"FALSE",5)) {
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

/* Module should default to LDAP authentication if no Auth-Type specified */
    if(pairfind(*check_pairs, PW_AUTHTYPE) == NULL){
	pairadd(check_pairs, pairmake("Auth-Type", "LDAP", T_OP_EQ));
    }

    DEBUG("LDAP looking for reply items in directory..."); 
    if((reply_tmp = ldap_pairget(ld,msg, reply_item_map)) != (VALUE_PAIR *)0) {
        pairadd(reply_pairs, reply_tmp);
    }

#ifdef DEFAULT_CONF
    if(pairfind(*reply_pairs, PW_SERVICE_TYPE) == NULL){
        pairadd(reply_pairs, pairmake("Service-Type", DEFAULT_SERVICE_TYPE, T_OP_EQ));
    }
    if(pairfind(*reply_pairs, PW_FRAMED_PROTOCOL) == NULL){
        pairadd(reply_pairs, pairmake("Framed-Protocol", DEFAULT_FRAMED_PROTOCOL, T_OP_EQ));
    }
    if(pairfind(*reply_pairs, PW_FRAMED_MTU) == NULL){
        pairadd(reply_pairs, pairmake("Framed-MTU", DEFAULT_FRAMED_MTU, T_OP_EQ));
    }
    if(pairfind(*reply_pairs, PW_FRAMED_COMPRESSION) == NULL){
        pairadd(reply_pairs, pairmake("Framed-Compression", DEFAULT_FRAMED_COMPRESSION, T_OP_EQ));
    }
    if(pairfind(*reply_pairs, PW_IDLE_TIMEOUT) == NULL){
        pairadd(reply_pairs, pairmake("Idle-Timeout", DEFAULT_IDLE_TIMEOUT, T_OP_EQ));       
    }
    if(pairfind(*check_pairs, PW_SIMULTANEOUS_USE) == NULL){
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
    char *filter, *dn,
	*attrs[] = { "uid",
		     NULL };
    char *name, *passwd;

    /*
     *  Ensure that we're being passed a plain-text password,
     *  and not anything else.
     */
    if (request->password->attribute != PW_PASSWORD) {
      log(L_AUTH, "rlm_ldap: Attribute \"Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
      return RLM_MODULE_REJECT;
    }

    name = request->username->strvalue;
    passwd = request->password->strvalue;

    if (use_ldap_auth == 0) {
      log(L_ERR,"LDAP Auth specified in users file, but not in ldapserver file");
      return RLM_MODULE_FAIL;
    }

    DEBUG("LDAP login attempt by '%s' with password '%s'",name,passwd);

	filter = make_filter(ldap_filter, name);

    if (ldap_search_s(ld,ldap_basedn,LDAP_SCOPE_SUBTREE,filter,attrs,1,&result) != LDAP_SUCCESS) {
	return RLM_MODULE_FAIL;
    }

    if ((ldap_count_entries(ld,result)) != 1) {
	return RLM_MODULE_FAIL;
    }

    if ((msg = ldap_first_entry(ld,result)) == NULL) {
	return RLM_MODULE_FAIL;
    }

    if ((dn = ldap_get_dn(ld,msg)) == NULL) {
	return RLM_MODULE_FAIL;
    }

    DEBUG("LDAP user DN: %s", dn);

    if (strlen(passwd) == 0) {
	return RLM_MODULE_FAIL;
    }
    if ( (ld_user = ldap_init(ldap_server,ldap_port)) == NULL)
        return RLM_MODULE_FAIL;

    if (ldap_simple_bind_s(ld_user,dn,passwd) != LDAP_SUCCESS) {
	ldap_unbind_s(ld_user);
	return RLM_MODULE_REJECT;
    }

    free(dn);
    ldap_unbind_s(ld_user);

    DEBUG("LDAP User %s authenticated succesfully", name);
    return RLM_MODULE_OK;
	}

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

VALUE_PAIR *ldap_pairget(LDAP *ld, LDAPMessage *entry, TLDAP_RADIUS *item_map)
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
  if((attr = ldap_first_attribute(ld, entry, &berptr)) == (char *)0) {
	DEBUG("Object has no attributes");
	return NULL;
  }
  
  do {
	for(element=item_map; element->attr != NULL; element++) {
		DEBUG2("Comparing %s with %s", attr, element->attr);
		if(!strncasecmp(attr,element->attr,strlen(element->attr))) {
			if(((vals = ldap_get_values(ld, entry, attr)) == NULL) ||
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
			if((newpair = pairmake(element->radius_attr, value, token)) == NULL)
				continue;
			pairadd(&pairlist, newpair);
			ldap_value_free(vals);
		}
	}
  } while ((attr = ldap_next_attribute(ld, entry, berptr)) != (char *)0);
  ber_free(berptr,0);
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
