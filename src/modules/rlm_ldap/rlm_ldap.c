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
#include	"modules.h"

#define MAX_AUTH_QUERY_LEN      256

static char	*make_filter(char *, char *);
static void	fieldcpy(char *, char **);

static char ldap_server[40];
static int  ldap_port;
static char ldap_login[40];
static char ldap_password[20];
static char ldap_filter[256];
static char ldap_basedn[256];
static int  use_ldap_auth;


/*************************************************************************
 *
 *	Function: rlm_ldap_init
 *
 *	Purpose: Reads in radldap Config File 
 *
 *************************************************************************/

static int rlm_ldap_init (int argc, char **argv)
{
	FILE    *ldapcfd;
        char    dummystr[64];
        char    namestr[64];
        int     line_no;
        char    buffer[256];
        char    ldapcfile[256];
        char    *ptr;
       
       strcpy(ldap_server,"");
       strcpy(ldap_login,"");
       strcpy(ldap_password,"");
       strcpy(ldap_basedn,"");
       strcpy(ldap_filter,"");
       ldap_port = 389;
       use_ldap_auth = 0;

        sprintf(ldapcfile, "%s/%s", radius_dir, "ldapserver");
        if((ldapcfd = fopen(ldapcfile, "r")) == (FILE *)NULL) {
                log(L_ERR,"could not read ldapserver file %s",ldapcfile);
                return(-1);
        }

        line_no = 0;
        while(fgets(buffer, sizeof(buffer), ldapcfd) != (char *)NULL) {
                line_no++;

                /* Skip empty space */
                if(*buffer == '#' || *buffer == '\0' || *buffer == '\n') {
                        continue;
                }

                if(strncasecmp(buffer, "server", 6) == 0) {
                        /* Read the SERVER line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of ldapserver file %s", 
				line_no,ldapcfile);
                         use_ldap_auth = 0;
                       } else {
                         strcpy(ldap_server,namestr);
                       }
               }
                if(strncasecmp(buffer, "port", 4) == 0) {
			/* Read the PORT line */
			if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
			log(L_ERR,"invalid attribute on line %d of ldapserver file %s", 
					line_no,ldapcfile);
			} else {
			ldap_port = atoi(namestr);
			}
		}
		if(strncasecmp(buffer, "login", 5) == 0) {
                        /* Read the LOGIN line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of ldapserver file %s, using NULL login", 
					line_no,ldapcfile);
			 strcpy(ldap_login,"");
                       } else {
                         strcpy(ldap_login,namestr);
                       }
               }
                if(strncasecmp(buffer, "password", 8) == 0) {
                        /* Read the PASSWORD line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of ldapserver file %s, using NULL password", 
					line_no,ldapcfile);
			strcpy(ldap_password,"");
                       } else {
                         strcpy(ldap_password,namestr);
                       }
               }
                if(strncasecmp(buffer, "basedn", 6) == 0) {
                        /* Read the BASEDN line */
			ptr = buffer + 6;
			fieldcpy(ldap_basedn,&ptr);
               }
                if(strncasecmp(buffer, "filter", 6) == 0) {
			 ptr = buffer + 6;                  
			 fieldcpy(ldap_filter,&ptr);
               }
                if(strncasecmp(buffer, "doauth", 6) == 0) {
                        /* Read the DOAUTH line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of ldapserver file %s", 
					line_no,ldapcfile);
                       } else {
                         if(strncasecmp(namestr, "yes", 3) == 0) {
                           use_ldap_auth = 1;
                         } else {
                           use_ldap_auth = 0;
                         }
                       }
               }
       }
       fclose(ldapcfd);

/*       if (!ldap_password) 
	  strcpy(ldap_password,"");
       if (!ldap_login)
	  strcpy(ldap_login,"");
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
 *	Function: ldap_pass
 *
 *	Purpose: Check the user's password against ldap database 
 *
 *************************************************************************/

static int rlm_ldap_pass(REQUEST *request, char *name, char *passwd)
{
    static LDAP *ld;
    LDAPMessage *result, *msg;
    char *filter, *dn,
	*attrs[] = { "uid",
		     NULL };
    
    if (use_ldap_auth == 0) 
    {
      log(L_ERR,"LDAP Auth specified in users file, but not in ldapserver file");
      return -1;
    }
    if (ld == NULL) {
  if ( (ld = ldap_init(ldap_server,ldap_port)) == NULL) 
	return -1;
  if ( (ldap_simple_bind_s(ld,ldap_login,ldap_password)) != LDAP_SUCCESS) {
	log(L_ERR,"LDAP ldap_simple_bind_s failed");
	ldap_unbind_s(ld);
	return -1;
  } 

    } else {
	log(L_ERR,"ldap handle already open");
    }

    DEBUG("LDAP login attempt by '%s' with password '%s'",name,passwd);

    if (ld != NULL) {
	filter = make_filter(ldap_filter, name);

    if (ldap_search_s(ld,ldap_basedn,LDAP_SCOPE_SUBTREE,filter,attrs,1,&result) != LDAP_SUCCESS) {
	ldap_unbind_s(ld);
	return -1;
    }

    if ((ldap_count_entries(ld,result)) != 1) {
	ldap_unbind_s(ld);
	return -1;
    }

    if ((msg = ldap_first_entry(ld,result)) == NULL) {
	ldap_unbind_s(ld);
	return -1;
    }

    if ((dn = ldap_get_dn(ld,msg)) == NULL) {
	ldap_unbind_s(ld);
	return -1;
    }

    if (strlen(passwd) == 0) {
	ldap_unbind_s(ld);
	return -1;
    }

    if (ldap_simple_bind_s(ld,dn,passwd) != LDAP_SUCCESS) {
	ldap_unbind_s(ld);
	return -1;
    }

    free(dn);
    ldap_unbind_s(ld);

    DEBUG("User %s successfully authenticated via LDAP", name);
    return 0;
	} else {
	return -1;
	}
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

static  void fieldcpy(char *string, char **uptr)
{
        char    *ptr;

        ptr = *uptr;
        while (*ptr == ' ' || *ptr == '\t') {
              ptr++;
        }
        if(*ptr == '"') {
                ptr++;
                while(*ptr != '"' && *ptr != '\0' && *ptr != '\n') {
                        *string++ = *ptr++;
                }
                *string = '\0';
                if(*ptr == '"') {
                        ptr++;
                }
                *uptr = ptr;
                return;
        }

        while(*ptr != ' ' && *ptr != '\t' && *ptr != '\0' && *ptr != '\n' &&
                                                *ptr != '=' && *ptr != ',') {
                        *string++ = *ptr++;
        }
        *string = '\0';
        *uptr = ptr;
	return;
}

/* globally exported name */
module_t rlm_ldap = {
  "LDAP",
  0,				/* type: reserved */
  rlm_ldap_init,		/* initialization */
  NULL,				/* authorization */
  rlm_ldap_pass,		/* authentication */
  NULL,				/* accounting */
  NULL,				/* detach */
};
