/*
 * pam.c	Functions to access the PAM library. This was taken
 *		from the hacks that miguel a.l. paraz <map@iphil.net>
 *		did on radiusd-cistron-1.5.3 and migrated to a
 *		separate file.
 *
 *		That, in fact, was again based on the original stuff
 *		from Jeph Blaize <jblaize@kiva.net> done in May 1997.
 *
 * Version:	$Id$
 *
 */

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<string.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>

#include	<security/pam_appl.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"
#include	"modules.h"

/*************************************************************************
 *
 *	Function: PAM_conv
 *
 *	Purpose: Dialogue between RADIUS and PAM modules.
 *
 * jab - stolen from pop3d
 *
 * Alan DeKok: modified to use PAM's appdata_ptr, so that we're
 *             multi-threaded safe, and don't have any nasty static
 *             variables hanging around.
 *
 *************************************************************************/

typedef struct my_PAM {
  const char *username;
  const char *password;
  int         error;
} my_PAM;

static int PAM_conv (int num_msg,
                     const struct pam_message **msg,
                     struct pam_response **resp,
                     void *appdata_ptr) {
  int count = 0, replies = 0;
  struct pam_response *reply = NULL;
  int size = sizeof(struct pam_response);
  my_PAM *pam_config = (my_PAM *) appdata_ptr;
  
#define GET_MEM if (reply) realloc(reply, size); else reply = malloc(size); \
  if (!reply) return PAM_CONV_ERR; \
  size += sizeof(struct pam_response)
#define COPY_STRING(s) ((s) ? strdup(s) : NULL)
				     
  for (count = 0; count < num_msg; count++) {
    switch (msg[count]->msg_style) {
    case PAM_PROMPT_ECHO_ON:
      GET_MEM;
      reply[replies].resp_retcode = PAM_SUCCESS;
      reply[replies++].resp = COPY_STRING(pam_config->username);
      /* PAM frees resp */
      break;
    case PAM_PROMPT_ECHO_OFF:
      GET_MEM;
      reply[replies].resp_retcode = PAM_SUCCESS;
      reply[replies++].resp = COPY_STRING(pam_config->password);
      /* PAM frees resp */
      break;
    case PAM_TEXT_INFO:
      /* ignore it... */
      break;
    case PAM_ERROR_MSG:
    default:
      /* Must be an error of some sort... */
      free (reply);
      pam_config->error = 1;
      return PAM_CONV_ERR;
    }
  }
  if (reply) *resp = reply;

  return PAM_SUCCESS;
}

/*************************************************************************
 *
 *	Function: pam_pass
 *
 *	Purpose: Check the users password against the standard UNIX
 *		 password table + PAM.
 *
 * jab start 19970529
 *************************************************************************/

/* cjd 19980706
 * 
 * for most flexibility, passing a pamauth type to this function
 * allows you to have multiple authentication types (i.e. multiple
 * files associated with radius in /etc/pam.d)
 */
static int pam_pass(const char *name, const char *passwd, const char *pamauth)
{
    pam_handle_t *pamh=NULL;
    int retval;
    my_PAM pam_config;
    struct pam_conv conv;

    /*
     *  Initialize the structures.
     */
    conv.conv = PAM_conv;
    conv.appdata_ptr = &pam_config;
    pam_config.username = name;
    pam_config.password = passwd;
    pam_config.error = 0;

    DEBUG("pam_pass: using pamauth string <%s> for pam.conf lookup", pamauth);
    retval = pam_start(pamauth, name, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
      DEBUG("pam_pass: function pam_start FAILED for <%s>. Reason: %s",
	    name, pam_strerror(pamh, retval));
      return -1;
    }

    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
      DEBUG("pam_pass: function pam_authenticate FAILED for <%s>. Reason: %s",
	    name, pam_strerror(pamh, retval));
      pam_end(pamh, 0);
      return -1;
    }

    /*
     * FreeBSD 3.x doesn't have account and session management
     * functions in PAM, while 4.0 does.
     */
#if !defined(__FreeBSD_version) || (__FreeBSD_version >= 400000)
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
      DEBUG("pam_pass: function pam_acct_mgmt FAILED for <%s>. Reason: %s",
	    name, pam_strerror(pamh, retval));
      pam_end(pamh, 0);
      return -1;
    }
#endif

    DEBUG("pam_pass: authentication succeeded for <%s>", name);
    pam_end(pamh, 0);
    return 0;
}

/* translate between function declarations */
static int pam_auth(REQUEST *request)
{
	int	r;
	VALUE_PAIR *pair;
	const char *pam_auth_string = "radiusd";

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!request->username) {
		log(L_AUTH, "rlm_pam: Attribute \"User-Name\" is required for authentication.");
		return RLM_MODULE_REJECT;
	}

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a Password attribute.
	 */
	if (!request->password) {
		log(L_AUTH, "rlm_pam: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_REJECT;
	}

	/*
	 *  Ensure that we're being passed a plain-text password,
	 *  and not anything else.
	 */
	if (request->password->attribute != PW_PASSWORD) {
		log(L_AUTH, "rlm_pam: Attribute \"Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_REJECT;
	}

	pair = pairfind(request->config_items, PAM_AUTH_ATTR);
	if (pair) pam_auth_string = (char *)pair->strvalue;

	r = pam_pass((char *)request->username->strvalue,
		     (char *)request->password->strvalue,
		     pam_auth_string);
	if (r == 0) {
		return RLM_MODULE_OK;
	}
	return RLM_MODULE_REJECT;
}

module_t rlm_pam = {
  "Pam",
  0,				/* type: reserved */
  NULL,				/* initialize */
  NULL,				/* authorize */
  pam_auth,			/* authenticate */
  NULL,				/* pre-accounting */
  NULL,				/* accounting */
  NULL,				/* detach */
};

