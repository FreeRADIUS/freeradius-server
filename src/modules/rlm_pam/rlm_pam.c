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
 * Copyright 1997  Jeph Blaize <jblaize@kiva.net>
 * Copyright 1999  miguel a.l. paraz <map@iphil.net>
 */

#include	"autoconf.h"
#include	"libradius.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#include	<security/pam_appl.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"
#include	"modules.h"

typedef struct rlm_pam_t {
	const char *pam_auth_name;
} rlm_pam_t;

static rlm_pam_t config;

static CONF_PARSER module_config[] = {
	{ "pam_auth",    PW_TYPE_STRING_PTR, &config.pam_auth_name, "radiusd" },
	{ NULL, -1, NULL, NULL }
};

/*
 *	(Re-)read radiusd.conf into memory.
 */
static int pam_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_pam_t *data;

	if (cf_section_parse(conf, module_config) < 0) {
		return -1;
	}

	data = malloc(sizeof(*data));
	if (!data) {
		radlog(L_ERR|L_CONS, "rlm_pam: Out of memory\n");
		return -1;
	}

	data->pam_auth_name = config.pam_auth_name;
	config.pam_auth_name = NULL;

	*instance = data;
	return 0;
}

/*
 *	Clean up.
 */
static int pam_detach(void *instance)
{
	rlm_pam_t *data = (rlm_pam_t *) instance;

	free((char *) data->pam_auth_name);
        free((char *) data);
	return 0;
}

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
static int pam_auth(void *instance, REQUEST *request)
{
	int	r;
	VALUE_PAIR *pair;
	rlm_pam_t *data = (rlm_pam_t *) instance;

	const char *pam_auth_string = data->pam_auth_name;

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!request->username) {
		radlog(L_AUTH, "rlm_pam: Attribute \"User-Name\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a Password attribute.
	 */
	if (!request->password) {
		radlog(L_AUTH, "rlm_pam: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Ensure that we're being passed a plain-text password,
	 *  and not anything else.
	 */
	if (request->password->attribute != PW_PASSWORD) {
		radlog(L_AUTH, "rlm_pam: Attribute \"Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Let the 'users' file over-ride the PAM auth name string,
	 *	for backwards compatibility.
	 */
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
  pam_instantiate,		/* instantiation */
  NULL,				/* authorize */
  pam_auth,			/* authenticate */
  NULL,				/* pre-accounting */
  NULL,				/* accounting */
  NULL,				/* checksimul */
  pam_detach,			/* detach */
  NULL,				/* destroy */
};

