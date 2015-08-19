/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file rlm_pam.c
 * @brief Interfaces with the PAM library to allow auth via PAM.
 *
 * @note This was taken from the hacks that miguel a.l. paraz <map@iphil.net>
 *	did on radiusd-cistron-1.5.3 and migrated to a separate file.
 *	That, in fact, was again based on the original stuff from
 *	Jeph Blaize <jblaize@kiva.net> done in May 1997.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 1997  Jeph Blaize <jblaize@kiva.net>
 * @copyright 1999  miguel a.l. paraz <map@iphil.net>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "config.h"

#ifdef HAVE_SECURITY_PAM_APPL_H
#  include <security/pam_appl.h>
#endif

#ifdef HAVE_PAM_PAM_APPL_H
#  include <pam/pam_appl.h>
#endif

#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#endif

typedef struct rlm_pam_t {
	char const *pam_auth_name;
} rlm_pam_t;

static const CONF_PARSER module_config[] = {
	{ "pam_auth", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_pam_t, pam_auth_name), "radiusd" },
	CONF_PARSER_TERMINATOR
};

typedef struct rlm_pam_data_t {
	REQUEST		*request;	//!< The current request.
	char const	*username;	//!< Username to provide to PAM when prompted.
	char const	*password;	//!< Password to provide to PAM when prompted.
	bool		error;		//!< True if pam_conv failed.
} rlm_pam_data_t;

/** Dialogue between RADIUS and PAM modules
 *
 * Uses PAM's appdata_ptr so it's thread safe, and doesn't
 * have any nasty static variables hanging around.
 */
static int pam_conv(int num_msg, struct pam_message const **msg, struct pam_response **resp, void *appdata_ptr)
{
	int count;
	struct pam_response *reply;
	REQUEST *request;
	rlm_pam_data_t *pam_config = (rlm_pam_data_t *) appdata_ptr;

	request = pam_config->request;

/* strdup(NULL) doesn't work on some platforms */
#define COPY_STRING(s) ((s) ? strdup(s) : NULL)

	reply = rad_malloc(num_msg * sizeof(struct pam_response));
	memset(reply, 0, num_msg * sizeof(struct pam_response));
	for (count = 0; count < num_msg; count++) {
		switch (msg[count]->msg_style) {
		case PAM_PROMPT_ECHO_ON:
			reply[count].resp_retcode = PAM_SUCCESS;
			reply[count].resp = COPY_STRING(pam_config->username);
			break;

		case PAM_PROMPT_ECHO_OFF:
			reply[count].resp_retcode = PAM_SUCCESS;
			reply[count].resp = COPY_STRING(pam_config->password);
			break;

		case PAM_TEXT_INFO:
			RDEBUG2("%s", msg[count]->msg);
			break;

		case PAM_ERROR_MSG:
		default:
			RERROR("PAM conversation failed");
			/* Must be an error of some sort... */
			for (count = 0; count < num_msg; count++) {
				if (msg[count]->msg_style == PAM_ERROR_MSG) RERROR("%s", msg[count]->msg);
				if (reply[count].resp) {
	  				/* could be a password, let's be sanitary */
	  				memset(reply[count].resp, 0, strlen(reply[count].resp));
	  				free(reply[count].resp);
				}
			}
			free(reply);
			pam_config->error = true;
			return PAM_CONV_ERR;
		}
	}
	*resp = reply;
	/* PAM frees reply (including reply[].resp) */

	return PAM_SUCCESS;
}

/** Check the users password against the standard UNIX password table + PAM.
 *
 * @note For most flexibility, passing a pamauth type to this function
 *	 allows you to have multiple authentication types (i.e. multiple
 *	 files associated with radius in /etc/pam.d).
 *
 * @param request The current request.
 * @param username User to authenticate.
 * @param passwd Password to authenticate with,
 * @param pamauth Type of PAM authentication.
 * @return 0 on success -1 on failure.
 */
static int do_pam(REQUEST *request, char const *username, char const *passwd, char const *pamauth)
{
	pam_handle_t *handle = NULL;
	int ret;
	rlm_pam_data_t pam_config;
	struct pam_conv conv;

	/*
	 *  Initialize the structures
	 */
	conv.conv = pam_conv;
	conv.appdata_ptr = &pam_config;
	pam_config.request = request;
	pam_config.username = username;
	pam_config.password = passwd;
	pam_config.error = false;

	RDEBUG2("Using pamauth string \"%s\" for pam.conf lookup", pamauth);

	ret = pam_start(pamauth, username, &conv, &handle);
	if (ret != PAM_SUCCESS) {
		RERROR("pam_start failed: %s", pam_strerror(handle, ret));
		return -1;
	}

	ret = pam_authenticate(handle, 0);
	if (ret != PAM_SUCCESS) {
		RERROR("pam_authenticate failed: %s", pam_strerror(handle, ret));
		pam_end(handle, ret);
		return -1;
	}

	/*
	 *	FreeBSD 3.x doesn't have account and session management
	 *	functions in PAM, while 4.0 does.
	 */
#if !defined(__FreeBSD_version) || (__FreeBSD_version >= 400000)
	ret = pam_acct_mgmt(handle, 0);
	if (ret != PAM_SUCCESS) {
		RERROR("pam_acct_mgmt failed: %s", pam_strerror(handle, ret));
		pam_end(handle, ret);
		return -1;
	}
#endif
	RDEBUG2("Authentication succeeded");
	pam_end(handle, ret);
	return 0;
}

static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, REQUEST *request)
{
	int ret;
	VALUE_PAIR *pair;
	rlm_pam_t *data = (rlm_pam_t *) instance;

	char const *pam_auth_string = data->pam_auth_name;

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!request->username) {
		RAUTH("Attribute \"User-Name\" is required for authentication");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Password attribute.
	 */
	if (!request->password) {
		RAUTH("Attribute \"User-Password\" is required for authentication");
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Ensure that we're being passed a plain-text password,
	 *  and not anything else.
	 */
	if (request->password->da->attr != PW_USER_PASSWORD) {
		RAUTH("Attribute \"User-Password\" is required for authentication.  Cannot use \"%s\".", request->password->da->name);
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Let the 'users' file over-ride the PAM auth name string,
	 *	for backwards compatibility.
	 */
	pair = fr_pair_find_by_num(request->config, PW_PAM_AUTH, 0, TAG_ANY);
	if (pair) pam_auth_string = pair->vp_strvalue;

	ret = do_pam(request, request->username->vp_strvalue, request->password->vp_strvalue, pam_auth_string);
	if (ret < 0) return RLM_MODULE_REJECT;

	return RLM_MODULE_OK;
}

extern module_t rlm_pam;
module_t rlm_pam = {
	.magic		= RLM_MODULE_INIT,
	.name		= "pam",
	.type		= RLM_TYPE_THREAD_UNSAFE,	/* The PAM libraries are not thread-safe */
	.inst_size	= sizeof(rlm_pam_t),
	.config		= module_config,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate
	},
};

