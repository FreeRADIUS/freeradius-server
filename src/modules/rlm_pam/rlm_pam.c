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
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 1997 Jeph Blaize (jblaize@kiva.net)
 * @copyright 1999 miguel a.l. paraz (map@iphil.net)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>

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

typedef struct {
	char const *pam_auth_name;
} rlm_pam_t;

typedef struct {
	REQUEST		*request;	//!< The current request.
	char const	*username;	//!< Username to provide to PAM when prompted.
	char const	*password;	//!< Password to provide to PAM when prompted.
	bool		error;		//!< True if pam_conv failed.
} rlm_pam_data_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("pam_auth", FR_TYPE_STRING, rlm_pam_t, pam_auth_name) },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_pam_dict[];
fr_dict_autoload_t rlm_pam_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_pam_auth;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t rlm_pam_dict_attr[];
fr_dict_attr_autoload_t rlm_pam_dict_attr[] = {
	{ .out = &attr_pam_auth, .name = "Pam-Auth", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_pam_t *inst = instance;

	if (!inst->pam_auth_name) inst->pam_auth_name = main_config->name;

	return 0;
}

/** Dialogue between RADIUS and PAM modules
 *
 * Uses PAM's appdata_ptr so it's thread safe, and doesn't
 * have any nasty static variables hanging around.
 */
static int pam_conv(int num_msg, struct pam_message const **msg, struct pam_response **resp, void *appdata_ptr)
{
	int		count;
	struct		pam_response *reply;
	REQUEST		*request;
	rlm_pam_data_t	*pam_config = (rlm_pam_data_t *) appdata_ptr;

	request = pam_config->request;

#define COPY_STRING(s) ((s) ? talloc_strdup(reply, s) : NULL)
	MEM(reply = talloc_zero_array(NULL, struct pam_response, num_msg));
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
				}
			}
			talloc_free(reply);
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
 * @return
 *	- 0 on success.
 *	- -1 on failure.
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

static rlm_rcode_t CC_HINT(nonnull) mod_authenticate(void *instance, UNUSED void *thread, REQUEST *request)
{
	int		ret;
	VALUE_PAIR	*pair;
	rlm_pam_t const	*data = instance;
	char const *pam_auth_string = data->pam_auth_name;
	VALUE_PAIR *username, *password;

	username = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
	password = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!username) {
		REDEBUG("Attribute \"User-Name\" is required for authentication");
		return RLM_MODULE_INVALID;
	}

	if (!password) {
		REDEBUG("Attribute \"User-Password\" is required for authentication");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Make sure the supplied password isn't empty
	 */
	if (password->vp_length == 0) {
		REDEBUG("User-Password must not be empty");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	Log the password
	 */
	if (RDEBUG_ENABLED3) {
		RDEBUG("Login attempt with password \"%pV\"", &password->data);
	} else {
		RDEBUG2("Login attempt with password");
	}

	/*
	 *	Let control list over-ride the PAM auth name string,
	 *	for backwards compatibility.
	 */
	pair = fr_pair_find_by_da(request->control, attr_pam_auth, TAG_ANY);
	if (pair) pam_auth_string = pair->vp_strvalue;

	ret = do_pam(request, username->vp_strvalue, password->vp_strvalue, pam_auth_string);
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
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate
	},
};

