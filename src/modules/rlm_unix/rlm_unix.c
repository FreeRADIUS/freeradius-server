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
 * @file rlm_unix.c
 * @brief Unixy things
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Jeff Carneal (jeff@apex.net)
 * @copyright 2000 Alan Curry (pacman@world.std.com)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#define LOG_PREFIX mctx->mi->name

#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/perm.h>
#include <freeradius-devel/unlang/xlat_func.h>

#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>

#include "config.h"

#ifdef HAVE_SHADOW_H
#  include <shadow.h>
#endif

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_unix_dict[];
fr_dict_autoload_t rlm_unix_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_crypt_password;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_login_ip_host;
static fr_dict_attr_t const *attr_framed_ip_address;
static fr_dict_attr_t const *attr_framed_protocol;
static fr_dict_attr_t const *attr_nas_ip_address;
static fr_dict_attr_t const *attr_nas_port;
static fr_dict_attr_t const *attr_acct_status_type;
static fr_dict_attr_t const *attr_acct_delay_time;
static fr_dict_attr_t const *attr_expr_bool_enum;

extern fr_dict_attr_autoload_t rlm_unix_dict_attr[];
fr_dict_attr_autoload_t rlm_unix_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_crypt_password, .name = "Password.Crypt", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_login_ip_host, .name = "Login-IP-Host", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_framed_ip_address, .name = "Framed-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_framed_protocol, .name = "Framed-Protocol", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_nas_ip_address, .name = "NAS-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_nas_port, .name = "NAS-Port", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_acct_delay_time, .name = "Acct-Delay-Time", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_expr_bool_enum, .name = "Expr-Bool-Enum", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ NULL }
};

/** Check if the user is in the given group
 *
 */
static bool CC_HINT(nonnull) unix_check_group(request_t *request, char const *name)
{
	bool		rcode = false;
	struct passwd	*pwd;
	struct group	*grp;
	fr_pair_t	*username;

	/*
	 *	No user name, can't compare.
	 */
	username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	if (!username) return false;

	if (fr_perm_getpwnam(request, &pwd, username->vp_strvalue) < 0) {
		RPEDEBUG("Failed resolving user name");
		return false;
	}

	if (fr_perm_getgrnam(request, &grp, name) < 0) {
		RPEDEBUG("Failed resolving group name");
		talloc_free(pwd);
		return false;
	}

	/*
	 *	The users default group may be the one we're looking
	 *	for, in which case we use that.
	 *
	 *	Otherwise, we go through the list of groups to see if the group name matches.
	 */
	if (pwd->pw_gid == grp->gr_gid) {
		rcode = true;

	} else {
		char **member;

		for (member = grp->gr_mem; *member; member++) {
			if (strcmp(*member, pwd->pw_name) == 0) {
				rcode = true;
				break;
			}
		}
	}

	/* lifo */
	talloc_free(grp);
	talloc_free(pwd);

	return rcode;
}


/** Check if the user is a member of a particular unix group
 *
@verbatim
%unix.group(<name>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t unix_group_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     UNUSED xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	fr_value_box_t		*arg = fr_value_box_list_head(in);
	char const		*p = arg->vb_strvalue;
	fr_value_box_t		*vb;

	fr_skip_whitespace(p);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));
	vb->vb_bool = unix_check_group(request, p);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


/*
 *	Read the config
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t			*xlat;
	xlat_arg_parser_t	*xlat_arg;

	/*
	 *	Define the new %unix.group(name) xlat.  The register
	 *	function automatically adds the module instance name
	 *	as a prefix.
	 */
	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "group", unix_group_xlat, FR_TYPE_BOOL);
	if (!xlat) {
		PERROR("Failed registering group expansion");
		return -1;
	}

	/*
	 *	The xlat escape function needs access to inst - so
	 *	argument parser details need to be defined here
	 */
	xlat_arg = talloc_zero_array(xlat, xlat_arg_parser_t, 2);
	xlat_arg[0] = (xlat_arg_parser_t) {
		.type = FR_TYPE_STRING,
		.required = true,
		.concat = true
	};
	xlat_arg[1] = (xlat_arg_parser_t)XLAT_ARG_PARSER_TERMINATOR;

	xlat_func_args_set(xlat, xlat_arg);

	return 0;
}


/*
 *	Pull the users password from where-ever, and add it to
 *	the given vp list.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	char const	*name;
	char const	*encrypted_pass;
#ifdef HAVE_GETSPNAM
	struct spwd	*spwd = NULL;
#endif
	struct passwd	*pwd;
#ifdef HAVE_GETUSERSHELL
	char		*shell;
#endif
	fr_pair_t	*vp;
	fr_pair_t	*username;

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	if (!username) RETURN_MODULE_NOOP;

	name = username->vp_strvalue;
	encrypted_pass = NULL;

	if ((pwd = getpwnam(name)) == NULL) {
		RETURN_MODULE_NOTFOUND;
	}
	encrypted_pass = pwd->pw_passwd;

#ifdef HAVE_GETSPNAM
	/*
	 *      See if there is a shadow password.
	 *
	 *	Only query the _system_ shadow file if the encrypted
	 *	password from the passwd file is < 10 characters (i.e.
	 *	a valid password would never crypt() to it).  This will
	 *	prevents users from using NULL password fields as things
	 *	stand right now.
	 */
	if ((!encrypted_pass) || (strlen(encrypted_pass) < 10)) {
		if ((spwd = getspnam(name)) == NULL) {
			RETURN_MODULE_NOTFOUND;
		}
		encrypted_pass = spwd->sp_pwdp;
	}
#endif	/* HAVE_GETSPNAM */

#ifdef DENY_SHELL
	/*
	 *	Users with a particular shell are denied access
	 */
	if (strcmp(pwd->pw_shell, DENY_SHELL) == 0) {
		REDEBUG("Invalid shell", name);
		RETURN_MODULE_REJECT;
	}
#endif

#ifdef HAVE_GETUSERSHELL
	/*
	 *	Check /etc/shells for a valid shell. If that file
	 *	contains /RADIUSD/ANY/SHELL then any shell will do.
	 */
	while ((shell = getusershell()) != NULL) {
		if (strcmp(shell, pwd->pw_shell) == 0 ||
		    strcmp(shell, "/RADIUSD/ANY/SHELL") == 0) {
			break;
		}
	}
	endusershell();
	if (!shell) {
		REDEBUG("[%s]: invalid shell [%s]", name, pwd->pw_shell);
		RETURN_MODULE_REJECT;
	}
#endif

#if defined(HAVE_GETSPNAM) && !defined(M_UNIX)
	/*
	 *      Check if password has expired.
	 */
	if (spwd && spwd->sp_lstchg > 0 && spwd->sp_max >= 0 &&
	    (fr_time_to_sec(request->packet->timestamp) / 86400) > (spwd->sp_lstchg + spwd->sp_max)) {
		REDEBUG("[%s]: password has expired", name);
		RETURN_MODULE_REJECT;
	}
	/*
	 *      Check if account has expired.
	 */
	if (spwd && spwd->sp_expire > 0 &&
	    (fr_time_to_sec(request->packet->timestamp) / 86400) > spwd->sp_expire) {
		REDEBUG("[%s]: account has expired", name);
		RETURN_MODULE_REJECT;
	}
#endif

#if defined(__FreeBSD__) || defined(bsdi) || defined(_PWF_EXPIRE)
	/*
	 *	Check if password has expired.
	 */
	if ((pwd->pw_expire > 0) &&
	    (fr_time_to_sec(request->packet->timestamp) > pwd->pw_expire)) {
		REDEBUG("[%s]: password has expired", name);
		RETURN_MODULE_REJECT;
	}
#endif

	/*
	 *	We might have a passwordless account.
	 *
	 *	FIXME: Maybe add Auth-Type := Accept?
	 */
	if (encrypted_pass[0] == 0)
		RETURN_MODULE_NOOP;

	MEM(pair_update_control(&vp, attr_crypt_password) >= 0);
	fr_pair_value_strdup(vp, encrypted_pass, false);

	RETURN_MODULE_UPDATED;
}


/* globally exported name */
extern module_rlm_t rlm_unix;
module_rlm_t rlm_unix = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "unix",
		.flags		= MODULE_TYPE_THREAD_UNSAFE,
		.bootstrap	= mod_bootstrap
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("recv", "Access-Request"), .method = mod_authorize },
			MODULE_BINDING_TERMINATOR
		}
	}
};
