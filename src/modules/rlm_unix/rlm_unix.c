/*
 * rlm_unix.c	authentication: Unix user authentication
 *		accounting:     Functions to write radwtmp file.
 *		Also contains handler for "Group".
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
 * Copyright 2000  Jeff Carneal <jeff@apex.net>
 * Copyright 2000  Alan Curry <pacman@world.std.com>
 */
static const char rcsid[] = "$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include	<stdlib.h>
#include	<string.h>
#include	<grp.h>
#include	<pwd.h>
#include	<sys/types.h>
#include	<sys/stat.h>

#include "config.h"

#ifdef HAVE_SHADOW_H
#  include	<shadow.h>
#endif

#ifdef OSFC2
#  include	<sys/security.h>
#  include	<prot.h>
#endif

#ifdef OSFSIA
#  include	<sia.h>
#  include	<siad.h>
#endif

#include	"radiusd.h"
#include	"modules.h"
#include	"sysutmp.h"
#include	"cache.h"
#include	"conffile.h"
#include	"compat.h"

static char trans[64] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define ENC(c) trans[c]

struct unix_instance {
	int cache_passwd;
	const char *passwd_file;
	const char *shadow_file;
	const char *group_file;
	const char *radwtmp;
	int usegroup;
	struct pwcache *cache;
	time_t cache_reload;
	time_t next_reload;
	time_t last_reload;
};

static CONF_PARSER module_config[] = {
	/*
	 *	Cache the password by default.
	 */
	{ "cache",    PW_TYPE_BOOLEAN,
	  offsetof(struct unix_instance,cache_passwd), NULL, "no" },
	{ "passwd",   PW_TYPE_STRING_PTR,
	  offsetof(struct unix_instance,passwd_file), NULL,  NULL },
	{ "shadow",   PW_TYPE_STRING_PTR,
	  offsetof(struct unix_instance,shadow_file), NULL,  NULL },
	{ "group",    PW_TYPE_STRING_PTR,
	  offsetof(struct unix_instance,group_file), NULL,   NULL },
	{ "radwtmp",  PW_TYPE_STRING_PTR,
	  offsetof(struct unix_instance,radwtmp), NULL,   "NULL" },
	{ "usegroup", PW_TYPE_BOOLEAN,
	  offsetof(struct unix_instance,usegroup), NULL,     "no" },
	{ "cache_reload", PW_TYPE_INTEGER,
	  offsetof(struct unix_instance,cache_reload), NULL, "600" },
	
	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/*
 * groupcmp is part of autz. But it uses the data from an auth instance. So
 * here is where it gets it. By default this will be the first configured
 * auth instance. That can be changed by putting "usegroup = yes" inside an
 * auth instance to explicitly bind all Group checks to it.
 */

/* binds "Group=" to an instance (a particular passwd file) */
static struct unix_instance *group_inst;

/* Tells if the above binding was explicit (usegroup=yes specified in config
 * file) or not ("Group=" was bound to the first instance of rlm_unix */
static int group_inst_explicit;

#ifdef HAVE_GETSPNAM
#if defined(M_UNIX)
static inline const char *get_shadow_name(shadow_pwd_t *spwd) {
	if (spwd == NULL) return NULL;
	return (spwd->pw_name);
}

static inline const char *get_shadow_encrypted_pwd(shadow_pwd_t *spwd) {
	if (spwd == NULL) return NULL;
	return (spwd->pw_passwd);
}
#else /* M_UNIX */
	static inline const char *get_shadow_name(shadow_pwd_t *spwd) {
		if (spwd == NULL) return NULL;
		return (spwd->sp_namp);
	}
	static inline const char *get_shadow_encrypted_pwd(shadow_pwd_t *spwd) {
		if (spwd == NULL) return NULL;
		return (spwd->sp_pwdp);
	}
#endif	/* M_UNIX */
#endif	/* HAVE_GETSPNAM */

static struct passwd *fgetpwnam(const char *fname, const char *name) {
	FILE		*file = fopen(fname, "ro");
	struct passwd	*pwd = NULL;

	if(file == NULL) return NULL;
	do {
		pwd = fgetpwent(file);
		if(pwd == NULL) {
			fclose(file);
			return NULL;
		}
	} while (strcmp(name, pwd->pw_name) != 0);

	fclose(file);
	return pwd;
}

static struct group *fgetgrnam(const char *fname, const char *name) {
	FILE		*file = fopen(fname, "ro");
	struct group	*grp = NULL;

	if(file == NULL) return NULL;

	do {
		grp = fgetgrent(file);
		if(grp == NULL) {
			fclose(file);
			return NULL;
		}
	} while(strcmp(name, grp->gr_name) != 0);
	fclose(file);
	return grp;
}

#ifdef HAVE_GETSPNAM

static shadow_pwd_t *fgetspnam(const char *fname, const char *name) {
	FILE		*file = fopen(fname, "ro");
	shadow_pwd_t	*spwd = NULL;

	if(file == NULL) return NULL;
	do {
		spwd = fgetspent(file);
		if(spwd == NULL) {
			fclose(file);
			return NULL;
		}
	} while(strcmp(name, get_shadow_name(spwd)) != 0);
	fclose(file);
	return spwd;
}

#endif

/*
 *	The Group = handler.
 */
static int groupcmp(void *instance, REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	struct passwd	*pwd;
	struct group	*grp;
	char		**member;
	char		*username;
	int		retval;

	instance = instance;
	check_pairs = check_pairs;
	reply_pairs = reply_pairs;

	if (!group_inst) {
		radlog(L_ERR, "groupcmp: no group list known.");
		return 1;
	}

	/*
	 *	No user name, doesn't compare.
	 */
	if (!req->username) {
		return -1;
	}
	username = (char *)req->username->strvalue;

	if (group_inst->cache_passwd &&
	    (retval = H_groupcmp(group_inst->cache, check, username)) != -2)
		return retval;

	if (group_inst->passwd_file)
		pwd = fgetpwnam(group_inst->passwd_file, username);
	else
		pwd = getpwnam(username);
	if (pwd == NULL)
		return -1;

	if (group_inst->group_file)
		grp = fgetgrnam(group_inst->group_file, (char *)check->strvalue);
	else
		grp = getgrnam((char *)check->strvalue);
	if (grp == NULL)
		return -1;

	retval = (pwd->pw_gid == grp->gr_gid) ? 0 : -1;
	if (retval < 0) {
		for (member = grp->gr_mem; *member && retval; member++) {
			if (strcmp(*member, pwd->pw_name) == 0)
				retval = 0;
		}
	}
	return retval;
}


/*
 *	FIXME:	We really should have an 'init' which makes
 *	System auth == Unix
 */
static int unix_init(void)
{
	/* FIXME - delay these until a group file has been read so we know
	 * groupcmp can actually do something */
	paircompare_register(PW_GROUP, PW_USER_NAME, groupcmp, NULL);
#ifdef PW_GROUP_NAME /* compat */
	paircompare_register(PW_GROUP_NAME, PW_USER_NAME, groupcmp, NULL);
#endif
	return 0;
}

static int unix_instantiate(CONF_SECTION *conf, void **instance)
{
	struct unix_instance *inst;

	/*
	 *	Allocate room for the instance.
	 */
	inst = *instance = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	Parse the configuration, failing if we can't do so.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	if (inst->cache_passwd) {
		radlog(L_INFO, "HASH:  Reinitializing hash structures "
			"and lists for caching...");
		if ((inst->cache = unix_buildpwcache(inst->passwd_file,
						     inst->shadow_file,
						     inst->group_file))==NULL)
                {
			radlog(L_ERR, "HASH:  unable to create user "
				"hash table.  disable caching and run debugs");
			if (inst->passwd_file)
				free((char *) inst->passwd_file);
			if (inst->shadow_file)
				free((char *) inst->shadow_file);
			if (inst->group_file)
				free((char *) inst->group_file);
			if (inst->radwtmp)
				free((char *) inst->radwtmp);
			free(inst);
			return -1;
		}

		if (inst->cache_reload) {
			inst->last_reload = 0;
			inst->next_reload = time(NULL) + inst->cache_reload;
		}
	} else {
		inst->cache = NULL;
	}

	if (inst->usegroup) {
		if (group_inst_explicit) {
			radlog(L_ERR, "Only one group list may be active");
		} else {
			group_inst = inst;
			group_inst_explicit = 1;
		}
	} else if (!group_inst) {
		group_inst = inst;
	}
#undef inst

	return 0;
}

/*
 *	Detach.
 */
static int unix_detach(void *instance)
{
#define inst ((struct unix_instance *)instance)
	if (group_inst == inst) {
		group_inst = NULL;
		group_inst_explicit = 0;
	}
	if (inst->passwd_file)
		free((char *) inst->passwd_file);
	if (inst->shadow_file)
		free((char *) inst->shadow_file);
	if (inst->group_file)
		free((char *) inst->group_file);
	if (inst->radwtmp)
		free((char *) inst->radwtmp);
	if (inst->cache) {
		unix_freepwcache(inst->cache);
	}
#undef inst
	free(instance);
	return 0;
}

static int unix_destroy(void)
{
	paircompare_unregister(PW_GROUP, groupcmp);
#ifdef PW_GROUP_NAME
	paircompare_unregister(PW_GROUP_NAME, groupcmp);
#endif
	return 0;
}


/*
 *	Check the users password against the standard UNIX
 *	password table.
 */
static int unix_authenticate(void *instance, REQUEST *request)
{
#define inst ((struct unix_instance *)instance)
	char *name, *passwd;
	struct passwd	*pwd;
	const char	*encrypted_pass;
	int		ret;
#ifdef HAVE_GETSPNAM
	shadow_pwd_t	*spwd = NULL;
#endif
#ifdef OSFC2
	struct pr_passwd *pr_pw;
#endif
#ifdef OSFSIA
	char		*info[2];
	char		*progname = "radius";
	SIAENTITY	*ent = NULL;
#endif
#ifdef HAVE_GETUSERSHELL
	char		*shell;
#endif

	/* See if we should refresh the cache */
	if (inst->cache && inst->cache_reload
	 && (inst->next_reload < request->timestamp)) {
		/* Time to refresh, maybe ? */
		int must_reload = 0;
		struct stat statbuf;

		DEBUG2("rlm_users : Time to refresh cache.");
		/* Check if any of the files has changed */
		if (inst->passwd_file
		 && (stat(inst->passwd_file, &statbuf) != -1)
		 && (statbuf.st_mtime > inst->last_reload)) {
			must_reload++;
		}

		if (inst->shadow_file
		 && (stat(inst->shadow_file, &statbuf) != -1)
		 && (statbuf.st_mtime > inst->last_reload)) {
			must_reload++;
		}

		if (inst->group_file
		 && (stat(inst->group_file, &statbuf) != -1)
		 && (statbuf.st_mtime > inst->last_reload)) {
			must_reload++;
		}

		if (must_reload) {
			/* Build a new cache to replace old one */
			struct pwcache *oldcache;
			struct pwcache *newcache = unix_buildpwcache(
							inst->passwd_file,
							inst->shadow_file,
							inst->group_file);

			if (newcache) {
				oldcache = inst->cache;
				inst->cache = newcache;
				unix_freepwcache(oldcache);

				inst->last_reload = time(NULL);
			}
		} else {
			DEBUG2("rlm_users : Files were unchanged. Not reloading.");
		}

		/* Schedule next refresh */
		inst->next_reload = time(NULL) + inst->cache_reload;
	}

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!request->username) {
		radlog(L_AUTH, "rlm_unix: Attribute \"User-Name\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Password attribute.
	 */
	if (!request->password) {
		radlog(L_AUTH, "rlm_unix: Attribute \"User-Password\" is required for authentication.");
		return RLM_MODULE_INVALID;
	}

	/*
	 *  Ensure that we're being passed a plain-text password,
	 *  and not anything else.
	 */
	if (request->password->attribute != PW_PASSWORD) {
		radlog(L_AUTH, "rlm_unix: Attribute \"User-Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_INVALID;
	}

	name = (char *)request->username->strvalue;
	passwd = (char *)request->password->strvalue;

	if (inst->cache_passwd &&
	    (ret = H_unix_pass(inst->cache, name, passwd, &request->reply->vps)) != -2)
		return (ret == 0) ? RLM_MODULE_OK : RLM_MODULE_REJECT;

#ifdef OSFSIA
	info[0] = progname;
	info[1] = NULL;
	if (sia_ses_init (&ent, 1, info, NULL, name, NULL, 0, NULL) !=
	    SIASUCCESS)
		return RLM_MODULE_NOTFOUND;
	if ((ret = sia_ses_authent (NULL, passwd, ent)) != SIASUCCESS) {
		if (ret & SIASTOP)
			sia_ses_release (&ent);
		return RLM_MODULE_NOTFOUND;
	}
	if (sia_ses_estab (NULL, ent) == SIASUCCESS) {
		sia_ses_release (&ent);
		return RLM_MODULE_OK;
	}

	return RLM_MODULE_NOTFOUND;
#else /* OSFSIA */
#ifdef OSFC2
	if ((pr_pw = getprpwnam(name)) == NULL)
		return RLM_MODULE_NOTFOUND;
	encrypted_pass = pr_pw->ufld.fd_encrypt;
#else /* OSFC2 */
	/*
	 *	Get encrypted password from password file
	 *
	 *	If a password file was explicitly specified, use it,
	 *	otherwise, use the system routines to read the
	 *	system password file
	 */
	if (inst->passwd_file != NULL) {
		if ((pwd = fgetpwnam(inst->passwd_file, name)) == NULL)
			return RLM_MODULE_NOTFOUND;
	} else if ((pwd = getpwnam(name)) == NULL) {
		return RLM_MODULE_NOTFOUND;
	}
	encrypted_pass = pwd->pw_passwd;
#endif /* OSFC2 */

#ifdef HAVE_GETSPNAM
	/*
	 *      See if there is a shadow password.
	 *
	 *	If a shadow file was explicitly specified, use it,
	 *	otherwise, use the system routines to read the
	 *	system shadow file.
	 *
	 *	Also, if we explicitly specify the password file,
	 *	only query the _system_ shadow file if the encrypted
	 *	password from the passwd file is < 10 characters (i.e.
	 *	a valid password would never crypt() to it).  This will
	 *	prevents users from using NULL password fields as things
	 *	stand right now.
	 */
	if (inst->shadow_file != NULL) {
		if ((spwd = fgetspnam(inst->shadow_file, name)) != NULL)
			encrypted_pass = get_shadow_encrypted_pwd(spwd);
	} else if ((encrypted_pass == NULL) || (strlen(encrypted_pass) < 10)) {
		if ((spwd = getspnam(name)) != NULL)
			encrypted_pass = get_shadow_encrypted_pwd(spwd);
	}
#endif	/* HAVE_GETSPNAM */

#ifdef DENY_SHELL
	/*
	 *	Undocumented temporary compatibility for iphil.NET
	 *	Users with a certain shell are always denied access.
	 */
	if (strcmp(pwd->pw_shell, DENY_SHELL) == 0) {
		radlog(L_AUTH, "rlm_unix: [%s]: invalid shell", name);
		return RLM_MODULE_REJECT;
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
	if (shell == NULL) {
		radlog(L_AUTH, "rlm_unix: [%s]: invalid shell [%s]",
			name, pwd->pw_shell);
		return RLM_MODULE_REJECT;
	}
#endif

#if defined(HAVE_GETSPNAM) && !defined(M_UNIX)
	/*
	 *      Check if password has expired.
	 */
	if (spwd && spwd->sp_expire > 0 &&
	    (request->timestamp / 86400) > spwd->sp_expire) {
		radlog(L_AUTH, "rlm_unix: [%s]: password has expired", name);
		return RLM_MODULE_REJECT;
	}
#endif

#if defined(__FreeBSD__) || defined(bsdi) || defined(_PWF_EXPIRE)
	/*
	 *	Check if password has expired.
	 */
	if ((pwd->pw_expire > 0) &&
	    (request->timestamp > pwd->pw_expire)) {
		radlog(L_AUTH, "rlm_unix: [%s]: password has expired", name);
		return RLM_MODULE_REJECT;
	}
#endif

#ifdef OSFC2
	/*
	 *	Check if account is locked.
	 */
	if (pr_pw->uflg.fg_lock!=1) {
		radlog(L_AUTH, "rlm_unix: [%s]: account locked", name);
		return RLM_MODULE_USERLOCK;
	}
#endif /* OSFC2 */

	/*
	 *	We might have a passwordless account.
	 */
	if (encrypted_pass[0] == 0)
		return RLM_MODULE_OK;

	/*
	 *	Check encrypted password.
	 */
	if (lrad_crypt_check(passwd, encrypted_pass)) {
		radlog(L_AUTH, "rlm_unix: [%s]: invalid password", name);
		return RLM_MODULE_REJECT;
	}
	return RLM_MODULE_OK;
#endif /* OSFSIA */
#undef inst
}

/*
 *	UUencode 4 bits base64. We use this to turn a 4 byte field
 *	(an IP address) into 6 bytes of ASCII. This is used for the
 *	wtmp file if we didn't find a short name in the naslist file.
 */
static char *uue(void *in)
{
	int i;
	static unsigned char res[7];
	unsigned char *data = (unsigned char *)in;

	res[0] = ENC( data[0] >> 2 );
	res[1] = ENC( ((data[0] << 4) & 060) + ((data[1] >> 4) & 017) );
	res[2] = ENC( ((data[1] << 2) & 074) + ((data[2] >> 6) & 03) );
	res[3] = ENC( data[2] & 077 );

	res[4] = ENC( data[3] >> 2 );
	res[5] = ENC( (data[3] << 4) & 060 );
	res[6] = 0;

	for(i = 0; i < 6; i++) {
		if (res[i] == ' ') res[i] = '`';
		if (res[i] < 32 || res[i] > 127)
			printf("uue: protocol error ?!\n");
	}
	return (char *)res;
}


/*
 *	Unix accounting - write a wtmp file.
 */
static int unix_accounting(void *instance, REQUEST *request)
{
	VALUE_PAIR	*vp;
	RADCLIENT	*cl;
	FILE		*fp;
	struct utmp	ut;
	time_t		t;
	char		buf[64];
	const char	*s;
	int		delay = 0;
	int		status = -1;
	int		nas_address = 0;
	int		framed_address = 0;
	int		protocol = -1;
	int		nas_port = 0;
	int		port_seen = 0;
	int		nas_port_type = 0;
	struct unix_instance *inst = (struct unix_instance *) instance;

	/*
	 *	No radwtmp.  Don't do anything.
	 */
	if (!inst->radwtmp) {
		DEBUG2("rlm_unix: No radwtmp file configured.  Ignoring accounting request.");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Which type is this.
	 */
	if ((vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE))==NULL) {
		radlog(L_ERR, "rlm_unix: no Accounting-Status-Type attribute in request.");
		return RLM_MODULE_NOOP;
	}
	status = vp->lvalue;

	/*
	 *	FIXME: handle PW_STATUS_ALIVE like 1.5.4.3 did.
	 */
	if (status != PW_STATUS_START &&
	    status != PW_STATUS_STOP)
		return RLM_MODULE_NOOP;

	/*
	 *	We're only interested in accounting messages
	 *	with a username in it.
	 */
	if ((vp = pairfind(request->packet->vps, PW_USER_NAME)) == NULL)
		return RLM_MODULE_NOOP;

	t = request->timestamp;
	memset(&ut, 0, sizeof(ut));

	/*
	 *	First, find the interesting attributes.
	 */
	for (vp = request->packet->vps; vp; vp = vp->next) {
		switch (vp->attribute) {
			case PW_USER_NAME:
				if (vp->length >= sizeof(ut.ut_name)) {
					memcpy(ut.ut_name, (char *)vp->strvalue, sizeof(ut.ut_name));
				} else {
					strNcpy(ut.ut_name, (char *)vp->strvalue, sizeof(ut.ut_name));
				}
				break;
			case PW_LOGIN_IP_HOST:
			case PW_FRAMED_IP_ADDRESS:
				framed_address = vp->lvalue;
				break;
			case PW_FRAMED_PROTOCOL:
				protocol = vp->lvalue;
				break;
			case PW_NAS_IP_ADDRESS:
				nas_address = vp->lvalue;
				break;
			case PW_NAS_PORT:
				nas_port = vp->lvalue;
				port_seen = 1;
				break;
			case PW_ACCT_DELAY_TIME:
				delay = vp->lvalue;
				break;
			case PW_NAS_PORT_TYPE:
				nas_port_type = vp->lvalue;
				break;
		}
	}

	/*
	 *	We don't store !root sessions, or sessions
	 *	where we didn't see a NAS-Port attribute.
	 */
	if (strncmp(ut.ut_name, "!root", sizeof(ut.ut_name)) == 0 || !port_seen)
		return RLM_MODULE_NOOP;

	/*
	 *	If we didn't find out the NAS address, use the
	 *	originator's IP address.
	 */
	if (nas_address == 0)
		nas_address = request->packet->src_ipaddr;

#ifdef __linux__
	/*
	 *	Linux has a field for the client address.
	 */
	ut.ut_addr = framed_address;
#endif
	/*
	 *	We use the tty field to store the terminal servers' port
	 *	and address so that the tty field is unique.
	 */
	s = "";
	if ((cl = client_find(nas_address)) != NULL)
		s = cl->shortname;
	if (s == NULL || s[0] == 0) s = uue(&(nas_address));
	sprintf(buf, "%03d:%s", nas_port, s);
	strNcpy(ut.ut_line, buf, sizeof(ut.ut_line));

	/*
	 *	We store the dynamic IP address in the hostname field.
	 */
#ifdef UT_HOSTSIZE
	if (framed_address) {
		ip_ntoa(buf, framed_address);
		strncpy(ut.ut_host, buf, sizeof(ut.ut_host));
	}
#endif
#ifdef HAVE_UTMPX_H
	ut.ut_xtime = t- delay;
#else
	ut.ut_time = t - delay;
#endif
#ifdef USER_PROCESS
	/*
	 *	And we can use the ID field to store
	 *	the protocol.
	 */
	if (protocol == PW_PPP)
		strcpy(ut.ut_id, "P");
	else if (protocol == PW_SLIP)
		strcpy(ut.ut_id, "S");
	else
		strcpy(ut.ut_id, "T");
	ut.ut_type = status == PW_STATUS_STOP ? DEAD_PROCESS : USER_PROCESS;
#endif
	if (status == PW_STATUS_STOP)
		ut.ut_name[0] = 0;

	/*
	 *	Write a RADIUS wtmp log file.
	 *
	 *	Try to open the file if we can't, we don't write the
	 *	wtmp file. If we can try to write. If we fail,
	 *	return RLM_MODULE_FAIL ..
	 */
	if ((fp = fopen(inst->radwtmp, "a")) != NULL) {
		if ((fwrite(&ut, sizeof(ut), 1, fp)) != 1) {
			fclose(fp);
			return RLM_MODULE_FAIL;
		}
		fclose(fp);
	} else 
		return RLM_MODULE_FAIL;

	return RLM_MODULE_OK;
}

/* globally exported name */
module_t rlm_unix = {
  "System",
  RLM_TYPE_THREAD_UNSAFE,        /* type: reserved */
  unix_init,                    /* initialization */
  unix_instantiate,		/* instantiation */
  {
	  unix_authenticate,    /* authentication */
	  NULL,                 /* authorization */
	  NULL,                 /* preaccounting */
	  unix_accounting,      /* accounting */
	  NULL,                  /* checksimul */
	  NULL,			/* pre-proxy */
	  NULL,			/* post-proxy */
	  NULL			/* post-auth */
  },
  unix_detach,                 	/* detach */
  unix_destroy,                  /* destroy */
};

