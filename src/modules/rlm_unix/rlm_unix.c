/*
 * rlm_unix.c	authentication: Unix user authentication
 *		accounting:     Functions to write radwtmp file.
 *		Also contains handler for "Group".
 *
 * Version:	$Id$
 *
 */
static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<grp.h>
#include	<pwd.h>
#include	<errno.h>

#include "config.h"

#if HAVE_MALLOC_H
#  include <malloc.h>
#endif

#if HAVE_SHADOW_H
#  include	<shadow.h>
#endif

#if HAVE_CRYPT_H
#  include <crypt.h>
#endif

#ifdef OSFC2
#  include	<sys/security.h>
#  include	<prot.h>
#endif

#include	"radiusd.h"
#include	"modules.h"
#include	"sysutmp.h"
#include	"cache.h"
#include	"conffile.h"

static char trans[64] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define ENC(c) trans[c]

/*
 *	Cache the password by default.
 */
static int cache_passwd = TRUE;
static char *passwd_file = NULL;
static char *shadow_file = NULL;
static char *group_file = NULL;

static CONF_PARSER module_config[] = {
	{ "cache",  PW_TYPE_BOOLEAN,    &cache_passwd, "yes" },
	{ "passwd", PW_TYPE_STRING_PTR, &passwd_file,  NULL },
	{ "shadow", PW_TYPE_STRING_PTR, &shadow_file,  NULL },
	{ "group",  PW_TYPE_STRING_PTR, &group_file,   NULL },
	
	{ NULL, -1, NULL, NULL }		/* end the list */
};

/*
 *	The Group = handler.
 */
static int groupcmp(VALUE_PAIR *request, VALUE_PAIR *check,
	VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	struct passwd	*pwd;
	struct group	*grp;
	char		**member;
	char		*username;
	int		retval;
	check_pairs = check_pairs; reply_pairs = reply_pairs;

	username = (char *)request->strvalue;

	if (cache_passwd && (retval = H_groupcmp(check, username)) != -2)
		return retval;

	if ((pwd = getpwnam(username)) == NULL)
		return -1;

	if ((grp = getgrnam((char *)check->strvalue)) == NULL)
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
	paircompare_register(PW_GROUP, PW_USER_NAME, groupcmp);
#ifdef PW_GROUP_NAME /* compat */
	paircompare_register(PW_GROUP_NAME, PW_USER_NAME, groupcmp);
#endif
	return 0;
}

static int unix_instantiate(CONF_SECTION *conf, void **instance)
{
	/*
	 *	Not yet multiple-instance-aware. groupcmp is a real
	 *	obstacle.
	 */
	static int alreadydone=0;

	if (alreadydone) {
		log(L_ERR,
		    "rlm_unix: can't handle multiple authentication instances");
		return -1;
	}
	if (cf_section_parse(conf, module_config) < 0) {
		return -1;
	}

	if (cache_passwd) {
		log(L_INFO, "HASH:  Reinitializing hash structures "
			"and lists for caching...");
		if (unix_buildHashTable(passwd_file, shadow_file) < 0) {
			log(L_ERR, "HASH:  unable to create user "
				"hash table.  disable caching and run debugs");
			return -1;
		}
		if (unix_buildGrpList() < 0) {
			log(L_ERR, "HASH:  unable to cache groups file.  "
				"disable caching and run debugs");
			return -1;
		}
	}

	alreadydone = 1;
	*instance = 0;
	return 0;
}

/*
 *	Detach.
 */
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
	char *name, *passwd;
	struct passwd	*pwd;
	char		*encpw;
	char		*encrypted_pass;
	int		ret;
#if HAVE_GETSPNAM
#if defined(M_UNIX)
	struct passwd	*spwd;
#else
	struct spwd	*spwd;
#endif
#endif
#ifdef OSFC2
	struct pr_passwd *pr_pw;
#endif
#ifdef HAVE_GETUSERSHELL
	char		*shell;
#endif
	instance = instance;

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a User-Name attribute.
	 */
	if (!request->username) {
		log(L_AUTH, "rlm_unix: Attribute \"User-Name\" is required for authentication.");
		return RLM_MODULE_REJECT;
	}

	/*
	 *	We can only authenticate user requests which HAVE
	 *	a Password attribute.
	 */
	if (!request->password) {
		log(L_AUTH, "rlm_unix: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_REJECT;
	}

	/*
	 *  Ensure that we're being passed a plain-text password,
	 *  and not anything else.
	 */
	if (request->password->attribute != PW_PASSWORD) {
		log(L_AUTH, "rlm_unix: Attribute \"Password\" is required for authentication.  Cannot use \"%s\".", request->password->name);
		return RLM_MODULE_REJECT;
	}

	name = (char *)request->username->strvalue;
	passwd = (char *)request->password->strvalue;

	if (cache_passwd && (ret = H_unix_pass(name, passwd)) != -2)
		return (ret == 0) ? RLM_MODULE_OK : RLM_MODULE_REJECT;

#ifdef OSFC2
	if ((pr_pw = getprpwnam(name)) == NULL)
		return RLM_MODULE_REJECT;
	encrypted_pass = pr_pw->ufld.fd_encrypt;
#else /* OSFC2 */
	/*
	 *	Get encrypted password from password file
	 */
	if ((pwd = getpwnam(name)) == NULL) {
		return RLM_MODULE_REJECT;
	}
	encrypted_pass = pwd->pw_passwd;
#endif /* OSFC2 */

#if HAVE_GETSPNAM
	/*
	 *      See if there is a shadow password.
	 */
	if ((spwd = getspnam(name)) != NULL)
#if defined(M_UNIX)
		encrypted_pass = spwd->pw_passwd;
#else
		encrypted_pass = spwd->sp_pwdp;
#endif	/* M_UNIX */
#endif	/* HAVE_GETSPNAM */

#ifdef DENY_SHELL
	/*
	 *	Undocumented temporary compatibility for iphil.NET
	 *	Users with a certain shell are always denied access.
	 */
	if (strcmp(pwd->pw_shell, DENY_SHELL) == 0) {
		log(L_AUTH, "rlm_unix: [%s]: invalid shell", name);
		return RLM_MODULE_REJECT;
	}
#endif

#if HAVE_GETUSERSHELL
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
	if (shell == NULL)
		return RLM_MODULE_REJECT;
#endif

#if defined(HAVE_GETSPNAM) && !defined(M_UNIX)
	/*
	 *      Check if password has expired.
	 */
	if (spwd && spwd->sp_expire > 0 &&
	    (time(NULL) / 86400) > spwd->sp_expire) {
		log(L_AUTH, "rlm_unix: [%s]: password has expired", name);
		return RLM_MODULE_REJECT;
	}
#endif

#if defined(__FreeBSD__) || defined(bsdi) || defined(_PWF_EXPIRE)
	/*
	 *	Check if password has expired.
	 */
	if (pwd->pw_expire > 0 && time(NULL) > pwd->pw_expire) {
		log(L_AUTH, "rlm_unix: [%s]: password has expired", name);
		return RLM_MODULE_REJECT;
	}
#endif

#ifdef OSFC2
	/*
	 *	Check if account is locked.
	 */
	if (pr_pw->uflg.fg_lock!=1) {
		log(L_AUTH, "rlm_unix: [%s]: account locked", name);
		return RLM_MODULE_REJECT;
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
	encpw = crypt(passwd, encrypted_pass);
	if (strcmp(encpw, encrypted_pass))
		return RLM_MODULE_REJECT;

	return RLM_MODULE_OK;
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
	NAS		*cl;
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

	instance = instance;

	/*
	 *	Which type is this.
	 */
	if ((vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE))==NULL) {
		log(L_ERR, "Accounting: no Accounting-Status-Type record.");
		return RLM_MODULE_OK;
	}
	status = vp->lvalue;

	/*
	 *	FIXME: handle PW_STATUS_ALIVE like 1.5.4.3 did.
	 */
	if (status != PW_STATUS_START &&
	    status != PW_STATUS_STOP)
		return RLM_MODULE_OK;

	/*
	 *	We're only interested in accounting messages
	 *	with a username in it.
	 */
	if ((vp = pairfind(request->packet->vps, PW_USER_NAME)) == NULL)
		return RLM_MODULE_OK;

	time(&t);
	memset(&ut, 0, sizeof(ut));

	/*
	 *	First, find the interesting attributes.
	 */
	for (vp = request->packet->vps; vp; vp = vp->next) {
		switch (vp->attribute) {
			case PW_USER_NAME:
				strNcpy(ut.ut_name, (char *)vp->strvalue, sizeof(ut.ut_name));
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
			case PW_NAS_PORT_ID:
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
	 *	where we didn't see a PW_NAS_PORT_ID.
	 */
	if (strncmp(ut.ut_name, "!root", sizeof(ut.ut_name)) == 0 || !port_seen)
		return RLM_MODULE_OK;

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
	if ((cl = nas_find(nas_address)) != NULL)
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
		strncpy(ut.ut_host, buf, UT_HOSTSIZE);
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
	 *	FIXME: return correct error.
	 *	Check if file is there. If not, we don't write the
	 *	wtmp file. If it is, we try to write. If we fail,
	 *	return RLM_MODULE_FAIL ..
	 */
	if ((fp = fopen(RADWTMP, "a")) != NULL) {
		fwrite(&ut, sizeof(ut), 1, fp);
		fclose(fp);
	}

	return RLM_MODULE_OK;
}

/* globally exported name */
module_t rlm_unix = {
  "System",
  0,                            /* type: reserved */
  unix_init,                    /* initialization */
  unix_instantiate,		/* instantiation */
  NULL,                         /* authorization */
  unix_authenticate,            /* authentication */
  NULL,                         /* preaccounting */
  unix_accounting,              /* accounting */
  NULL,                  	/* detach */
  unix_destroy,                  /* destroy */
};

