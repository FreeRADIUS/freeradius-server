/*
 * compat.c	Compatibity routines for fgetpwent(), fgetspent(), and fgetgrent()
 *
 *		The code in here was borrowed from the cache.c module
 *		and adapted to be a standalone set of functions.
 *
 * Version: $Id$
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
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright 2001  The FreeRADIUS server project.
 */    
static const char rcsid[] = "$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include <stdlib.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"

#ifdef HAVE_SHADOW_H
#  include <shadow.h>
#endif

#include "radiusd.h"
#include "cache.h"
#include "compat.h"


#ifndef HAVE_FGETPWENT

struct passwd *rad_fgetpwent(FILE *pwhandle) {
	static struct passwd pwbuf;
	static char username[MAX_STRING_LEN];
	static char userpwd[64];
	static char gecostmp[128];
	static char homedirtmp[128];
	static char shelltmp[128];
	char uidtmp[16];
	char gidtmp[16];
	char *ptr, *bufptr;
	char buffer[BUFSIZE];
	int len;



#define RAD_EXTRACT_FIELD(txt_field, tmp_buf) \
	for(bufptr = ptr; (*ptr != '\0') && (*ptr != '\n') && (*ptr != ':'); ptr++); \
	len = ptr - bufptr; \
	if((len+1) > sizeof(tmp_buf)) { \
		radlog(L_ERR, "rlm_unix:  %s too long in line: %s", (txt_field), buffer); \
		return rad_fgetpwent(pwhandle); \
	} \
	strncpy((tmp_buf), bufptr, len); \
	(tmp_buf)[len] = '\0';



	if (pwhandle == NULL)
		return NULL;

	if (fgets(buffer, BUFSIZE , pwhandle) == (char *)NULL)
		return NULL;

	memset(&pwbuf, 0, sizeof(struct passwd));
	memset(username, 0, sizeof(username));
	memset(userpwd, 0, sizeof(userpwd));
	memset(gecostmp, 0, sizeof(gecostmp));
	memset(homedirtmp, 0, sizeof(homedirtmp));
	memset(shelltmp, 0, sizeof(shelltmp));
	buffer[BUFSIZE] ='\0';

	/* Get usernames from the password file */
	ptr = buffer;
	RAD_EXTRACT_FIELD("Username", username);
	pwbuf.pw_name = username;
	
	/* Get (encrypted) password from password file (shadow comes later) */
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("Password", userpwd);
	pwbuf.pw_passwd = userpwd;

	/* Get uid from the password file */
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("UID", uidtmp);
	pwbuf.pw_uid = atoi(uidtmp);
	
	/* Get gid from the password file */
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("GID", gidtmp);
	pwbuf.pw_gid = atoi(gidtmp);
	
	/* Get the GECOS (name) field from the password file */
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("GECOS", gecostmp);
	pwbuf.pw_gecos = gecostmp;

	/* Get the home directory from the password file */
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("Home dir", homedirtmp);
	pwbuf.pw_dir = homedirtmp;

	/* Get the shell from the password file */
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("Shell", shelltmp);
	pwbuf.pw_shell = shelltmp;

	return(&pwbuf);
}

#undef RAD_EXTRACT_FIELD

#endif /* HAVE_FGETPWENT */




#ifndef HAVE_FGETSPENT

shadow_pwd_t *rad_fgetspent(FILE *sphandle) {
	static shadow_pwd_t spbuf;
	static char username[MAX_STRING_LEN];
	static char userpwd[64];
	char lastchgtmp[16];
	char mintmp[16];
	char maxtmp[16];
	char warntmp[16];
	char inactmp[16];
	char expiretmp[16];
	char *ptr, *bufptr;
	char buffer[BUFSIZE];
	int len;

#define RAD_EXTRACT_FIELD(txt_field, tmp_buf) \
	for(bufptr = ptr; (*ptr != '\0') && (*ptr != '\n') && (*ptr != ':'); ptr++); \
	len = ptr - bufptr; \
	if((len+1) > sizeof(tmp_buf)) { \
		radlog(L_ERR, "rlm_unix:  %s too long in line: %s", (txt_field), buffer); \
		return rad_fgetspent(sphandle); \
	} \
	strncpy((tmp_buf), bufptr, len); \
	(tmp_buf)[len] = '\0';



	if (sphandle == NULL)
		return NULL;

	if (fgets(buffer, BUFSIZE, sphandle) == (char *)NULL)
		return NULL;

	memset(&spbuf, 0, sizeof(shadow_pwd_t));
	memset(username, 0, sizeof(username));
	memset(userpwd, 0, sizeof(userpwd));
	buffer[BUFSIZE] ='\0';

	/* Get usernames from the shadow file */
	ptr = buffer;
	RAD_EXTRACT_FIELD("Username", username);
	GET_SP_NAME(&spbuf) = username;
	
	/* Get (encrypted) passwords from the shadow file */
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("Password", userpwd);
	GET_SP_PWD(&spbuf) = userpwd;

	/* Get the 'last change' field from the shadow file */
#ifdef GET_SP_LSTCHG
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("'Last change'", lastchgtmp);
	GET_SP_LSTCHG(&spbuf) = atoi(lastchgtmp);
#endif

	/* Get the 'minimum time between changes' field from the shadow file */
#ifdef GET_SP_MIN
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("'Min change'", mintmp);
	GET_SP_MIN(&spbuf) = atoi(mintmp);
#endif

	/* Get the 'maximum time between changes' field from the shadow file */
#ifdef GET_SP_MAX
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("'Max change'", maxtmp);
	GET_SP_MAX(&spbuf) = atoi(maxtmp);
#endif

	/* Get the 'expire warning time' field from the shadow file */
#ifdef GET_SP_WARN
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("'Warn time'", warntmp);
	GET_SP_WARN(&spbuf) = atoi(warntmp);
#endif

	/* Get the 'account inactivity time' field from the shadow file */
#ifdef GET_SP_INACT
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("'Inactive time'", inactmp);
	GET_SP_INACT(&spbuf) = atoi(inactmp);
#endif

	/* Get the 'expire time' field from the shadow file */
#ifdef GET_SP_EXPIRE
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("'Expire time'", expiretmp);
	GET_SP_EXPIRE(&spbuf) = atoi(expiretmp);
#endif
	return (&spbuf);
}

#undef RAD_EXTRACT_FIELD

#endif  /* HAVE_FGETSPENT */



#ifndef HAVE_FGETGRENT

#define RAD_MAX_GROUP_MEMBERS 500

struct group *rad_fgetgrent(FILE *grhandle) {
	static struct group grbuf;
	static char grname[MAX_STRING_LEN];
	static char grpwd[64];
	static char *grmem[RAD_MAX_GROUP_MEMBERS];
	static char grmembuf[2048];
	char gidtmp[16];
	char *ptr, *bufptr, *grptr;
	char buffer[BUFSIZE];
	int len, gidx;



#define RAD_EXTRACT_FIELD(txt_field, tmp_buf) \
	for(bufptr = ptr; (*ptr != '\0') && (*ptr != '\n') && (*ptr != ':'); ptr++); \
	len = ptr - bufptr; \
	if((len+1) > sizeof(tmp_buf)) { \
		radlog(L_ERR, "rlm_unix:  %s too long in line: %s", (txt_field), buffer); \
		return rad_fgetgrent(grhandle); \
	} \
	strncpy((tmp_buf), bufptr, len); \
	(tmp_buf)[len] = '\0';



	if (grhandle == NULL)
		return NULL;

	if (fgets(buffer, BUFSIZE, grhandle) == (char *)NULL)
		return NULL;

	memset(&grbuf, 0, sizeof(struct group));
	memset(grname, 0, sizeof(grname));
	memset(grpwd, 0, sizeof(grpwd));
	memset(grmem, 0, sizeof(grmem));
	memset(grmembuf, 0, sizeof(grmembuf));
	buffer[BUFSIZE] ='\0';

	/* Get the group name */
	ptr = buffer;
	RAD_EXTRACT_FIELD("Group name", grname);
	grbuf.gr_name = grname;

	/* Get the group password */
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("Group password", grpwd);
	grbuf.gr_passwd = grpwd;

	/* Get the group id */
	if (*ptr != '\0') ptr++;
	RAD_EXTRACT_FIELD("Group ID", gidtmp);
	grbuf.gr_gid = atoi(gidtmp);

	/* Collect all of the group members... */
	gidx = 0;
	grbuf.gr_mem = grmem;
	grbuf.gr_mem[gidx] = NULL;
	grptr = grmembuf;
	while (*ptr != '\0') {
		if (*ptr != '\0') ptr++;
		for(bufptr = ptr; (*ptr != '\0') && (*ptr != '\n') && (*ptr != ','); ptr++);
		len = ptr - bufptr;

		/* Ignore "NULL" entries... */
		if (len == 0) continue;

		if((len+1) > (sizeof(grmembuf) - (grptr - grmembuf))) {
			radlog(L_ERR, "rlm_unix:  Some entries dropped.  Group members line too long: %s", buffer);
			/* Return a partial list */
			return (&grbuf);
		}

		/* Prevent buffer overflows! */
		if (gidx+1 >= RAD_MAX_GROUP_MEMBERS) {
			radlog(L_ERR, "rlm_unix:  Some entries dropped.  Too many group members: %s", buffer);
			/* Return a partial list */
			return (&grbuf);
		}

		strncpy(grptr, bufptr, len);
		grptr[len] = '\0';
		grbuf.gr_mem[gidx++] = grptr;
		grbuf.gr_mem[gidx] = NULL;
		grptr += len + 1;

	}
	return (&grbuf);
}

#undef RAD_EXTRACT_FIELD

#endif /* HAVE_FGETGRENT */
