/*
 * smbpass.c	
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
 * Copyright 2001  The FreeRADIUS server project
 */
 
/*
 *   smbpass.c contains a set of functions required to handle passwd
 *   files in SAMBA format. Some pieces of code were adopted from SAMBA
 *   project.
 *
 *   ZARAZA	3APA3A@security.nnov.ru
 */

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>
#include <ctype.h>
#include "smbpass.h"

void pdb_init_smb(struct smb_passwd *user)
{
        if (user == NULL) return;
        memset((char *)user, '\0', sizeof(*user));
        user->pass_last_set_time    = (time_t)-1;
        user->smb_passwd = NULL;
        user->smb_nt_passwd = NULL;
        memset(user->smb_name_value,0,256);
        memset(user->smb_passwd_value,0,16);
        memset(user->smb_nt_passwd_value,0,16);
}



uint16 pdb_decode_acct_ctrl(const char *p)
{
	uint16 acct_ctrl = 0;
	int finished = 0;

	/*
	 * Check if the account type bits have been encoded after the
	 * NT password (in the form [NDHTUWSLXI]).
	 */

	if (*p != '[') return 0;

	for (p++; *p && !finished; p++)
	{
		switch (*p)
		{
			case 'N': { acct_ctrl |= ACB_PWNOTREQ ; break; /* 'N'o password. */ }
			case 'D': { acct_ctrl |= ACB_DISABLED ; break; /* 'D'isabled. */ }
			case 'H': { acct_ctrl |= ACB_HOMDIRREQ; break; /* 'H'omedir required. */ }
			case 'T': { acct_ctrl |= ACB_TEMPDUP  ; break; /* 'T'emp account. */ } 
			case 'U': { acct_ctrl |= ACB_NORMAL   ; break; /* 'U'ser account (normal). */ } 
			case 'M': { acct_ctrl |= ACB_MNS      ; break; /* 'M'NS logon user account. What is this ? */ } 
			case 'W': { acct_ctrl |= ACB_WSTRUST  ; break; /* 'W'orkstation account. */ } 
			case 'S': { acct_ctrl |= ACB_SVRTRUST ; break; /* 'S'erver account. */ } 
			case 'L': { acct_ctrl |= ACB_AUTOLOCK ; break; /* 'L'ocked account. */ } 
			case 'X': { acct_ctrl |= ACB_PWNOEXP  ; break; /* No 'X'piry on password */ } 
			case 'I': { acct_ctrl |= ACB_DOMTRUST ; break; /* 'I'nterdomain trust account. */ }
		        case ' ': { break; }
			case ':':
			case '\n':
			case '\0': 
			case ']':
			default:  { finished = 1; }
		}
	}

	return acct_ctrl;
}


static char letters[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		      	'A', 'B', 'C', 'D', 'E', 'F'};


/*
 *	hex2bin converts hexadecimal strings into binary
 */
int hex2bin (const char *szHex, unsigned char* szBin, int len)
{
	char * c1, * c2;
	int i;
   
   	for (i = 0; i < len; i++) {
		if( !(c1 = memchr(letters, toupper(szHex[i << 1]), 16)) ||
		    !(c2 = memchr(letters, toupper(szHex[(i << 1) + 1]), 16)))
		     break;
                 szBin[i] = ((c1-letters)<<4) + (c2-letters);
        }
        return i;
}

/*
 *	bin2hex creates hexadecimal presentation
 *	of binary data
 */ 
void bin2hex (const unsigned char *szBin, char *szHex, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		szHex[i<<1] = letters[szBin[i] >> 4];
		szHex[(i<<1) + 1] = letters[szBin[i] & 0x0F];
	}
}



struct smb_passwd *getsmbfilepwent(struct smb_passwd *pw_buf, FILE *fp)
{
	/* Static buffers we will return. */
	char user_name[256];
	char            linebuf[256];
	unsigned char   c;
	char  *p;
	long            uidval;
	size_t            linebuf_len;


	if(fp == NULL || pw_buf == NULL) {
		return NULL;
	}

	pdb_init_smb(pw_buf);

	pw_buf->acct_ctrl = ACB_NORMAL;  

	/*
	 * Scan the file, a line at a time and check if the name matches.
	 */
	while (!feof(fp)) {
		linebuf[0] = '\0';
		fgets(linebuf, 256, fp);
		if (ferror(fp)) {
		  return NULL;
		}

		/*
		 * Check if the string is terminated with a newline - if not
		 * then we must keep reading and discard until we get one.
		 */
		if ((linebuf_len = strlen(linebuf)) == 0)
			continue;

		if (linebuf[linebuf_len - 1] != '\n') {
		  c = '\0';
		  while (!ferror(fp) && !feof(fp)) {
		    c = fgetc(fp);
		    if (c == '\n')
		      break;
		  }
		} else
		  linebuf[linebuf_len - 1] = '\0';

		if ((linebuf[0] == 0) && feof(fp)) {
		  break;
		}
		/*
		 * The line we have should be of the form :-
		 * 
		 * username:uid:32hex bytes:[Account type]:LCT-12345678....other flags presently
		 * ignored....
		 * 
		 * or,
		 *
		 * username:uid:32hex bytes:32hex bytes:[Account type]:LCT-12345678....ignored....
		 *
		 * if Windows NT compatible passwords are also present.
		 * [Account type] is an ascii encoding of the type of account.
		 * LCT-(8 hex digits) is the time_t value of the last change time.
		 */

		if (linebuf[0] == '#' || linebuf[0] == '\0') {
		  continue;
		}
		p = strchr(linebuf, ':');
		if (p == NULL) {
		  continue;
		}
		/*
		 * As 256 is shorter than a pstring we don't need to check
		 * length here - if this ever changes....
		 */
		strncpy(user_name, linebuf, p - linebuf);
		user_name[p - linebuf] = '\0';

		/* Get smb uid. */

		p++;		/* Go past ':' */

		if(*p == '-') {
		  continue;
		}

		if (!isdigit(*p)) {
		  continue;
		}

		uidval = atoi(p);

		while (*p && isdigit(*p))
		  p++;

		if (*p != ':') {
		  continue;
		}

		setsmbname(pw_buf,user_name);
		pw_buf->smb_userid = uidval;

		/*
		 * Now get the password value - this should be 32 hex digits
		 * which are the ascii representations of a 16 byte string.
		 * Get two at a time and put them into the password.
		 */

		/* Skip the ':' */
		p++;

		if (*p == '*' || *p == 'X') {
		  /* Password deliberately invalid - end here. */
		  pw_buf->smb_nt_passwd = NULL;
		  pw_buf->smb_passwd = NULL;
		  pw_buf->acct_ctrl |= ACB_DISABLED;
		  return pw_buf;
		}

		if (linebuf_len < ((p - linebuf) + 33)) {
		  continue;
		}

		if (p[32] != ':') {
		  continue;
		}

		if (!strncasecmp((char *) p, "NO PASSWORD", 11)) {
		  pw_buf->smb_passwd = NULL;
		  pw_buf->acct_ctrl |= ACB_PWNOTREQ;
		} else {
		  if (hex2bin((char *)p, pw_buf->smb_passwd_value, 16) != 16) {
		    continue;
		  }
		  pw_buf->smb_passwd = pw_buf->smb_passwd_value;
		}

		/* 
		 * Now check if the NT compatible password is
		 * available.
		 */
		pw_buf->smb_nt_passwd = NULL;

		p += 33; /* Move to the first character of the line after
		            the lanman password. */
		if ((linebuf_len >= ((p - linebuf) + 33)) && (p[32] == ':')) {
		  if (*p != '*' && *p != 'X') {
		    if(hex2bin((char *)p, pw_buf->smb_nt_passwd_value, 16)==16)
		      pw_buf->smb_nt_passwd = pw_buf->smb_nt_passwd_value;
		  }
		  p += 33; /* Move to the first character of the line after
		              the NT password. */
		}

		if (*p == '[') {
	
		  unsigned char *end_p = (unsigned char *)strchr((char *)p, ']');
		  pw_buf->acct_ctrl = pdb_decode_acct_ctrl((char*)p);
		   /* Must have some account type set. */
		  if(pw_buf->acct_ctrl == 0)
		    pw_buf->acct_ctrl = ACB_NORMAL;

		  /* Now try and get the last change time. */
		  if(end_p)
		    p = end_p + 1;
		  if(*p == ':') {
		    p++;
		    if(*p && (strncasecmp(p, "LCT-", 4)==0)) {
		      int i;
		      p += 4;
		      for(i = 0; i < 8; i++) {
		        if(p[i] == '\0' || !isxdigit(p[i]))
		          break;
		      }
		      if(i == 8) {
		        /*
		         * p points at 8 characters of hex digits - 
		         * read into a time_t as the seconds since
		         * 1970 that the password was last changed.
		         */
		        pw_buf->pass_last_set_time = (time_t)strtol((char *)p, NULL, 16);
		      }
		    }
		  }
		} else {
		  /* 'Old' style file. Fake up based on user name. */
		  /*
		   * Currently trust accounts are kept in the same
		   * password file as 'normal accounts'. If this changes
		   * we will have to fix this code. JRA.
		   */
		  if(pw_buf->smb_name[strlen(pw_buf->smb_name) - 1] == '$') {
		    pw_buf->acct_ctrl &= ~ACB_NORMAL;
		    pw_buf->acct_ctrl |= ACB_WSTRUST;
		  }
		}

		return pw_buf;
	}
	return NULL;
}

struct smb_passwd *getsmbfilepwname(struct smb_passwd *pw_buf,const char *fname, const char *name)
{
	FILE *file;

	if(!pw_buf)return NULL;
	file = fopen(fname, "ro");
	if (file == NULL) return NULL;
	while ( getsmbfilepwent(pw_buf, file) && strcmp(pw_buf->smb_name, name))
		/* skip entries */;
	fclose(file);
	return pw_buf;
}

void setsmbname(struct smb_passwd *pw_buf,const char *name)
{
	strncpy((char*)pw_buf->smb_name_value,name,255);
	pw_buf->smb_name_value[255] = '\0';
	pw_buf->smb_name = pw_buf->smb_name_value;
}
