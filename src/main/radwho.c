/*
 * radwho.c	Show who is logged in on the terminal servers.
 *		Can also be installed as fingerd on the UNIX
 *		machine RADIUS runs on.
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
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

static const char rcsid[] =
"$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <ctype.h>

#include "sysutmp.h"
#include "radutmp.h"
#include "radiusd.h"
#include "conffile.h"

/*
 *	FIXME: put in header file.
 */
#define SYS_FINGER "/usr/bin/finger"
#define FINGER_DIR "/usr/local/lib/finger"

/*
 *	Header above output and format.
 */
static const char *hdr1 = 
"Login      Name              What  TTY  When      From      Location";
static const char *ufmt1 = "%-10.10s %-17.17s %-5.5s %-4.4s %-9.9s %-9.9s %-.16s%s";
static const char *ufmt1r = "%s,%s,%s,%s,%s,%s,%s%s";
static const char *rfmt1 = "%-10.10s %-17.17s %-5.5s %s%-3d %-9.9s %-9.9s %-.19s%s";
static const char *rfmt1r = "%s,%s,%s,%s%d,%s,%s,%s%s";

static const char *hdr2 = 
"Login      Port    What      When          From       Location";
static const char *ufmt2 = "%-10.10s %-6.6d %-7.7s %-13.13s %-10.10s %-.16s%s";
static const char *ufmt2r = "%s,%d,%s,%s,%s,%s%s";
static const char *rfmt2 = "%-10.10s %s%-5d  %-6.6s %-13.13s %-10.10s %-.28s%s";
static const char *rfmt2r = "%s,%s%d,%s,%s,%s,%s%s";

static const char *eol = "\n";
static int showname = -1;
static int showptype = 0;
static int showcid = 0;
int debug_flag = 0;
const char *progname = "radwho";
const char *radlog_dir = "stdout";

static int              max_request_time = MAX_REQUEST_TIME;
static int              cleanup_delay = CLEANUP_DELAY;
static int              max_requests = MAX_REQUESTS;
static int              allow_core_dumps = FALSE;
static const char       *pid_file = NULL;
static const char       *uid_name = NULL;
static const char       *gid_name = NULL;
static int              proxy_requests = TRUE;
int                     proxy_synchronous = TRUE;
const char              *radius_dir = NULL;
const char              *radacct_dir = NULL;
const char              *radlib_dir = NULL;
int                     auth_port = 0;
int                     acct_port;
uint32_t                myip = INADDR_ANY;
int                     proxy_retry_delay = RETRY_DELAY;
int                     proxy_retry_count = RETRY_COUNT;
int                     log_stripped_names;
struct  main_config_t   mainconfig;


static CONF_PARSER proxy_config[] = {
  { "retry_delay",  PW_TYPE_INTEGER,
    &proxy_retry_delay, Stringify(RETRY_DELAY) },
  { "retry_count",  PW_TYPE_INTEGER,
    &proxy_retry_count, Stringify(RETRY_COUNT) },
  { "synchronous",  PW_TYPE_BOOLEAN, &proxy_synchronous, "yes" },

  { NULL, -1, NULL, NULL }
};

/*
 *	A mapping of configuration file names to internal variables
 */
static CONF_PARSER server_config[] = {
  { "max_request_time",   PW_TYPE_INTEGER,
    &max_request_time,    Stringify(MAX_REQUEST_TIME) },
  { "cleanup_delay",      PW_TYPE_INTEGER,
    &cleanup_delay,       Stringify(CLEANUP_DELAY) },
  { "max_requests",       PW_TYPE_INTEGER,
    &max_requests,        Stringify(MAX_REQUESTS) },
  { "port",               PW_TYPE_INTEGER,
    &auth_port,           Stringify(PW_AUTH_UDP_PORT) },
  { "allow_core_dumps",   PW_TYPE_BOOLEAN,    &allow_core_dumps,  "no" },
  { "log_stripped_names", PW_TYPE_BOOLEAN,    &log_stripped_names,"no" },
  { "log_auth",           PW_TYPE_BOOLEAN,    &mainconfig.log_auth,   "no" },
  { "log_auth_badpass",   PW_TYPE_BOOLEAN,    &mainconfig.log_auth_badpass,  "no" },
  { "log_auth_goodpass",  PW_TYPE_BOOLEAN,    &mainconfig.log_auth_goodpass, "no" },
  { "pidfile",            PW_TYPE_STRING_PTR, &pid_file,          "${run_dir}/radiusd.pid"},
  { "bind_address",       PW_TYPE_IPADDR,     &myip,              "*" },
  { "user",           PW_TYPE_STRING_PTR, &uid_name,  "nobody"},
  { "group",          PW_TYPE_STRING_PTR, &gid_name,  "nobody"},
  { "usercollide",   PW_TYPE_BOOLEAN,    &mainconfig.do_usercollide,  "no" },
  { "lower_user",     PW_TYPE_STRING_PTR,    &mainconfig.do_lower_user, "no" },
  { "lower_pass",     PW_TYPE_STRING_PTR,    &mainconfig.do_lower_pass, "no" },
  { "nospace_user",   PW_TYPE_STRING_PTR,    &mainconfig.do_nospace_user, "no" },
  { "nospace_pass",   PW_TYPE_STRING_PTR,    &mainconfig.do_nospace_pass, "no" },

  { "proxy_requests", PW_TYPE_BOOLEAN,    &proxy_requests,    "yes" },
  { "proxy",          PW_TYPE_SUBSECTION, proxy_config,       NULL },
  { NULL, -1, NULL, NULL }
};



/*
 *	Safe popen. Ugh.
 */
static FILE *safe_popen(const char *cmd, const char *mode)
{
	char		*p;
	char		buf[1024];

	/*
	 *	Change all suspect characters into a space.
	 */
	strncpy(buf, cmd, sizeof(buf));
	buf[sizeof(buf) - 1] = 0;
	for (p = buf; *p; p++) {
		if (isalnum(*p))
			continue;
		if (strchr("@%-_ \t+:,./", *p) == NULL)
			*p = ' ';
	}

	return popen(buf, mode);
}

/*
 *	Print a file from FINGER_DIR. If the file is executable,
 *	execute it instead. Return 0 if succesfull.
 */
static int ffile(const char *arg)
{
	FILE *fp;
	char fn[1024];
	int p = 0;
	char *s;

	sprintf(fn, "%s/%.32s", FINGER_DIR, arg);
	if (access(fn, X_OK) == 0) {
		p = 1;
		sprintf(fn, "exec %s/%.32s 2>&1", FINGER_DIR, arg);
		fp = safe_popen(fn, "r");
	} else fp = fopen(fn, "r");

	if (fp == NULL) return -1;

	while(fgets(fn, 1024, fp)) {
		if ((s = strchr(fn, '\n')) != NULL)
			*s = 0;
		fprintf(stdout, "%s\r\n", fn);
	}
	if (p)
		pclose(fp);
	else
		fclose(fp);
	fflush(stdout);
	return 0;
}


/*
 *	Execute the system finger and translate LF to CRLF.
 */
static void sys_finger(const char *l)
{
	FILE *fp;
	char fn[1024];
	char *p;

	if (ffile(l) == 0)
		exit(0);

	sprintf(fn, "exec %s %s", SYS_FINGER, l);
	if ((fp = safe_popen(fn, "r")) == NULL) {
		printf("popen: %s\r\n", strerror(errno));
		exit(1);
	}

	while(fgets(fn, 1024, fp)) {
		if ((p = strchr(fn, '\n')) != NULL)
			*p = 0;
		fprintf(stdout, "%s\r\n", fn);
	}
	pclose(fp);
	exit(0);
}


/*
 *	Get fullname of a user.
 */
static char *fullname(char *username)
{
	struct passwd *pwd;
	char *s;

	if ((pwd = getpwnam(username)) != NULL) {
		if ((s = strchr(pwd->pw_gecos, ',')) != NULL) *s = 0;
		return pwd->pw_gecos;
	}
	return username;
}

/*
 *	Return protocol type.
 */
static const char *proto(int id, int porttype)
{
	static char buf[8];

	if (showptype) {
		if (!strchr("ASITX", porttype))
			porttype = ' ';
		if (id == 'S')
			sprintf(buf, "SLP %c", porttype);
		else if (id == 'P')
			sprintf(buf, "PPP %c", porttype);
		else
			sprintf(buf, "shl %c", porttype);
		return buf;
	}
	if (id == 'S') return "SLIP";
	if (id == 'P') return "PPP";
	return "shell";
}

/*
 *	Return a time in the form day hh:mm
 */
static char *dotime(time_t t)
{
	char *s = ctime(&t);

	if (showname) {
		strncpy(s + 4, s + 11, 5);
		s[9] = 0;
	} else {
		strncpy(s + 4, s + 8, 8);
		s[12] = 0;
	}

	return s;
}

#if 0 /*UNUSED*/
/*
 *	See how long a tty has been idle.
 */
char *idletime(char *line)
{
	char tty[16];
	static char tmp[8];
	time_t t;
	struct stat st;
	int hr, min, days;

	if (line[0] == '/')
		strcpy(tty, "/dev/");
	else
		tty[0] = 0;
	strncat(tty, line, 10);
	tty[15] = 0;

	tmp[0] = 0;
	if (stat(tty, &st) == 0) {
		time(&t);
		t -= st.st_mtime;
		if (t >= 60) {
			min = (t / 60);
			hr = min / 24;
			days = hr / 24;
			min %= 60;
			hr %= 24;
			if (days > 0)
				sprintf(tmp, "%dd", days);
			else
				sprintf(tmp, "%2d:%02d", hr, min);
		}
	}
	return tmp;
}
#endif

/*
 *	Shorten tty name.
 */
static const char *ttyshort(char *tty)
{
	static char tmp[16];

	if (tty[0] == '/') tty += 5;

	if (strncmp(tty, "tty", 3) == 0) {
		if (tty[3] >= '0' && tty[3] <= '9')
			sprintf(tmp, "v%.14s", tty + 3);
		else
			sprintf(tmp, "%.15s", tty + 3);
		return tmp;
	}
	if (strncmp(tty, "vc", 2) == 0) {
		sprintf(tmp, "v.14%s", tty + 2);
		return tmp;
	}
	if (strncmp(tty, "cu", 2) == 0) {
		return tmp + 2;
	}
	return "??";
}


/*
 *	Print address of NAS.
 */
static const char *hostname(char *buf, size_t buflen, uint32_t ipaddr)
{
	if (ipaddr == 0 || ipaddr == (uint32_t)-1 || ipaddr == (uint32_t)-2)
		return "";
	return ip_hostname(buf, buflen, ipaddr);
}


/*
 *	Print usage message and exit.
 */
static void usage(void)
{
	fprintf(stderr, "Usage: radwho [-lhfnsipcr]\n");
	fprintf(stderr, "       -l: show local (shell) users too\n");
	fprintf(stderr, "       -h: hide shell users from radius\n");
	fprintf(stderr, "       -f: give fingerd output\n");
	fprintf(stderr, "       -n: no full name\n");
	fprintf(stderr, "       -s: show full name\n");
	fprintf(stderr, "       -i: show session ID\n");
	fprintf(stderr, "       -p: show port type\n");
	fprintf(stderr, "       -c: show caller ID, if available\n");
	fprintf(stderr, "       -r: output as raw data\n");
	exit(1);
}


/*
 *	Main program, either pmwho or fingerd.
 */
int main(int argc, char **argv)
{
	CONF_SECTION *cs;
	FILE *fp;
	struct radutmp rt;
	struct utmp ut;
	int hdrdone = 0;
	char inbuf[128];
	char myname[128];
	char othername[256];
	char session_id[16];
	int fingerd = 0;
	int showlocal = 0;
	int hideshell = 0;
	int showsid = 0;
	int rawoutput = 0;
	char *p, *q;
	const char *portind;
	int c, portno;

	radius_dir = strdup(RADIUS_DIR);

	while((c = getopt(argc, argv, "flhnsipcr")) != EOF) switch(c) {
		case 'f':
			fingerd++;
			showname = 0;
			break;
		case 'l':
			showlocal = 1;
			break;
		case 'h':
			hideshell = 1;
			break;
		case 'n':
			showname = 0;
			break;
		case 's':
			showname = 1;
			break;
		case 'i':
			showsid = 1;
			break;
		case 'p':
			showptype = 1;
			break;
		case 'c':
			showcid = 1;
			showname = 1;
			break;
		case 'r':
			rawoutput = 1;
			break;
		default:
			usage();
			break;
	}

	/* Read radiusd.conf */
	if(read_radius_conf_file() < 0) {
		printf("Errors reading radiusd.conf\n");
		exit(1);
	}

	cs = cf_section_find(NULL);
	if(!cs) {
		printf("No configuration information in radiusd.conf!\n");
		exit(1);
	}
	cf_section_parse(cs, server_config);


	/*
	 *	See if we are "fingerd".
	 */
	if (strstr(argv[0], "fingerd")) {
		fingerd++;
		eol = "\r\n";
		if (showname < 0) showname = 0;
	}
	if (showname < 0) showname = 1;

	if (fingerd) {
		/*
		 *	Read first line of the input.
		 */
		fgets(inbuf, 128, stdin);
		p = inbuf;
		while(*p == ' ' || *p == '\t') p++;
		if (*p == '/' && *(p + 1)) p += 2;
		while(*p == ' ' || *p == '\t') p++;
		for(q = p; *q && *q != '\r' && *q != '\n'; q++)
			;
		*q = 0;

		/*
		 *	See if we fingered a specific user.
		 */
		ffile("header");
		if (*p) sys_finger(p);
	}

	if (showlocal && (fp = fopen(UTMP_FILE, "r"))) {
		if (rawoutput == 0)
		{	
			fputs(showname ? hdr1 : hdr2, stdout);
			fputs(eol, stdout);
		}
		hdrdone = 1;

		/*
		 *	Show the logged in UNIX users.
		 */
		gethostname(myname, 128);
		while(fread(&ut, sizeof(ut), 1, fp) == 1) {
#ifdef USER_PROCESS
			if (ut.ut_user[0] && ut.ut_line[0] &&
				ut.ut_type == USER_PROCESS) {
#else
			if (ut.ut_user[0] && ut.ut_line[0]) {
#endif
#ifdef UT_HOSTSIZE
			   if (showname)
				printf((rawoutput == 0? ufmt1: ufmt1r),
					ut.ut_name,
					fullname(ut.ut_name),
					"shell",
					ttyshort(ut.ut_line),
#ifdef HAVE_UTMPX_H
					dotime(ut.ut_xtime),
#else
					dotime(ut.ut_time),
#endif
					ut.ut_host,
					myname, eol);
			    else
				printf((rawoutput==0? ufmt2:ufmt2r),
					ut.ut_name,
					ttyshort(ut.ut_line),
					"shell",
#ifdef HAVE_UTMPX_H
					dotime(ut.ut_xtime),
#else
					dotime(ut.ut_time),
#endif
					ut.ut_host,
					myname, eol);
#endif
			}
		}
		fclose(fp);
	}

	/*
	 *	Show the users logged in on the terminal server(s).
	 */
	if ((fp = fopen(RADUTMP, "r")) == NULL)
		return 0;

	if (!hdrdone) {
		fputs(showname ? hdr1 : hdr2, stdout);
		fputs(eol, stdout);
	}

	while(fread(&rt, sizeof(rt), 1, fp) == 1) {
		if (rt.type == P_LOGIN) {
			/*
			 *	We don't show shell users if we are
			 *	fingerd, as we have done that above.
			 */
			if (hideshell && !strchr("PCS", rt.proto))
				continue;

			sprintf(session_id, "%.8s", rt.session_id);

			if (!rawoutput && rt.nas_port > (showname ? 999 : 99999)) {
				portind = ">";
				portno = (showname ? 999 : 99999);
			} else {
				portind = "S";
				portno = rt.nas_port;
			}
			if (showname)
			    printf((rawoutput == 0? rfmt1: rfmt1r),
				rt.login,
				showcid ? rt.caller_id :
				(showsid? session_id : fullname(rt.login)),
				proto(rt.proto, rt.porttype),
				portind, portno,
				dotime(rt.time),
				nas_name(rt.nas_address),
				hostname(othername, sizeof(othername), rt.framed_address), eol);
			else
			    printf((rawoutput == 0? rfmt2: rfmt2r),
				rt.login,
				portind, portno,
				proto(rt.proto, rt.porttype),
				dotime(rt.time),
				nas_name(rt.nas_address),
				hostname(othername, sizeof(othername), rt.framed_address), eol);
		}
	}
	fflush(stdout);
	fflush(stderr);
	fclose(fp);

	return 0;
}

