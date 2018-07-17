/*@-skipposixheaders@*/
/*
 * radwho.c	Show who is logged in on the terminal servers.
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/radutmp.h>
#include <freeradius-devel/server/sysutmp.h>

#include <pwd.h>
#include <sys/stat.h>
#include <ctype.h>

/*
 *	Header above output and format.
 */
static char const *hdr1 =
"Login      Name	      What  TTY  When      From	    Location";

static char const *hdr2 =
"Login      Port    What      When	  From	    Location";

static char const *eol = "\n";
static int showname = -1;
static int showptype = 0;
static int showcid = 0;
static char const *progname = "radwho";

static char const *radutmp_file = NULL;

static struct radutmp_config_t {
	char const *radutmp_fn;
} radutmpconfig;

static const CONF_PARSER module_config[] = {
  { FR_CONF_POINTER("filename", FR_TYPE_FILE_INPUT, &radutmpconfig.radutmp_fn), .dflt = RADUTMP },
  CONF_PARSER_TERMINATOR
};

/*
 *	Get fullname of a user.
 */
static char *fullname(char *username)
{
#ifdef HAVE_PWD_H
	struct passwd *pwd;
	char *s;

	if ((pwd = getpwnam(username)) != NULL) {
		if ((s = strchr(pwd->pw_gecos, ',')) != NULL) *s = 0;
		return pwd->pw_gecos;
	}
#endif

	return username;
}

/*
 *	Return protocol type.
 */
static char const *proto(int id, int porttype)
{
	static char buf[8];

	if (showptype) {
		if (!strchr("ASITX", porttype))
			porttype = ' ';
		if (id == 'S')
			snprintf(buf, sizeof(buf), "SLP %c", porttype);
		else if (id == 'P')
			snprintf(buf, sizeof(buf), "PPP %c", porttype);
		else
			snprintf(buf, sizeof(buf), "shl %c", porttype);
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
		strlcpy(s + 4, s + 11, 6);
		s[9] = 0;
	} else {
		strlcpy(s + 4, s + 8, 9);
		s[12] = 0;
	}

	return s;
}


/*
 *	Print address of NAS.
 */
static char const *hostname(char *buf, size_t buflen, uint32_t ipaddr)
{
	/*
	 *	WTF is this code for?
	 */
	if (ipaddr == 0 || ipaddr == (uint32_t)-1 || ipaddr == (uint32_t)-2)
		return "";

	return inet_ntop(AF_INET, &ipaddr, buf, buflen);

}


/*
 *	Print usage message and exit.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *output = status?stderr:stdout;

	fprintf(output, "Usage: radwho [-d raddb] [-cfihnprRsSZ] [-N nas] [-P nas_port] [-u user] [-U user]\n");
	fprintf(output, "  -c                   Show caller ID, if available.\n");
	fprintf(output, "  -d                   Set the raddb directory (default is %s).\n", RADIUS_DIR);
	fprintf(output, "  -F <file>            Use radutmp <file>.\n");
	fprintf(output, "  -i                   Show session ID.\n");
	fprintf(output, "  -n                   No full name.\n");
	fprintf(output, "  -N <nas-ip-address>  Show entries matching the given NAS IP address.\n");
	fprintf(output, "  -p                   Show port type.\n");
	fprintf(output, "  -P <port>            Show entries matching the given nas port.\n");
	fprintf(output, "  -r                   Print output as raw comma-delimited data.\n");
	fprintf(output, "  -R                   Print output as RADIUS attributes and values.\n");
	fprintf(output, "                       includes ALL information from the radutmp record.\n");
	fprintf(output, "  -s                   Show full name.\n");
	fprintf(output, "  -S                   Hide shell users from radius.\n");
	fprintf(output, "  -u <user>            Show entries matching the given user.\n");
	fprintf(output, "  -U <user>            Like -u, but case-sensitive.\n");
	fprintf(output, "  -Z                   Include accounting stop information in radius output.  Requires -R.\n");
	exit(status);
}


/*
 *	Main program
 */
int main(int argc, char **argv)
{
	CONF_SECTION		*maincs, *cs;
	FILE			*fp;
	struct			radutmp rt;
	char			othername[256];
	char			nasname[1024];
	char			session_id[sizeof(rt.session_id)+1];
	int			hideshell = 0;
	int			showsid = 0;
	int			rawoutput = 0;
	int			radiusoutput = 0;	/* Radius attributes */
	char const		*portind;
	int			c;
	unsigned int		portno;
	char			buffer[2048];
	char const		*user = NULL;
	int			user_cmp = 0;
	time_t			now = 0;
	uint32_t		nas_port = ~0;
	uint32_t		nas_ip_address = INADDR_NONE;
	int			zap = 0;
	fr_dict_t		*dict = NULL;
	TALLOC_CTX		*autofree = talloc_autofree_context();

	char const		*p;
	main_config_t		*config;


#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("%s", main_config->name);
		exit(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	/*
	 *	Allocate the main config structure.
	 *	It's allocating so we can hang talloced buffers off it.
	 */
	config = main_config_alloc(autofree);
	if (!config) {
		fr_perror("Failed allocating main config");
		exit(EXIT_FAILURE);
	}

	p = strrchr(argv[0], FR_DIR_SEP);
	if (!p) {
		main_config_name_set_default(config, argv[0], false);
	} else {
		main_config_name_set_default(config, p + 1, false);
	}

	while((c = getopt(argc, argv, "d:D:fF:nN:sSipP:crRu:U:Z")) != EOF) switch (c) {
		case 'd':
			main_config_raddb_dir_set(config, optarg);
			break;
		case 'D':
			main_config_dict_dir_set(config, optarg);
			break;
		case 'F':
			radutmp_file = optarg;
			break;
		case 'h':
			usage(0);	/* never returns */

		case 'S':
			hideshell = 1;
			break;
		case 'n':
			showname = 0;
			break;
		case 'N':
			if (inet_pton(AF_INET, optarg, &nas_ip_address) <= 0) {
				usage(1);
			}
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
		case 'P':
			nas_port = atoi(optarg);
			break;
		case 'c':
			showcid = 1;
			showname = 1;
			break;
		case 'r':
			rawoutput = 1;
			break;
		case 'R':
			radiusoutput = 1;
			now = time(NULL);
			break;
		case 'u':
			user = optarg;
			user_cmp = 0;
			break;
		case 'U':
			user = optarg;
			user_cmp = 1;
			break;
		case 'Z':
			zap = 1;
			break;

		default:
			usage(1);	/* never returns */
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("%s", main_config->name);
		return 1;
	}

	if (fr_dict_global_init(autofree, config->dict_dir) < 0) {
		fr_perror("%s", main_config->name);
		exit(EXIT_FAILURE);
	}

	if (fr_dict_from_file(&dict, FR_DICTIONARY_FILE) < 0) {
		fr_perror("%s", main_config->name);
		return 1;
	}

	if (fr_dict_read(dict, config->raddb_dir, FR_DICTIONARY_FILE) == -1) {
		fr_log_perror(&default_log, L_ERR, "Failed to initialize the dictionaries");
		return 1;
	}
	fr_strerror();	/* Clear the error buffer */

	/*
	 *	Be safe.
	 */
	if (zap && !radiusoutput) zap = 0;

	/*
	 *	zap EVERYONE, but only on this nas
	 */
	if (zap && !user && (~nas_port == 0)) {
		/*
		 *	We need to know which NAS to zap users in.
		 */
		if (nas_ip_address == INADDR_NONE) usage(1);

		printf("Acct-Status-Type = Accounting-Off\n");
		printf("NAS-IP-Address = %s\n",
		       hostname(buffer, sizeof(buffer), nas_ip_address));
		printf("Acct-Delay-Time = 0\n");
		exit(0);	/* don't bother printing anything else */
	}

	if (radutmp_file) goto have_radutmp;

	/* Read radiusd.conf */
	maincs = cf_section_alloc(NULL, NULL, "main", NULL);
	if (!maincs) exit(EXIT_FAILURE);

	snprintf(buffer, sizeof(buffer), "%.200s/radiusd.conf", config->raddb_dir);
	if ((cf_file_read(maincs, buffer) < 0) || (cf_section_pass2(maincs) < 0)) {
		fr_perror("%s: Error reading or parsing radiusd.conf\n", argv[0]);
		talloc_free(maincs);
		exit(EXIT_FAILURE);
	}

	cs = cf_section_find(maincs, "modules", NULL);
	if (!cs) {
		fr_perror("%s: No modules section found in radiusd.conf\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	/* Read the radutmp section of radiusd.conf */
	cs = cf_section_find(cs, "radutmp", NULL);
	if (!cs) {
		fr_perror("%s: No configuration information in radutmp section of radiusd.conf\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (cf_section_rules_push(cs, module_config) < 0) exit(EXIT_FAILURE);
	cf_section_parse(maincs, NULL, cs);

	/* Assign the correct path for the radutmp file */
	radutmp_file = radutmpconfig.radutmp_fn;

 have_radutmp:
	if (showname < 0) showname = 1;

	/*
	 *	Show the users logged in on the terminal server(s).
	 */
	if ((fp = fopen(radutmp_file, "r")) == NULL) {
		fr_perror("%s: Error reading %s: %s\n",
			progname, radutmp_file, fr_syserror(errno));
		return 0;
	}

	/*
	 *	Don't print the headers if raw or RADIUS
	 */
	if (!rawoutput && !radiusoutput) {
		fputs(showname ? hdr1 : hdr2, stdout);
		fputs(eol, stdout);
	}

	/*
	 *	Read the file, printing out active entries.
	 */
	while (fread(&rt, sizeof(rt), 1, fp) == 1) {
		char name[sizeof(rt.login) + 1];

		if (rt.type != P_LOGIN) continue; /* hide logout sessions */

		/*
		 *	We don't show shell users if we are
		 *	fingerd, as we have done that above.
		 */
		if (hideshell && !strchr("PCS", rt.proto))
			continue;

		/*
		 *	Print out sessions only for the given user.
		 */
		if (user) {	/* only for a particular user */
			if (((user_cmp == 0) &&
			     (strncasecmp(rt.login, user, strlen(user)) != 0)) ||
			    ((user_cmp == 1) &&
			     (strncmp(rt.login, user, strlen(user)) != 0))) {
				continue;
			}
		}

		/*
		 *	Print out only for the given NAS port.
		 */
		if (~nas_port != 0) {
			if (rt.nas_port != nas_port) continue;
		}

		/*
		 *	Print out only for the given NAS IP address
		 */
		if (nas_ip_address != INADDR_NONE) {
			if (rt.nas_address != nas_ip_address) continue;
		}

		memcpy(session_id, rt.session_id, sizeof(rt.session_id));
		session_id[sizeof(rt.session_id)] = 0;

		if (!rawoutput && rt.nas_port > (showname ? 999 : 99999)) {
			portind = ">";
			portno = (showname ? 999 : 99999);
		} else {
			portind = "S";
			portno = rt.nas_port;
		}

		/*
		 *	Print output as RADIUS attributes
		 */
		if (radiusoutput) {
			memcpy(nasname, rt.login, sizeof(rt.login));
			nasname[sizeof(rt.login)] = '\0';

			fr_snprint(buffer, sizeof(buffer), nasname, -1, '"');
			printf("User-Name = \"%s\"\n", buffer);

			fr_snprint(buffer, sizeof(buffer), session_id, -1, '"');
			printf("Acct-Session-Id = \"%s\"\n", buffer);

			if (zap) printf("Acct-Status-Type = Stop\n");

			printf("NAS-IP-Address = %s\n",
			       hostname(buffer, sizeof(buffer),
					rt.nas_address));
			printf("NAS-Port = %u\n", rt.nas_port);

			switch (rt.proto) {
			case 'S':
				printf("Service-Type = Framed-User\n");
				printf("Framed-Protocol = SLIP\n");
				break;

			case 'P':
				printf("Service-Type = Framed-User\n");
				printf("Framed-Protocol = PPP\n");
				break;

			default:
				printf("Service-type = Login-User\n");
				break;
			}
			if (rt.framed_address != INADDR_NONE) {
				printf("Framed-IP-Address = %s\n",
				       hostname(buffer, sizeof(buffer),
						rt.framed_address));
			}

			/*
			 *	Some sanity checks on the time
			 */
			if ((rt.time <= now) &&
			    (now - rt.time) <= (86400 * 365)) {
				printf("Acct-Session-Time = %" PRId64 "\n", (int64_t) (now - rt.time));
			}

			if (rt.caller_id[0] != '\0') {
				memcpy(nasname, rt.caller_id,
				       sizeof(rt.caller_id));
				nasname[sizeof(rt.caller_id)] = '\0';

				fr_snprint(buffer, sizeof(buffer), nasname, -1, '"');
				printf("Calling-Station-Id = \"%s\"\n", buffer);
			}

			printf("\n"); /* separate entries with a blank line */
			continue;
		}

		/*
		 *	Show the fill name, or not.
		 */
		memcpy(name, rt.login, sizeof(rt.login));
		name[sizeof(rt.login)] = '\0';

		if (showname) {
			if (rawoutput == 0) {
				printf("%-10.10s %-17.17s %-5.5s %s%-3u %-9.9s %-15.15s %-.19s%s",
				       name,
				       showcid ? rt.caller_id :
				       (showsid? session_id : fullname(rt.login)),
				       proto(rt.proto, rt.porttype),
				       portind, portno,
				       dotime(rt.time),
				       hostname(nasname, sizeof(nasname), rt.nas_address),
				       hostname(othername, sizeof(othername), rt.framed_address), eol);
			} else {
				printf("%s,%s,%s,%s%u,%s,%s,%s%s",
				       name,
				       showcid ? rt.caller_id :
				       (showsid? session_id : fullname(rt.login)),
				       proto(rt.proto, rt.porttype),
				       portind, portno,
				       dotime(rt.time),
				       hostname(nasname, sizeof(nasname), rt.nas_address),
				       hostname(othername, sizeof(othername), rt.framed_address), eol);
			}
		} else {
			if (rawoutput == 0) {
				printf("%-10.10s %s%-5u  %-6.6s %-13.13s %-15.15s %-.28s%s",
				       name,
				       portind, portno,
				       proto(rt.proto, rt.porttype),
				       dotime(rt.time),
				       hostname(nasname, sizeof(nasname), rt.nas_address),
				       hostname(othername, sizeof(othername), rt.framed_address),
				       eol);
			} else {
				printf("%s,%s%u,%s,%s,%s,%s%s",
				       name,
				       portind, portno,
				       proto(rt.proto, rt.porttype),
				       dotime(rt.time),
				       hostname(nasname, sizeof(nasname), rt.nas_address),
				       hostname(othername, sizeof(othername), rt.framed_address),
				       eol);
			}
		}
	}
	fclose(fp);

	main_config_free(&config);

	return 0;
}
