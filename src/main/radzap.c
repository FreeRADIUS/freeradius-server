/*
 * radzap.c	Zap a user from the radutmp and radwtmp file.
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

#include "autoconf.h"
#include "libradius.h"

#include <sys/file.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#if HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#include "radiusd.h"
#include "radutmp.h"
#include "conffile.h"

const char *progname;
const char *radlog_dir = NULL;
const char *radius_dir = NULL;
const char *radacct_dir = NULL;
const char *radlib_dir = NULL;
radlog_dest_t radlog_dest = RADLOG_FILES;
int debug_flag = 0;
int auth_port = 0;
int acct_port;
int log_stripped_names;
struct main_config_t mainconfig;
uint32_t radiusip = INADDR_NONE;
static void usage(void);

struct radutmp_config_t {
  char *radutmp_fn;
} radutmpconfig;

static CONF_PARSER module_config[] = {
  { "filename", PW_TYPE_STRING_PTR, 0, &radutmpconfig.radutmp_fn,  RADUTMP },
  { NULL, -1, 0, NULL, NULL }
};

#define LOCK_LEN sizeof(struct radutmp)

static int radutmp_lookup(struct radutmp *u, uint32_t nasaddr,
		uint32_t port, const char *user)
{
	int fd;

	if ((fd = open(radutmpconfig.radutmp_fn, O_RDONLY|O_CREAT, 0644)) >= 0) {
		/*
		 *	Lock the utmp file.
		 */
		rad_lockfd(fd, LOCK_LEN);

		/*
		 *	Find the entry for this NAS / portno combination.
		 */
		while (read(fd, u, sizeof(*u)) == sizeof(*u)) {
			if ((nasaddr != 0 && nasaddr != u->nas_address) ||
					(port != u->nas_port) ||
					(user != NULL &&
					strncmp(u->login, user, sizeof u->login) != 0) ||
					u->type != P_LOGIN)
				continue;
			/*
			 *	Match. Zap it.
			 */
			close(fd);
			return 1;
		}
		close(fd);
	}
	return 0;
}
static int do_accton_packet(uint32_t nasaddr);
static int do_stop_packet(const struct radutmp *u);

/*
 *  Display the syntax for starting this program.
 */
static void usage(void)
{
        fprintf(stderr,
                        "Usage: %s [-d raddb] [-p acct_port] [-r servername|serverip] termserver [port] [user]\n", progname);
        fprintf(stderr, "Options:\n\n");
	fprintf(stderr, "  -d raddb        Set the raddb directory (default is %s)\n", RADIUS_DIR);
        fprintf(stderr, "  -p acct_port    Accounting port on radius server\n");
        fprintf(stderr, "  -r radserver    Radius server name or IP address\n");
        fprintf(stderr, "  termserver      Terminal Server (NAS) name or IP address to match, can be '' for any\n");
        fprintf(stderr, "  [port]          Terminal Server port to match\n");
        fprintf(stderr, "  [user]          Login account to match\n");
        exit(1);
}                


/*
 *	Zap a user from the radutmp and radwtmp file.
 */
int main(int argc, char **argv)
{
	CONF_SECTION *cs;
	NAS *nas;
	uint32_t ip = 0;
	uint32_t nas_port = ~0;
	char *user = NULL;
	char *s;
	char buf[256];
	struct radutmp u;
	int argval;

	progname = argv[0];

	radius_dir = strdup(RADIUS_DIR);

        /*  Process the options.  */
        while ((argval = getopt(argc, argv, "d:p:r:")) != EOF) {
                                
                switch(argval) {
                        
			case 'd':
				if (radius_dir) free(radius_dir);
				radius_dir = strdup(optarg);
				break;
                        case 'p':
				acct_port = atoi(optarg);
                                break;
                                 
                        case 'r':
                                if ((radiusip = ip_getaddr(optarg)) == INADDR_NONE) {
                                        fprintf(stderr, "%s: %s: radius server unknown\n",
                                                progname, optarg);
                                        exit(1);
				}
                                break;
                               
                        default:
                                usage();
                                exit(1);
                }
        }


	if (argc == optind) {	/* no terminal server specified */
		usage();
                exit(1);
	}

	if (argc > optind + 1) {	/* NAS port given */
		s = argv[optind+1];
		if (*s == 's' || *s == 'S') s++;
		nas_port = strtoul(s, NULL, 10);
	}

	if (argc > optind + 2) {	/* username (login) given */
		user = argv[optind+2];
	}

	/*
	 *	Find the IP address of the terminal server.
	 */
	if ((nas = nas_findbyname(argv[optind])) == NULL && argv[optind][0] != 0) {
		if ((ip = ip_getaddr(argv[optind])) == INADDR_NONE) {
			fprintf(stderr, "%s: host not found.\n", argv[optind]);
			exit(1);
		}
	}
	if (nas != NULL) 
		ip = nas->ipaddr;

	/*
	 *	Ensure that the configuration is initialized.
	 */
	memset(&mainconfig, 0, sizeof(mainconfig));

        /* Read radiusd.conf */
	if (read_mainconfig(0) < 0) {
		fprintf(stderr, "%s: Error reading radiusd.conf.\n", argv[0]);
		exit(1);
	}

        /* Read the radutmp section of radiusd.conf */
        cs = cf_section_sub_find(cf_section_find("modules"), "radutmp");
        if(!cs) {
                fprintf(stderr, "%s: No configuration information in radutmp section of radiusd.conf!\n",
                        argv[0]);
                exit(1);
        }

        cf_section_parse(cs, NULL, module_config);

	printf("%s: zapping termserver %s, port %u",
		progname, ip_hostname(buf, sizeof(buf), ip), nas_port);
	if (user != NULL) 
		printf(", user %s", user);
	printf("\n");

	if (nas_port == ~0) {
		return do_accton_packet(ip);
	}

	if (!radutmp_lookup(&u, ip, nas_port, user)) {
		fprintf(stderr, "Entry not found\n");
		return 1;
	}

	return do_stop_packet(&u);
}

static int getport(const char *name)
{
	struct servent *svp;

	svp = getservbyname(name, "udp");
	if (svp == NULL) {
		return 0;
	}

	return ntohs(svp->s_port);
}

static const char *getsecret(uint32_t server)
{
	RADCLIENT *cl;

	cl = client_find(server);
	if (cl == NULL) {
		char buf[32];
		radlog(L_ERR|L_CONS, "No clients entry for %s",
		       ip_ntoa(buf,server));
		exit(1);
	}
	return (const char *)cl->secret;
}

/* Packet-fabrication macros. Don't stare directly at them without protective
 * eye gear */
#define PAIR(n,v,t,e) do { \
  if(!(vp=paircreate(n, t))) { \
    radlog(L_ERR|L_CONS, "no memory"); \
    pairfree(&req->vps); \
    return 1; \
  } \
  vp->e=v; \
  pairadd(&req->vps, vp); \
} while(0)
#define INTPAIR(n,v) PAIR(n,v,PW_TYPE_INTEGER,lvalue)
#define IPPAIR(n,v) PAIR(n,v,PW_TYPE_IPADDR,lvalue)
#define STRINGPAIR(n,v) do { \
  if(!(vp=paircreate(n, PW_TYPE_STRING))) { \
    radlog(L_ERR|L_CONS, "no memory"); \
    pairfree(&req->vps); \
    return 1; \
  } \
  strNcpy((char *)vp->strvalue, v, sizeof vp->strvalue); \
  vp->length=strlen(v); \
  pairadd(&req->vps, vp); \
} while(0)

static int do_packet(int allports, uint32_t nasaddr, const struct radutmp *u)
{
	int i, retries=5, timeout=3;
	struct timeval tv;
	RADIUS_PACKET *req, *rep = NULL;
	VALUE_PAIR *vp;
	const char *secret;

	if ((req = rad_alloc(1)) == NULL) {
		librad_perror("radzap");
		exit(1);
	}
	req->id = getpid() & 0xFF;
	req->code = PW_ACCOUNTING_REQUEST;
	req->dst_port = acct_port;
	if(req->dst_port == 0) 
		req->dst_port = getport("radacct");
	if(req->dst_port == 0) 
		req->dst_port = PW_ACCT_UDP_PORT;
	if (radiusip == INADDR_NONE) {
		req->dst_ipaddr = ip_getaddr("localhost");
	}
	else {
		req->dst_ipaddr = radiusip;
	}
	if(!req->dst_ipaddr) 
		req->dst_ipaddr = 0x7f000001;
	req->vps = NULL;
	secret = getsecret(req->dst_ipaddr);

	if(allports != 0) {
		INTPAIR(PW_ACCT_STATUS_TYPE, PW_STATUS_ACCOUNTING_OFF);
		IPPAIR(PW_NAS_IP_ADDRESS, nasaddr);
		INTPAIR(PW_ACCT_DELAY_TIME, 0);
	} else {
		char login[sizeof u->login+1];
		char session_id[sizeof u->session_id+1];
		strNcpy(login, u->login, sizeof login);
		strNcpy(session_id, u->session_id, sizeof session_id);
		INTPAIR(PW_ACCT_STATUS_TYPE, PW_STATUS_STOP);
		IPPAIR(PW_NAS_IP_ADDRESS, u->nas_address);
		INTPAIR(PW_ACCT_DELAY_TIME, 0);
		STRINGPAIR(PW_USER_NAME, login);
		INTPAIR(PW_NAS_PORT, u->nas_port);
		STRINGPAIR(PW_ACCT_SESSION_ID, session_id);
		if(u->proto=='P') {
			INTPAIR(PW_SERVICE_TYPE, PW_FRAMED_USER);
			INTPAIR(PW_FRAMED_PROTOCOL, PW_PPP);
		} else if(u->proto=='S') {
			INTPAIR(PW_SERVICE_TYPE, PW_FRAMED_USER);
			INTPAIR(PW_FRAMED_PROTOCOL, PW_SLIP);
		} else {
			INTPAIR(PW_SERVICE_TYPE, PW_LOGIN_USER); /* A guess, really */
		}
		IPPAIR(PW_FRAMED_IP_ADDRESS, u->framed_address);
		INTPAIR(PW_ACCT_SESSION_TIME, 0);
		INTPAIR(PW_ACCT_INPUT_OCTETS, 0);
		INTPAIR(PW_ACCT_OUTPUT_OCTETS, 0);
		INTPAIR(PW_ACCT_INPUT_PACKETS, 0);
		INTPAIR(PW_ACCT_OUTPUT_PACKETS, 0);
	}
	if ((req->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("radzap: socket: ");
		exit(1);
	}

	for (i = 0; i < retries; i++) {
		fd_set rdfdesc;

		rad_send(req, NULL, secret);

		/* And wait for reply, timing out as necessary */
		FD_ZERO(&rdfdesc);
		FD_SET(req->sockfd, &rdfdesc);

		tv.tv_sec = (int)timeout;
		tv.tv_usec = 1000000 * (timeout - (int)timeout);

		/* Something's wrong if we don't get exactly one fd. */
		if (select(req->sockfd + 1, &rdfdesc, NULL, NULL, &tv) != 1) {
			continue;
		}

		rep = rad_recv(req->sockfd);
		if (rep != NULL) {
			break;
		} else {	/* NULL: couldn't receive the packet */
			librad_perror("radzap:");
			exit(1);
		}
	}

	/* No response or no data read (?) */
	if (i == retries) {
		fprintf(stderr, "%s: no response from server\n", progname);
		exit(1);
	}

	if (rad_decode(rep, req, secret) != 0) {
		librad_perror("rad_decode");
		exit(1);
	}

	vp_printlist(stdout, rep->vps);
	return 0;
}

static int do_accton_packet(uint32_t nasaddr)
{
	return do_packet(1, nasaddr, 0);
}

static int do_stop_packet(const struct radutmp *u)
{
	return do_packet(0, 0, u);
}
