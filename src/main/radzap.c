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

#include	"autoconf.h"
#include	"libradius.h"

#include	<sys/file.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<fcntl.h>
#include	<netdb.h>
#include	<limits.h>
#include	<sys/types.h>
#include	<sys/socket.h>

#if HAVE_NETINET_IN_H
#  include      <netinet/in.h>
#endif

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"
#include	"radutmp.h"

/* FIXME: Some of the following are unused and just there to make the linker
 * happy. Also all of log.o is linked in mainly to make the linker happy. */
int debug_flag = 0;
const char *progname;
const char *radlog_dir = NULL;
const char *radius_dir = NULL;
#if 0
int auth_port; /* Not really used */
#endif
int acct_port = 0;

#define LOCK_LEN sizeof(struct radutmp)

/*
 *	Internal wrapper for locking, to minimize the number of ifdef's
 *	in the source. Copied from rlm_radutmp.c (was src/main/radutmp.c),
 *	perhaps these wrappers should be #defined in radutmp.h
 *
 *	Lock the utmp file, prefer lockf() over flock()
 */
static void radutmp_lock(int fd)
{
#if defined(F_LOCK) && !defined(BSD)
	(void)lockf(fd, F_LOCK, LOCK_LEN);
#else
	(void)flock(fd, LOCK_EX);
#endif
}

/*
 *	Internal wrapper for unlocking, to minimize the number of ifdef's
 *	in the source.
 *
 *	Unlock the utmp file, prefer lockf() over flock()
 */
static void radutmp_unlock(int fd)
{
#if defined(F_LOCK) && !defined(BSD)
	(void)lockf(fd, F_ULOCK, LOCK_LEN);
#else
	(void)flock(fd, LOCK_UN);
#endif
}

static int radutmp_lookup(struct radutmp *u, uint32_t nasaddr, int port,
			  const char *user)
{
	int		fd;

	if ((fd = open(RADUTMP, O_RDONLY|O_CREAT, 0644)) >= 0) {
		/*
		 *	Lock the utmp file, prefer lockf() over flock().
		 */
		radutmp_lock(fd);

		/*
		 *	Find the entry for this NAS / portno combination.
		 */
		while (read(fd, u, sizeof(*u)) == sizeof(*u)) {
			if ((nasaddr != 0 && nasaddr != u->nas_address) ||
			      (port >= 0  && port    != u->nas_port) ||
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
 *	Zap a user from the radutmp and radwtmp file.
 */
int main(int argc, char **argv)
{
	NAS	*nas;
	uint32_t ip = 0;
	int	nas_port = -1;
	char	*user = NULL;
	char	*s;
	char	buf[256];
	struct radutmp u;

	progname = argv[0];
	--argc, ++argv;
	if (argc > 1 && !strcmp(argv[0], "-p")) {
		acct_port = atoi(argv[1]);
		argc -= 2, argv+=2;
	}
	if (argc < 1 || argc > 3 || argv[1][0] == '-') {
		fprintf(stderr, "Usage: radzap termserver [port] [user]\n");
		fprintf(stderr, "       radzap is only an admin tool to clean the radutmp file!\n");
		exit(1);
	}
	if (argc > 1) {
		s = argv[1];
		if (*s == 's' || *s == 'S') s++;
		nas_port = atoi(s);
	}
	if (argc > 2) user     = argv[2];

	radius_dir = strdup(RADIUS_DIR);

	/*
	 *	Read the "naslist" file.
	 */
	sprintf(buf, "%s/%s", RADIUS_DIR, RADIUS_NASLIST);
	if (read_naslist_file(buf) < 0)
		exit(1);

	/*
	 *	Find the IP address of the terminal server.
	 */
	if ((nas = nas_findbyname(argv[0])) == NULL && argv[0][0] != 0) {
		if ((ip = ip_getaddr(argv[0])) == INADDR_NONE) {
			fprintf(stderr, "%s: host not found.\n", argv[0]);
			exit(1);
		}
	}
	if (nas) ip = nas->ipaddr;

	printf("radzap: zapping termserver %s, port %d",
		ip_hostname(buf, sizeof(buf), ip), nas_port);
	if (user) printf(", user %s", user);
	printf("\n");

	if(nas_port < 0) {
		return do_accton_packet(ip);
	}

	if(!radutmp_lookup(&u, ip, nas_port, user)) {
		fprintf(stderr, "Entry not found\n");
		return 1;
	}

	return do_stop_packet(&u);
}

static int getport(const char *name)
{
	struct	servent		*svp;

	svp = getservbyname (name, "udp");
	if (!svp) {
		return 0;
	}

	return ntohs(svp->s_port);
}

static const char *getlocalhostsecret(void)
{
	RADCLIENT *cl;
	char fn[PATH_MAX];
	snprintf(fn, sizeof fn, "%s/%s", radius_dir, RADIUS_CLIENTS);
	if(read_clients_file(fn)<0) {
		radlog(L_ERR|L_CONS, "Errors reading clients");
		exit(1);
	}
	cl=client_find(htonl(INADDR_LOOPBACK));
	if(!cl) {
		radlog(L_ERR|L_CONS, "No clients entry for localhost");
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
	RADIUS_PACKET *req, *rep;
	VALUE_PAIR *vp;
	const char *secret=getlocalhostsecret();

	if ((req = rad_alloc(1)) == NULL) {
		librad_perror("radzap");
		exit(1);
	}
	req->id = getpid() & 0xFF;
	req->code = PW_ACCOUNTING_REQUEST;
        req->dst_port = acct_port;
	if(req->dst_port == 0) req->dst_port = getport("radacct");
	if(req->dst_port == 0) req->dst_port = PW_ACCT_UDP_PORT;
	req->dst_ipaddr = ip_getaddr("localhost");
	if(!req->dst_ipaddr) req->dst_ipaddr = 0x7f000001;
	req->vps = NULL;

	if(allports) {
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
		INTPAIR(PW_NAS_PORT_ID, u->nas_port);
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
		fd_set		rdfdesc;

		rad_send(req, secret);

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
		fprintf(stderr, "radzap: no response from server\n");
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

#if 0
/* FIXME: Not called. Needed for files.o to link. Ick */
int setup_modules(void); /* -Wmissing-prototypes */
int setup_modules(void)
{
  abort();
}

/* FIXME: Not called. Needed for files.o to link. Ick */
int read_radius_conf_file(void); /* -Wmissing-prototypes */
int read_radius_conf_file(void)
{
  abort();
}
#endif
