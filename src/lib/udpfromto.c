/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 *  Helper functions to get/set addresses of UDP packets 
 *  based on recvfromto by Miquel van Smoorenburg
 *
 * recvfromto	Like recvfrom, but also stores the destination
 *		IP address. Useful on multihomed hosts.
 *
 *		Should work on Linux and BSD.
 *
 *		Copyright (C) 2002 Miquel van Smoorenburg.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU Lesser General Public
 *		License as published by the Free Software Foundation; either
 *		version 2 of the License, or (at your option) any later version.
 *
 * sendfromto	added 18/08/2003, Jan Berkel <jan@sitadelle.com>
 *		Works on Linux and FreeBSD (5.x) 			
 * 
 * Version: $Id$
 */

#include "autoconf.h"
static const char rcsid[] = "$Id$";

#include <sys/types.h>

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "udpfromto.h"

/* Remove this when autoconf can detect this. */
#if defined(IP_RECVDSTADDR) && !defined(HAVE_IP_RECVDSTADDR)
#  define HAVE_IP_RECVDSTADDR
#endif

#if defined(IP_SENDSRCADDR) && !defined(HAVE_IP_SENDSRCADDR)
#  define HAVE_IP_SENDSRCADDR
#endif

int udpfromto_init(int s)
{
	int err = -1, opt = 1;
	errno = ENOSYS;
#ifdef HAVE_IP_PKTINFO
	/* Set the IP_PKTINFO option (Linux). */
	err = setsockopt(s, SOL_IP, IP_PKTINFO, &opt, sizeof(opt));
#endif

#ifdef HAVE_IP_RECVDSTADDR
	/*
	 * Set the IP_RECVDSTADDR option (BSD). 
	 * Note: IP_RECVDSTADDR == IP_SENDSRCADDR 
	 */
	err = setsockopt(s, IPPROTO_IP, IP_RECVDSTADDR, &opt, sizeof(opt));
#endif
	return err;
}
	
int recvfromto(int s, void *buf, size_t len, int flags,
	struct sockaddr *from, socklen_t *fromlen,
	struct sockaddr *to, socklen_t *tolen)
{
#if defined(HAVE_IP_PKTINFO) || defined(HAVE_IP_RECVDSTADDR)
	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char cbuf[256];
	int err;

	/*
	 *	If from or to are set, they must be big enough
	 *	to store a struct sockaddr_in.
	 */
	if ((from && (!fromlen || *fromlen < sizeof(struct sockaddr_in))) ||
	    (to   && (!tolen   || *tolen   < sizeof(struct sockaddr_in)))) {
		errno = EINVAL;
		return -1;
	}

	/*
	 *	IP_PKTINFO / IP_RECVDSTADDR don't provide sin_port so we have to
	 *	retrieve it using getsockname().
	 */
	if (to) {
		struct sockaddr_in si;
		socklen_t l = sizeof(si);

		((struct sockaddr_in *)to)->sin_family = AF_INET;
		((struct sockaddr_in *)to)->sin_port = 0;
		l = sizeof(si);
		if (getsockname(s, (struct sockaddr *)&si, &l) == 0) {
			((struct sockaddr_in *)to)->sin_port = si.sin_port;
			((struct sockaddr_in *)to)->sin_addr = si.sin_addr; 
		}
		if (tolen) *tolen = sizeof(struct sockaddr_in);
	}

	/* Set up iov and msgh structures. */
	memset(&msgh, 0, sizeof(struct msghdr));
	iov.iov_base = buf;
	iov.iov_len  = len;
	msgh.msg_control = cbuf;
	msgh.msg_controllen = sizeof(cbuf);
	msgh.msg_name = from;
	msgh.msg_namelen = fromlen ? *fromlen : 0;
	msgh.msg_iov  = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_flags = 0;

	/* Receive one packet. */
	if ((err = recvmsg(s, &msgh, flags)) < 0) {
		return err;
	}
	if (fromlen) *fromlen = msgh.msg_namelen;

	/* Process auxiliary received data in msgh */
	for (cmsg = CMSG_FIRSTHDR(&msgh);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msgh,cmsg)) {

# ifdef HAVE_IP_PKTINFO
		if (cmsg->cmsg_level == SOL_IP
		    && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *i =
				(struct in_pktinfo *)CMSG_DATA(cmsg);
			if (to) {
				((struct sockaddr_in *)to)->sin_addr =
					i->ipi_addr;
				if (tolen) *tolen = sizeof(struct sockaddr_in);
			}
			break;
		}
# endif

# ifdef HAVE_IP_RECVDSTADDR
		if (cmsg->cmsg_level == IPPROTO_IP
		    && cmsg->cmsg_type == IP_RECVDSTADDR) {
			struct in_addr *i = (struct in_addr *)CMSG_DATA(cmsg);
			if (to) {
				((struct sockaddr_in *)to)->sin_addr = *i;
				if (tolen) *tolen = sizeof(struct sockaddr_in);
			}
			break;
		}
# endif
	}
	return err;
#else 
	/* fallback: call recvfrom */
	return recvfrom(s, buf, len, flags, from, fromlen);
#endif /* defined(HAVE_IP_PKTINFO) || defined(HAVE_IP_RECVDSTADDR) */
}

int sendfromto(int s, void *buf, size_t len, int flags,
			  struct sockaddr *from, socklen_t fromlen,
			  struct sockaddr *to, socklen_t tolen)
{
#if defined(HAVE_IP_PKTINFO) || defined(HAVE_IP_SENDSRCADDR)
	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct iovec iov;
# ifdef HAVE_IP_PKTINFO
	char cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct in_pktinfo pktinfo, *pktinfo_ptr;
	memset(&pktinfo, 0, sizeof(struct in_pktinfo));
# endif

# ifdef HAVE_IP_SENDSRCADDR
	char cmsgbuf[CMSG_SPACE(sizeof(struct in_addr))];
# endif

	/* Set up iov and msgh structures. */
	memset(&msgh, 0, sizeof(struct msghdr));
	iov.iov_base = buf;
	iov.iov_len = len;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = cmsgbuf;
	msgh.msg_controllen = sizeof(cmsgbuf);
	msgh.msg_name = to;
	msgh.msg_namelen = tolen;
	
	cmsg = CMSG_FIRSTHDR(&msgh);

# ifdef HAVE_IP_PKTINFO
	cmsg->cmsg_level = SOL_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	pktinfo.ipi_spec_dst = ((struct sockaddr_in *)from)->sin_addr;
	pktinfo_ptr = (struct in_pktinfo *)CMSG_DATA(cmsg);
	memcpy(pktinfo_ptr, &pktinfo, sizeof(struct in_pktinfo));
# endif
# ifdef HAVE_IP_SENDSRCADDR
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_SENDSRCADDR;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
	memcpy((struct in_addr *)CMSG_DATA(cmsg), 
			&((struct sockaddr_in *)from)->sin_addr, sizeof(struct in_addr));
# endif

	return sendmsg(s, &msgh, flags);
#else
	/* fallback: call sendto() */
	return sendto(s, buf, len, flags, to, tolen);
#endif	/* defined(HAVE_IP_PKTINFO) || defined (HAVE_IP_SENDSRCADDR) */
}


#ifdef TESTING
/*
 *	Small test program to test recvfromto/sendfromto
 *
 *	use a virtual IP address as first argument to test 
 *
 *	reply packet should originate from virtual IP and not
 *	from the default interface the alias is bound to
 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>

#define DEF_PORT 20000		/* default port to listen on */
#define DESTIP "127.0.0.1"	/* send packet to localhost per default */
#define TESTSTRING "foo"	/* what to send */
#define TESTLEN 4			/* 4 bytes */

int main(int argc, char **argv)
{
	struct sockaddr_in from, to, in;
	char buf[TESTLEN];
	char *destip = DESTIP;
	int port = DEF_PORT;
	int n, server_socket, client_socket, fl, tl, pid;

	if (argc > 1) destip = argv[1];
	if (argc > 2) port = atoi(argv[2]);

	in.sin_family = AF_INET;
	in.sin_addr.s_addr = INADDR_ANY;
	in.sin_port = htons(port);
	fl = tl = sizeof(struct sockaddr_in);
	memset(&from, 0, sizeof(from));
	memset(&to,   0, sizeof(to));

	switch(pid = fork()) {
		case -1:
			perror("fork");
			return 0;
		case 0:
			/* child */
			usleep(100000);	
			goto client;
	}

	/* parent: server */
	server_socket = socket(PF_INET, SOCK_DGRAM, 0);
	if (udpfromto_init(server_socket) != 0) {
		perror("udpfromto_init\n");
		waitpid(pid, NULL, WNOHANG);
		return 0;
	}

	if (bind(server_socket, (struct sockaddr *)&in, sizeof(in)) < 0) {
		perror("server: bind");
		waitpid(pid, NULL, WNOHANG);
		return 0;
	}

	printf("server: waiting for packets on INADDR_ANY:%d\n", port);
	if ((n = recvfromto(server_socket, buf, sizeof(buf), 0,
	    (struct sockaddr *)&from, &fl,
	    (struct sockaddr *)&to, &tl)) < 0) {
		perror("server: recvfromto");
		waitpid(pid, NULL, WNOHANG);
		return 0;
	}

	printf("server: received a packet of %d bytes [%s] ", n, buf);
	printf("(src ip:port %s:%d ",
		inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	printf(" dst ip:port %s:%d)\n",
		inet_ntoa(to.sin_addr), ntohs(to.sin_port));

	printf("server: replying from address packet was received on to source address\n");
		
	if ((n = sendfromto(server_socket, buf, n, 0,
		(struct sockaddr *)&to, tl,
		(struct sockaddr *)&from, fl)) < 0) {
		perror("server: sendfromto");
	}

	waitpid(pid, NULL, 0);
	return 0;

client:
	close(server_socket);
	client_socket = socket(PF_INET, SOCK_DGRAM, 0);
	if (udpfromto_init(client_socket) != 0) {
		perror("udpfromto_init");
		_exit(0);
	}
	/* bind client on different port */
	in.sin_port = htons(port+1);
	if (bind(client_socket, (struct sockaddr *)&in, sizeof(in)) < 0) {
		perror("client: bind");
		_exit(0);
	}

	in.sin_port = htons(port);
	in.sin_addr.s_addr = inet_addr(destip);

	printf("client: sending packet to %s:%d\n", destip, port);
	if (sendto(client_socket, TESTSTRING, TESTLEN, 0, 
			(struct sockaddr *)&in, sizeof(in)) < 0) {
		perror("client: sendto");
		_exit(0);
	}
			
	printf("client: waiting for reply from server on INADDR_ANY:%d\n", port+1);

	if ((n = recvfromto(client_socket, buf, sizeof(buf), 0,
	    (struct sockaddr *)&from, &fl,
	    (struct sockaddr *)&to, &tl)) < 0) {
		perror("client: recvfromto");
		_exit(0);
	}

	printf("client: received a packet of %d bytes [%s] ", n, buf);
	printf("(src ip:port %s:%d",
		inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	printf(" dst ip:port %s:%d)\n",
		inet_ntoa(to.sin_addr), ntohs(to.sin_port));

	_exit(0);
}

#endif /* TESTING */
