/*
 * session.c	session management
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
 */


#include	"autoconf.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>

#ifdef HAVE_UNISTD_H
#include	<unistd.h>
#endif

#include	<signal.h>
#include	<errno.h>
#include	<sys/wait.h>

#ifdef HAVE_NETINET_IN_H
#include	<netinet/in.h>
#endif

#include	"radiusd.h"
#include	"modules.h"

/* End a session by faking a Stop packet to all accounting modules */
int session_zap(int sockfd, uint32_t nasaddr, int port, const char *user,
		const char *sessionid, uint32_t cliaddr, char proto, time_t t)
{
	static unsigned char id = 0;

	REQUEST *stopreq;
	RADIUS_PACKET *stoppkt;
	VALUE_PAIR *vp, *userpair;
	int ret;

	stoppkt = rad_alloc(0);

	stoppkt->sockfd = -1;
	stoppkt->src_ipaddr = htonl(INADDR_LOOPBACK);
	stoppkt->dst_ipaddr = htonl(INADDR_LOOPBACK);
	stoppkt->src_port = 0;
	stoppkt->dst_port = 0;

	stoppkt->id = id++;
	stoppkt->code = PW_ACCOUNTING_REQUEST;

	stoppkt->timestamp = t?t:time(0);

	stoppkt->data = NULL;
	stoppkt->data_len = 0;

	stoppkt->vps = NULL;

	/* Hold your breath */
#define PAIR(n,v,t,e) do { \
		if(!(vp = paircreate(n, t))) { \
			radlog(L_ERR|L_CONS, "no memory"); \
			pairfree(&stoppkt->vps); \
			return 0; \
		} \
		vp->e = v; \
		pairadd(&stoppkt->vps, vp); \
	} while(0)
#define INTPAIR(n,v) PAIR(n,v,PW_TYPE_INTEGER,lvalue)
#define IPPAIR(n,v) PAIR(n,v,PW_TYPE_IPADDR,lvalue)
#define STRINGPAIR(n,v) do { \
	if(!(vp = paircreate(n, PW_TYPE_STRING))) { \
		radlog(L_ERR|L_CONS, "no memory"); \
		pairfree(&stoppkt->vps); \
		return 0; \
	} \
	strNcpy((char *)vp->strvalue, v, sizeof vp->strvalue); \
	vp->length = strlen(v); \
	pairadd(&stoppkt->vps, vp); \
	} while(0)

	INTPAIR(PW_ACCT_STATUS_TYPE, PW_STATUS_STOP);
	IPPAIR(PW_NAS_IP_ADDRESS, nasaddr);
	INTPAIR(PW_ACCT_DELAY_TIME, 0);
	STRINGPAIR(PW_USER_NAME, user);
	userpair = vp;
	INTPAIR(PW_NAS_PORT_ID, port);
	STRINGPAIR(PW_ACCT_SESSION_ID, sessionid);
	if(proto == 'P') {
		INTPAIR(PW_SERVICE_TYPE, PW_FRAMED_USER);
		INTPAIR(PW_FRAMED_PROTOCOL, PW_PPP);
	} else if(proto == 'S') {
		INTPAIR(PW_SERVICE_TYPE, PW_FRAMED_USER);
		INTPAIR(PW_FRAMED_PROTOCOL, PW_SLIP);
	} else {
		INTPAIR(PW_SERVICE_TYPE, PW_LOGIN_USER); /* A guess, really */
	}
	if(cliaddr != 0)
		IPPAIR(PW_FRAMED_IP_ADDRESS, cliaddr);
	INTPAIR(PW_ACCT_SESSION_TIME, 0);
	INTPAIR(PW_ACCT_INPUT_OCTETS, 0);
	INTPAIR(PW_ACCT_OUTPUT_OCTETS, 0);
	INTPAIR(PW_ACCT_INPUT_PACKETS, 0);
	INTPAIR(PW_ACCT_OUTPUT_PACKETS, 0);

	stopreq = rad_malloc(sizeof *stopreq);
	memset(stopreq, 0, sizeof *stopreq);
#ifndef NDEBUG
	stopreq->magic = REQUEST_MAGIC;
#endif
	stopreq->packet = stoppkt;
	stopreq->proxy = NULL;

	/*
	 *  Leave room for a fake reply
	 */
	stopreq->reply = rad_alloc(0);

	stopreq->reply->sockfd = stopreq->packet->sockfd;
	stopreq->reply->dst_ipaddr = stopreq->packet->src_ipaddr;
	stopreq->reply->dst_port = stopreq->packet->src_port;
	stopreq->reply->id = stopreq->packet->id;
	stopreq->reply->code = 0; /* UNKNOWN code */
	stopreq->reply->vps = NULL;
	stopreq->reply->data = NULL;
	stopreq->reply->data_len = 0;
	
	stopreq->proxy_reply = NULL;
	stopreq->config_items = NULL;
	stopreq->username = userpair;
	stopreq->password = NULL;
	stopreq->timestamp = stoppkt->timestamp;

	/*
	 *  This request does NOT exist in the request list, as it's
	 *  not managed by rad_process().  Therefore, there's no number,
	 *  PID, or other stuff associated with it.
	 */
	stopreq->number = 0;
	stopreq->child_pid = NO_SUCH_CHILD_PID;
	stopreq->container = NULL;

	ret = rad_accounting(stopreq);

	/*
	 *  We've got to clean it up by hand, because no one else will.
	 */
	request_free(&stopreq);

	return ret;
}


/*
 *	Check one terminal server to see if a user is logged in.
 */
int rad_check_ts(uint32_t nasaddr, int portnum, const char *user,
		 const char *session_id)
{
	pid_t	pid, child_pid;
	int	status;
	int	n;
	char	address[16];
	char	port[8];
	RADCLIENT *cl;

	/*
	 *	Find NAS type.
	 */
	cl = client_find(nasaddr);
	if (!cl) {
		/*
		 *  Unknown NAS, so trusting radutmp.
		 */
		return 1;
	}

	/*
	 *  No nastype, or nas type 'other', trust radutmp.
	 */
	if ((cl->nastype[0] == '\0') ||
	    (strcmp(cl->nastype, "other") == 0)) {
		return 1;
	}

	/*
	 *	Fork.
	 */
	if ((pid = rad_fork(1)) < 0) { /* do wait for the fork'd result */
		radlog(L_ERR, "Accounting: fork: %s", strerror(errno));
		return -1;
	}

	if (pid > 0) {
		int found = 0;

		/*
		 *	Parent - Wait for checkrad to terminate.
		 *	We timeout in 10 seconds.
		 */
		child_pid = -1;
		for (n = 0; n < 10; n++) {
			sleep(1);
			child_pid = rad_waitpid(pid, &status, WNOHANG);
			if ((child_pid < 0) || (child_pid == pid)) {
				found = 1;
				break;
			}
		}

		/*
		 *  It's taking too long.  Kill it.
		 */
		if (!found) {
			kill(pid, SIGTERM);
			sleep(1);
			kill(pid, SIGKILL);
			radlog(L_ERR, "Check-TS: timeout waiting for checkrad");
			rad_waitpid(pid, &status, WNOHANG); /* to be safe */
			return 2;
		}

		if (child_pid < 0) {
			radlog(L_ERR, "Check-TS: unknown error in waitpid()");
			return 2;
		}

		return WEXITSTATUS(status);
	}

	/*
	 *	Child - exec checklogin with the right parameters.
	 */
	for (n = 256; n >= 3; n--)
		close(n);

	ip_ntoa(address, nasaddr);
	sprintf(port, "%d", portnum);

#ifdef __EMX__
	/* OS/2 can't directly execute scripts then we call the command
	   processor to execute checkrad
	*/
	execl(getenv("COMSPEC"), "", "/C","checkrad", cl->nastype, address, port,
		user, session_id, NULL);
#else
	execl(mainconfig.checkrad, "checkrad", cl->nastype, address, port,
		user, session_id, NULL);
#endif
	radlog(L_ERR, "Check-TS: exec %s: %s", mainconfig.checkrad, strerror(errno));

	/*
	 *	Exit - 2 means "some error occured".
	 */
	exit(2);
	return -1;
}
