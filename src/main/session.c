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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>

#ifdef HAVE_SYS_WAIT_H
#include	<sys/wait.h>
#endif

#ifdef WITH_SESSION_MGMT
/*
 *	End a session by faking a Stop packet to all accounting modules.
 */
int session_zap(REQUEST *request, fr_ipaddr_t const *nasaddr, uint32_t nas_port,
		char const *user,
		char const *sessionid, uint32_t cliaddr, char proto,
		int session_time)
{
	REQUEST *stopreq;
	VALUE_PAIR *vp;
	int ret;

	stopreq = request_alloc_fake(request);
	rad_assert(stopreq != NULL);
	rad_assert(stopreq->packet != NULL);
	stopreq->packet->code = PW_CODE_ACCOUNTING_REQUEST; /* just to be safe */
	stopreq->listener = request->listener;

	/* Hold your breath */
#define PAIR(n,v,e) do { \
		if(!(vp = fr_pair_afrom_num(stopreq->packet,n, 0))) {	\
			talloc_free(stopreq); \
			ERROR("no memory"); \
			return 0; \
		} \
		vp->e = v; \
		fr_pair_add(&(stopreq->packet->vps), vp); \
	} while(0)

#define INTPAIR(n,v) PAIR(n,v,vp_integer)

#define IPPAIR(n,v) PAIR(n,v,vp_ipaddr)

#define IPV6PAIR(n,v) PAIR(n,v,vp_ipv6addr)

#define STRINGPAIR(n,v) do { \
	  if(!(vp = fr_pair_afrom_num(stopreq->packet,n, 0))) {	\
		talloc_free(stopreq); \
		ERROR("no memory"); \
		return 0; \
	} \
	fr_pair_value_strcpy(vp, v);	\
	fr_pair_add(&(stopreq->packet->vps), vp); \
	} while(0)

	INTPAIR(PW_ACCT_STATUS_TYPE, PW_STATUS_STOP);

	if (nasaddr->af == AF_INET) {
		IPPAIR(PW_NAS_IP_ADDRESS, nasaddr->ipaddr.ip4addr.s_addr);
	} else {
		IPV6PAIR(PW_NAS_IPV6_ADDRESS, nasaddr->ipaddr.ip6addr);
	}

	INTPAIR(PW_EVENT_TIMESTAMP, 0);
	vp->vp_date = time(NULL);
	INTPAIR(PW_ACCT_DELAY_TIME, 0);

	STRINGPAIR(PW_USER_NAME, user);
	stopreq->username = vp;

	INTPAIR(PW_NAS_PORT, nas_port);
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
	INTPAIR(PW_ACCT_SESSION_TIME, session_time);
	INTPAIR(PW_ACCT_INPUT_OCTETS, 0);
	INTPAIR(PW_ACCT_OUTPUT_OCTETS, 0);
	INTPAIR(PW_ACCT_INPUT_PACKETS, 0);
	INTPAIR(PW_ACCT_OUTPUT_PACKETS, 0);

	stopreq->password = NULL;

	RDEBUG("Running Accounting section for automatically created accounting 'stop'");
	rdebug_pair_list(L_DBG_LVL_1, request, request->packet->vps, NULL);
	ret = rad_accounting(stopreq);

	/*
	 *  We've got to clean it up by hand, because no one else will.
	 */
	talloc_free(stopreq);

	return ret;
}

#ifndef __MINGW32__

/*
 *	Check one terminal server to see if a user is logged in.
 *
 *	Return values:
 *		0 The user is off-line.
 *		1 The user is logged in.
 *		2 Some error occured.
 */
int rad_check_ts(fr_ipaddr_t const *nasaddr, uint32_t nas_port, char const *user,
		 char const *session_id)
{
	pid_t	pid, child_pid;
	int	status;
	char	address[64];
	char	port[11];
	RADCLIENT *cl;

	/*
	 *	Find NAS type.
	 */
	cl = client_find_old(nasaddr);
	if (!cl) {
		/*
		 *  Unknown NAS, so trusting radutmp.
		 */
		DEBUG2("checkrad: Unknown NAS %s, not checking",
		       inet_ntop(nasaddr->af, &(nasaddr->ipaddr), address, sizeof(address)));
		return 1;
	}

	/*
	 *  No nas_type, or nas type 'other', trust radutmp.
	 */
	if (!cl->nas_type || (cl->nas_type[0] == '\0') ||
	    (strcmp(cl->nas_type, "other") == 0)) {
		DEBUG2("checkrad: No NAS type, or type \"other\" not checking");
		return 1;
	}

	/*
	 *	Fork.
	 */
	if ((pid = rad_fork()) < 0) { /* do wait for the fork'd result */
		ERROR("Accounting: Failed in fork(): Cannot run checkrad\n");
		return 2;
	}

	if (pid > 0) {
		child_pid = rad_waitpid(pid, &status);

		/*
		 *	It's taking too long.  Stop waiting for it.
		 *
		 *	Don't bother to kill it, as we don't care what
		 *	happens to it now.
		 */
		if (child_pid == 0) {
			ERROR("Check-TS: timeout waiting for checkrad");
			return 2;
		}

		if (child_pid < 0) {
			ERROR("Check-TS: unknown error in waitpid()");
			return 2;
		}

		return WEXITSTATUS(status);
	}

	/*
	 *  We don't close fd's 0, 1, and 2.  If we're in debugging mode,
	 *  then they should go to stdout (etc), along with the other
	 *  server log messages.
	 *
	 *  If we're not in debugging mode, then the code in radiusd.c
	 *  takes care of connecting fd's 0, 1, and 2 to /dev/null.
	 */
	closefrom(3);

	inet_ntop(nasaddr->af, &(nasaddr->ipaddr), address, sizeof(address));
	snprintf(port, sizeof(port), "%u", nas_port);

#ifdef __EMX__
	/* OS/2 can't directly execute scripts then we call the command
	   processor to execute checkrad
	*/
	execl(getenv("COMSPEC"), "", "/C","checkrad", cl->nas_type, address, port,
		user, session_id, NULL);
#else
	execl(main_config.checkrad, "checkrad", cl->nas_type, address, port,
		user, session_id, NULL);
#endif
	ERROR("Check-TS: exec %s: %s", main_config.checkrad, fr_syserror(errno));

	/*
	 *	Exit - 2 means "some error occured".
	 */
	exit(2);
}
#else
int rad_check_ts(fr_ipaddr_t const *nasaddr, UNUSED unsigned int nas_port,
		 UNUSED char const *user, UNUSED char const *session_id)
{
	ERROR("Simultaneous-Use is not supported");
	return 2;
}
#endif

#else
/* WITH_SESSION_MGMT */

int session_zap(UNUSED REQUEST *request, fr_ipaddr_t const *nasaddr, UNUSED uint32_t nas_port,
		UNUSED char const *user,
		UNUSED char const *sessionid, UNUSED uint32_t cliaddr, UNUSED char proto,
		UNUSED int session_time)
{
	return RLM_MODULE_FAIL;
}

int rad_check_ts(fr_ipaddr_t const *nasaddr, UNUSED unsigned int nas_port,
		 UNUSED char const *user, UNUSED char const *session_id)
{
	ERROR("Simultaneous-Use is not supported");
	return 2;
}
#endif
