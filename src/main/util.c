/*
 * util.c	Various utility functions.
 *
 * Version:     @(#)util.c  2.20  17-Jul-1999  miquels@cistron.nl
 */

char util_sccsid[] =
"@(#)util.c	2.20 Copyright 1997-1999 Cistron Internet Services B.V.";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>
#include	<signal.h>

#include	"radiusd.h"

/*
 *	Call getpwnam but cache the result.
 */
struct passwd *rad_getpwnam(char *name)
{
	static struct passwd *lastpwd;
	static char lastname[64];
	static time_t lasttime = 0;
	time_t now;

	now = time(NULL);

	if ((now <= lasttime + 5 ) && strncmp(name, lastname, 64) == 0)
		return lastpwd;

	strncpy(lastname, name, 63);
	lastname[63] = 0;
	lastpwd = getpwnam(name);
	lasttime = now;

	return lastpwd;
}

#if defined (sun) && defined(__svr4__)
/*
 *	The signal() function in Solaris 2.5.1 sets SA_NODEFER in
 *	sa_flags, which causes grief if signal() is called in the
 *	handler before the cause of the signal has been cleared.
 *	(Infinite recursion).
 */
void (*sun_signal(int signo, void (*func)(int)))(int)
{
	struct sigaction act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
#ifdef  SA_INTERRUPT		/* SunOS */
	act.sa_flags |= SA_INTERRUPT;
#endif
	if (sigaction(signo, &act, &oact) < 0)
		return SIG_ERR;
	return oact.sa_handler;
}
#endif


/*
 *	Free an AUTHREQ struct.
 */
void request_free(REQUEST *request)
{
	if (request->packet)
		rad_free(request->packet);
	if (request->proxy)
		rad_free(request->proxy);
	free(request);
}


/*
 *	Build a reply radius packet, based on the request data.
 */
RADIUS_PACKET *build_reply(int code, REQUEST *request,
	VALUE_PAIR *vps, char *user_msg)
{
	RADIUS_PACKET	*rp;
	VALUE_PAIR	*vp;

	if ((rp = rad_alloc(0)) == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	rp->dst_ipaddr = request->packet->src_ipaddr;
	rp->dst_port   = request->packet->src_port;
	rp->id         = request->packet->id;
	rp->code       = code;
	memcpy(rp->vector, request->packet->vector, sizeof(rp->vector));
	rp->vps        = paircopy(vps);

	/*
	 *	Need to copy PROXY_PAIRS from request->packet->vps
	 */
	if ((vp = paircopy2(request->packet->vps, PW_PROXY_STATE)) != NULL)
		pairadd(&(rp->vps), vp);

	if (user_msg && !(vp = paircreate(PW_REPLY_MESSAGE, PW_TYPE_STRING))) {
		strcpy(vp->strvalue, user_msg);
		vp->length = strlen(user_msg);
		pairadd(&(rp->vps), vp);
	}

	return rp;
}

