/*
 * util.c	Various utility functions.
 *
 * Version:     $Id$
 */

static const char rcsid[] = "$Id$";

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
struct passwd *rad_getpwnam(const char *name)
{
	static struct passwd *lastpwd;
	static char lastname[64];
	static time_t lasttime = 0;
	time_t now;

	now = time(NULL);

	if ((now <= lasttime + 5 ) && strncmp(name, lastname, sizeof(lastname)) == 0)
		return lastpwd;

	strNcpy(lastname, name, sizeof(lastname));
	lastpwd = getpwnam(name);
	lasttime = now;

	return lastpwd;
}

/*
 *	The signal() function in Solaris 2.5.1 sets SA_NODEFER in
 *	sa_flags, which causes grief if signal() is called in the
 *	handler before the cause of the signal has been cleared.
 *	(Infinite recursion).
 *
 *	The same problem appears on HPUX, so we avoid it, if we can.
 *
 *	Using sigaction() to reset the signal handler fixes the problem,
 *	so where available, we prefer that solution.
 */
void (*reset_signal(int signo, void (*func)(int)))(int)
{
#ifdef HAVE_SIGACTION
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
#else
	
	/*
	 *	re-set by calling the 'signal' function, which
	 *	may cause infinite recursion and core dumps due to
	 *	stack growth.
	 *
	 *	However, the system is too dumb to implement sigaction(),
	 *	so we don't have a choice.
	 */
	signal(signo, func);
#endif
}


/*
 *	Free a REQUEST struct.
 */
void request_free(REQUEST *request)
{
	if (request->packet)
		rad_free(request->packet);
	if (request->proxy)
		rad_free(request->proxy);
	if (request->reply) {
		rad_free(request->reply);
	}
	if (request->config_items) {
		pairfree(request->config_items);
	}
	free(request);
}


/*
 *	Build a reply radius packet, based on the request data.
 */
RADIUS_PACKET *build_reply(int code, REQUEST *request,
	VALUE_PAIR *vps, const char *user_msg)
{
	RADIUS_PACKET	*rp;
	VALUE_PAIR	*vp;

	if ((rp = rad_alloc(0)) == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}
	rp->sockfd     = request->packet->sockfd;
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

	if (user_msg && (vp = paircreate(PW_REPLY_MESSAGE, PW_TYPE_STRING))) {
		strNcpy(vp->strvalue, user_msg, sizeof(vp->strvalue));
		vp->length = strlen(user_msg);
		pairadd(&(rp->vps), vp);
	}

	/*
	 *	Get rid of the old reply (if it exists)
	 */
	if (request->reply) {
		rad_free(request->reply);
	}
	request->reply = rp;

	return rp;
}
