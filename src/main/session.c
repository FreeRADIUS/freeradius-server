#include	"autoconf.h"

#include	<stdio.h>
#include	<string.h>
#include	<time.h>
#include	<unistd.h>
#include	<signal.h>
#include	<errno.h>
#include	<sys/wait.h>

#include	"radiusd.h"
#include	"modules.h"

/* End a session by faking a Stop packet to all accounting modules */
int session_zap(uint32_t nasaddr, int port, const char *user,
		const char *sessionid, uint32_t cliaddr, char proto, time_t t)
{
  static unsigned char id=0;

  REQUEST stopreq;
  RADIUS_PACKET stoppkt;
  VALUE_PAIR *vp, *userpair;
  int modret;
  int ret;

  memset(&stoppkt, 0, sizeof stoppkt);
  stoppkt.data=0;
  stoppkt.sockfd=-1;
  stoppkt.code=PW_ACCOUNTING_REQUEST;
  stoppkt.id=id++;
  stoppkt.timestamp=t?t:time(0);
  stoppkt.vps=0;

  /* Hold your breath */
#define PAIR(n,v,t,e) do { \
    if(!(vp=paircreate(n, t))) { \
      radlog(L_ERR|L_CONS, "no memory"); \
      pairfree(&stoppkt.vps); \
      return 0; \
    } \
    vp->e=v; \
    pairadd(&stoppkt.vps, vp); \
  } while(0)
#define INTPAIR(n,v) PAIR(n,v,PW_TYPE_INTEGER,lvalue)
#define IPPAIR(n,v) PAIR(n,v,PW_TYPE_IPADDR,lvalue)
#define STRINGPAIR(n,v) do { \
    if(!(vp=paircreate(n, PW_TYPE_STRING))) { \
      radlog(L_ERR|L_CONS, "no memory"); \
      pairfree(&stoppkt.vps); \
      return 0; \
    } \
    strNcpy((char *)vp->strvalue, v, sizeof vp->strvalue); \
    vp->length=strlen(v); \
    pairadd(&stoppkt.vps, vp); \
  } while(0)

  INTPAIR(PW_ACCT_STATUS_TYPE, PW_STATUS_STOP);
  IPPAIR(PW_NAS_IP_ADDRESS, nasaddr);
  INTPAIR(PW_ACCT_DELAY_TIME, 0);
  STRINGPAIR(PW_USER_NAME, user);
  userpair=vp;
  INTPAIR(PW_NAS_PORT_ID, port);
  STRINGPAIR(PW_ACCT_SESSION_ID, sessionid);
  if(proto=='P') {
    INTPAIR(PW_SERVICE_TYPE, PW_FRAMED_USER);
    INTPAIR(PW_FRAMED_PROTOCOL, PW_PPP);
  } else if(proto=='S') {
    INTPAIR(PW_SERVICE_TYPE, PW_FRAMED_USER);
    INTPAIR(PW_FRAMED_PROTOCOL, PW_SLIP);
  } else {
    INTPAIR(PW_SERVICE_TYPE, PW_LOGIN_USER); /* A guess, really */
  }
  if(cliaddr)
    IPPAIR(PW_FRAMED_IP_ADDRESS, cliaddr);
  INTPAIR(PW_ACCT_SESSION_TIME, 0);
  INTPAIR(PW_ACCT_INPUT_OCTETS, 0);
  INTPAIR(PW_ACCT_OUTPUT_OCTETS, 0);
  INTPAIR(PW_ACCT_INPUT_PACKETS, 0);
  INTPAIR(PW_ACCT_OUTPUT_PACKETS, 0);

  memset(&stopreq, 0, sizeof stopreq);
  stopreq.packet=&stoppkt;
  stopreq.proxy=0;
  stopreq.reply=0;
  stopreq.config_items=0;
  stopreq.username=userpair;
  stopreq.child_pid=-1;
  stopreq.timestamp=stoppkt.timestamp;
  stopreq.next=0;

  /* FIXME: Need to run preaccouting, so replication can work */
  modret = module_accounting(&stopreq);
  if(modret==RLM_MODULE_NOOP ||
     modret==RLM_MODULE_OK ||
     modret==RLM_MODULE_UPDATED ||
     modret==RLM_MODULE_HANDLED)
    ret=1;
  else
    ret=0;

  pairfree(&stoppkt.vps);
  return ret;
}


/*
 *	Timeout handler (10 secs)
 */
static volatile int got_alrm;
static void alrm_handler(int s)
{
	(void)s;
	got_alrm = 1;
}

/*
 *	Check one terminal server to see if a user is logged in.
 */
int rad_check_ts(uint32_t nasaddr, int portnum, const char *user,
		 const char *session_id)
{
	int	pid, st, e;
	int	n;
	NAS	*nas;
	char	address[16];
	char	port[8];
	void	(*handler)(int);

	/*
	 *	Find NAS type.
	 */
	if ((nas = nas_find(nasaddr)) == NULL) {
		radlog(L_ERR, "Accounting: unknown NAS");
		return -1;
	}

	/*
	 *	Fork.
	 */
	handler = signal(SIGCHLD, SIG_DFL);
	if ((pid = fork()) < 0) {
		radlog(L_ERR, "Accounting: fork: %s", strerror(errno));
		signal(SIGCHLD, handler);
		return -1;
	}

	if (pid > 0) {
		/*
		 *	Parent - Wait for checkrad to terminate.
		 *	We timeout in 10 seconds.
		 */
		got_alrm = 0;
		signal(SIGALRM, alrm_handler);
		alarm(10);
		while((e = waitpid(pid, &st, 0)) != pid)
			if (e < 0 && (errno != EINTR || got_alrm))
				break;
		alarm(0);
		signal(SIGCHLD, handler);
		if (got_alrm) {
			kill(pid, SIGTERM);
			sleep(1);
			kill(pid, SIGKILL);
			radlog(L_ERR, "Check-TS: timeout waiting for checkrad");
			return 2;
		}
		if (e < 0) {
			radlog(L_ERR, "Check-TS: unknown error in waitpid()");
			return 2;
		}
		return WEXITSTATUS(st);
	}

	/*
	 *	Child - exec checklogin with the right parameters.
	 */
	for (n = 32; n >= 3; n--)
		close(n);

	ip_ntoa(address, nasaddr);
	sprintf(port, "%d", portnum);

#ifdef __EMX__
	/* OS/2 can't directly execute scripts then we call the command
	   processor to execute checkrad
	*/
	execl(getenv("COMSPEC"), "", "/C","checkrad",nas->nastype, address, port,
		user, session_id, NULL);
#else
	execl(CHECKRAD, "checkrad",nas->nastype, address, port,
		user, session_id, NULL);
#endif
	radlog(L_ERR, "Check-TS: exec %s: %s", CHECKRAD, strerror(errno));

	/*
	 *	Exit - 2 means "some error occured".
	 */
	exit(2);
}
