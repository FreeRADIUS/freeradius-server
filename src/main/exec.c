/*
 * exec.c	Execute external programs.
 *
 * Version:	@(#)exec.c  1.83  07-Aug-1999  miquels@cistron.nl
 *
 */
char exec_sccsid[] =
"@(#)exec.c	1.83 Copyright 1999 Cistron Internet Services B.V."; 

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/time.h>
#include	<sys/file.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<fcntl.h>
#include	<time.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<signal.h>
#include	<errno.h>
#include	<sys/wait.h>

#include	"radiusd.h"

/*
 *	Replace %<whatever> in a string.
 *
 *	%p   Port number
 *	%n   NAS IP address
 *	%f   Framed IP address
 *	%u   User name
 *	%c   Callback-Number
 *	%t   MTU
 *	%a   Protocol (SLIP/PPP)
 *	%s   Speed (PW_CONNECT_INFO)
 *	%i   Calling Station ID
 *
 */
char *radius_xlate(char *str, VALUE_PAIR *request, VALUE_PAIR *reply)
{
	static char buf[MAX_STRING_LEN * 2];
	int n, i = 0, c;
	char *p;
	VALUE_PAIR *tmp;

	for (p = str; *p; p++) {
		if (i >= MAX_STRING_LEN)
			break;
		c = *p;
		if (c != '%') {
			buf[i++] = *p;
			continue;
		}
		if (*++p == 0) break;
		if (c == '%') switch(*p) {
			case '%':
				buf[i++] = *p;
				break;
			case 'f': /* Framed IP address */
				n = 0;
				if ((tmp = pairfind(reply,
				     PW_FRAMED_IP_ADDRESS)) != NULL) {
					n = tmp->lvalue;
				}
				ip_ntoa(buf + i, n);
				i += strlen(buf + i);
				break;
			case 'n': /* NAS IP address */
				n = 0;
				if ((tmp = pairfind(request,
				     PW_NAS_IP_ADDRESS)) != NULL) {
					n = tmp->lvalue;
				}
				ip_ntoa(buf + i, n);
				i += strlen(buf + i);
				break;
			case 't': /* MTU */
				n = 0;
				if ((tmp = pairfind(reply,
				     PW_FRAMED_MTU)) != NULL) {
					n = tmp->lvalue;
				}
				sprintf(buf + i, "%d", n);
				i += strlen(buf + i);
				break;
			case 'p': /* Port number */
				n = 0;
				if ((tmp = pairfind(request,
				     PW_NAS_PORT_ID)) != NULL) {
					n = tmp->lvalue;
				}
				sprintf(buf + i, "%d", n);
				i += strlen(buf + i);
				break;
			case 'u': /* User name */
				if ((tmp = pairfind(request,
				     PW_USER_NAME)) != NULL)
					strcpy(buf + i, tmp->strvalue);
				else
					strcpy(buf + i, "unknown");
				i += strlen(buf + i);
				break;
			case 'i': /* Calling station ID */
				if ((tmp = pairfind(request,
				     PW_CALLING_STATION_ID)) != NULL)
					strcpy(buf + i, tmp->strvalue);
				else
					strcpy(buf + i, "unknown");
				i += strlen(buf + i);
				break;
			case 'c': /* Callback-Number */
				if ((tmp = pairfind(reply,
				     PW_CALLBACK_NUMBER)) != NULL)
					strcpy(buf + i, tmp->strvalue);
				else
					strcpy(buf + i, "unknown");
				i += strlen(buf + i);
				break;
			case 'a': /* Protocol: SLIP/PPP */
				if ((tmp = pairfind(reply,
				     PW_FRAMED_PROTOCOL)) != NULL)
		strcpy(buf + i, tmp->lvalue == PW_PPP ? "PPP" : "SLIP");
				else
					strcpy(buf + i, "unknown");
				i += strlen(buf + i);
				break;
			case 's': /* Speed */
				if ((tmp = pairfind(request,
				     PW_CONNECT_INFO)) != NULL)
					strcpy(buf + i, tmp->strvalue);
				else
					strcpy(buf + i, "unknown");
				i += strlen(buf + i);
				break;
			default:
				buf[i++] = '%';
				buf[i++] = *p;
				break;
		}
	}
	if (i >= MAX_STRING_LEN)
		i = MAX_STRING_LEN - 1;
	buf[i++] = 0;

	return buf;
}

/*
 *	Execute a program on successful authentication.
 *	Return 0 if exec_wait == 0.
 *	Return the exit code of the called program if exec_wait != 0.
 *
 */
int radius_exec_program(char *cmd, VALUE_PAIR *request, VALUE_PAIR **reply,
		int exec_wait, char **user_msg)
{
	VALUE_PAIR	*vp;
	static char	message[256];
	char		answer[4096];
	char		*argv[32];
	char		*buf, *p;
	int		pd[2];
	pid_t		pid;
	int		argc = -1;
	int		comma = 0;
	int		status;
	int		n, left, done;
	void		(*oldsig)(int) = NULL;
	

	/*
	 *	(hs)	- Open a pipe for child/parent communication.
	 *		- Reset the signal handler for SIGCHLD, so
	 *		  we have a chance to notice the dead child here and
	 *  		  not in some signal handler.
	 *		  This has to be done for the exec_wait case only, since
	 *		  if we don't wait we aren't interested in any
	 *		  gone children ...
	 */	
	if (exec_wait) {
		if (pipe(pd) != 0) {
			log(L_ERR|L_CONS, "Couldn't open pipe: %m");
			pd[0] = pd[1] = 0;
		}
		if ((oldsig = signal(SIGCHLD, SIG_DFL)) == SIG_ERR) {
			log(L_ERR|L_CONS, "Can't reset SIGCHLD: %m");
			oldsig = NULL;
		}
	}

	if ((pid = fork()) == 0) {
		/*	
		 *	Child
		 */
		buf = radius_xlate(cmd, request, *reply);

		/*
		 *	XXX FIXME: This is debugging info.
		 */
		log(L_INFO, "Exec-Program: %s", buf);

		/*
		 *	Build vector list and execute.
		 */
		p = strtok(buf, " \t");
		if (p) do {
			argv[++argc] = p;
			p = strtok(NULL, " \t");
		} while(p != NULL);
		argv[++argc] = p;
		if (argc == 0) {
			log(L_ERR, "Exec-Program: empty command line.");
			exit(1);
		}

		if (exec_wait) {
			if (close(pd[0]) != 0)
				log(L_ERR|L_CONS, "Can't close pipe: %m");
			if (dup2(pd[1], 1) != 1)
				log(L_ERR|L_CONS, "Can't dup stdout: %m");
		}

		for(n = 32; n >= 3; n--)
			close(n);

		execvp(argv[0], argv);

		log(L_ERR, "Exec-Program: %s: %m", argv[0]);
		exit(1);
	}

	/*
	 *	Parent 
	 */
	if (pid < 0) {
		log(L_ERR|L_CONS, "Couldn't fork: %m");
		return -1;
	}
	if (!exec_wait)
		return 0;

	/*
	 *	(hs) Do we have a pipe?
	 *	--> Close the write side of the pipe 
	 *	--> Read from it.
	 */
	done = 0;
	if (pd[0] || pd[1]) {
		if (close(pd[1]) != 0)
			log(L_ERR|L_CONS, "Can't close pipe: %m");

		/*
		 *	(hs) Read until we doesn't get any more
		 *	or until the message is full.
		 */
		done = 0;
		left = sizeof(answer) - 1;
		while ((n = read(pd[0], answer + done, left)) > 0) {
			done += n;
			left -= n;
			if (left <= 0) break;
		}
		answer[done] = 0;

		/*
		 *	(hs) Make sure that the writer can't block
		 *	while writing in a pipe that isn't read anymore.
		 */
		close(pd[0]);
	}

	/*
	 *	Parse the output, if any.
	 */
	if (done) {
		/*
		 *	For backwards compatibility, first check
		 *	for plain text (user_msg).
		 */
		vp = NULL;
		n = userparse(answer, &vp);
		if (vp) pairfree(vp);
		vp = NULL;

		if (n != 0) {
			log(L_DBG, "Exec-Program-Wait: plaintext: %s", answer);
			if (user_msg) {
				strncpy(message, answer, sizeof(message));
				message[sizeof(message) - 1] = 0;
				*user_msg = message;
			}
		} else {
			/*
			 *	HACK: Replace '\n' with ',' so that
			 *	userparse() can parse the buffer in
			 *	one go (the proper way would be to
			 *	fix userparse(), but oh well).
			 */
			for (p = answer; *p; p++) {
				if (*p == '\n') {
					*p = comma ? ' ' : ',';
					comma = 0;
				}
				if (*p == ',') comma++;
			}

			log(L_DBG,"Exec-Program-Wait: value-pairs: %s", answer);
			if (userparse(answer, &vp) != 0)
				log(L_ERR,
		"Exec-Program-Wait: %s: unparsable reply", cmd);
			else {
				pairmove(reply, &vp);
				pairfree(vp);
			}
		}
	}

	while(waitpid(pid, &status, 0) != pid)
		;

	/*
	 *	(hs) Now we let our cleanup_sig handler take care for
	 *	all signals that will arise.
	 */
	if (oldsig && (signal(SIGCHLD, oldsig) == SIG_ERR))
		log(L_ERR|L_CONS,
			"Can't set SIGCHLD to the cleanup handler: %m");
	sig_cleanup(SIGCHLD);

	if (WIFEXITED(status)) {
		status = WEXITSTATUS(status);
		log(L_INFO, "Exec-Program: returned: %d", status);
		return status;
	}
	log(L_ERR|L_CONS, "Exec-Program: Abnormal child exit (killed or coredump)");

	return 1;
}

