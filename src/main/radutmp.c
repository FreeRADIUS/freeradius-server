/*
 * radutmp.c	Radius session management.
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
 * Copyright 2000  Alan DeKok <aland@ox.com>
 */

static const char rcsid[] =
"$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include	<sys/file.h>
#include	<sys/stat.h>

#include	<fcntl.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>
#include	<signal.h>

#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#include	"radiusd.h"
#include	"radutmp.h"

static const char porttypes[] = "ASITX";

#define LOCK_LEN sizeof(struct radutmp)

/*
 *	used for caching radutmp lookups.
 */
typedef struct nas_port {
	uint32_t	        nasaddr;
	int			port;
	off_t			offset;
	struct nas_port 	*next;
} NAS_PORT;
static NAS_PORT *nas_port_list = NULL;

/*
 *	Internal wrapper for locking, to minimize the number of ifdef's
 *	in the source.
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

/*
 *	Lookup a NAS_PORT in the nas_port_list
 */
static NAS_PORT *nas_port_find(uint32_t nasaddr, int port)
{
	NAS_PORT	*cl;

	for(cl = nas_port_list; cl; cl = cl->next)
		if (nasaddr == cl->nasaddr &&
			port == cl->port)
			break;
	return cl;
}


/*
 *	Zap a user, or all users on a NAS, from the radutmp file.
 */
int radutmp_zap(uint32_t nasaddr, int port, char *user, time_t t)
{
	struct radutmp	u;
	FILE		*fp;
	int		fd;

	if (t == 0) time(&t);
	fp = fopen(RADWTMP, "a");

	if ((fd = open(RADUTMP, O_RDWR|O_CREAT, 0644)) >= 0) {
		int r;

		radutmp_lock(fd);
		
		/*
		 *	Find the entry for this NAS / portno combination.
		 */
		r = 0;
		while (read(fd, &u, sizeof(u)) == sizeof(u)) {
			if (((nasaddr != 0 && nasaddr != u.nas_address) ||
			      (port >= 0   && port    != u.nas_port) ||
			      (user != NULL &&
			       strncmp(u.login, user, sizeof(u.login)) != 0) ||
			       u.type != P_LOGIN))
				continue;
			/*
			 *	Match. Zap it.
			 */
			if (lseek(fd, -(off_t)sizeof(u), SEEK_CUR) < 0) {
				radlog(L_ERR, "Accounting: radutmp_zap: "
					   "negative lseek!\n");
				lseek(fd, (off_t)0, SEEK_SET);
			}
			u.type = P_IDLE;
			u.time = t;
			write(fd, &u, sizeof(u));

#if 0 /* FIXME: should we fixup radwtmp as well or not ? */
			/*
			 *	Add a logout entry to the wtmp file.
			 */
			if (fp != NULL)  {
				make_wtmp(&u, &wt, PW_STATUS_STOP);
				fwrite(&wt, sizeof(wt), 1, fp);
			}
#endif
		}
		close(fd);
	}
	if (fp) fclose(fp);

	return 0;
}


/*
 *	Store logins in the RADIUS utmp file.
 */
int radutmp_add(REQUEST *request)
{
	struct radutmp	ut, u;
	VALUE_PAIR	*vp;
	int		rb_record = 0;
	int		status = -1;
	int		nas_address = 0;
	int		framed_address = 0;
	int		protocol = -1;
	time_t		t;
	int		fd;
	int		ret = 0;
	int		just_an_update = 0;
	int		port_seen = 0;
	int		nas_port_type = 0;
	int		off;

	/*
	 *	Which type is this.
	 */
	if ((vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE)) == NULL) {
		radlog(L_ERR, "Accounting: no Accounting-Status-Type record.");
		return -1;
	}
	status = vp->lvalue;
	if (status == PW_STATUS_ACCOUNTING_ON ||
	    status == PW_STATUS_ACCOUNTING_OFF) rb_record = 1;

	if (!rb_record &&
	    (vp = pairfind(request->packet->vps, PW_USER_NAME)) == NULL) do {
		int check1 = 0;
		int check2 = 0;

		/*
		 *	ComOS (up to and including 3.5.1b20) does not send
		 *	standard PW_STATUS_ACCOUNTING_XXX messages.
		 *
		 *	Check for:  o no Acct-Session-Time, or time of 0
		 *		    o Acct-Session-Id of "00000000".
		 *
		 *	We could also check for NAS-Port, that attribute
		 *	should NOT be present (but we don't right now).
		 */
		if ((vp = pairfind(request->packet->vps, PW_ACCT_SESSION_TIME))
		     == NULL || vp->lvalue == 0)
			check1 = 1;
		if ((vp = pairfind(request->packet->vps, PW_ACCT_SESSION_ID))
		     != NULL && vp->length == 8 &&
		     memcmp(vp->strvalue, "00000000", 8) == 0)
			check2 = 1;
		if (check1 == 0 || check2 == 0) {
#if 0 /* Cisco sometimes sends START records without username. */
			radlog(L_ERR, "Accounting: no username in record");
			return -1;
#else
			break;
#endif
		}
		radlog(L_INFO, "Accounting: converting reboot records.");
		if (status == PW_STATUS_STOP)
			status = PW_STATUS_ACCOUNTING_OFF;
		if (status == PW_STATUS_START)
			status = PW_STATUS_ACCOUNTING_ON;
		rb_record = 1;
	} while(0);

	time(&t);
	memset(&ut, 0, sizeof(ut));
	ut.porttype = 'A';

	/*
	 *	First, find the interesting attributes.
	 */
	for (vp = request->packet->vps; vp; vp = vp->next) {
		switch (vp->attribute) {
			case PW_USER_NAME:
				strncpy(ut.login, (char *)vp->strvalue,
					RUT_NAMESIZE);
				break;
			case PW_LOGIN_IP_HOST:
			case PW_FRAMED_IP_ADDRESS:
				framed_address = vp->lvalue;
				ut.framed_address = vp->lvalue;
				break;
			case PW_FRAMED_PROTOCOL:
				protocol = vp->lvalue;
				break;
			case PW_NAS_IP_ADDRESS:
				nas_address = vp->lvalue;
				ut.nas_address = vp->lvalue;
				break;
			case PW_NAS_PORT_ID:
				ut.nas_port = vp->lvalue;
				port_seen = 1;
				break;
			case PW_ACCT_DELAY_TIME:
				ut.delay = vp->lvalue;
				break;
			case PW_ACCT_SESSION_ID:
				/*
				 *	If length > 8, only store the
				 *	last 8 bytes.
				 */
				off = vp->length - sizeof(ut.session_id);
				if (off < 0) off = 0;
				memcpy(ut.session_id, vp->strvalue + off,
					sizeof(ut.session_id));
				break;
			case PW_NAS_PORT_TYPE:
				if (vp->lvalue >= 0 && vp->lvalue <= 4)
					ut.porttype = porttypes[vp->lvalue];
				nas_port_type = vp->lvalue;
				break;
			case PW_CALLING_STATION_ID:
				strncpy(ut.caller_id, (char *)vp->strvalue,
					sizeof(ut.caller_id));
				ut.caller_id[sizeof(ut.caller_id) - 1] = 0;
				break;
		}
	}

	/*
	 *	If we didn't find out the NAS address, use the
	 *	originator's IP address.
	 */
	if (nas_address == 0) {
		nas_address = request->packet->src_ipaddr;
		ut.nas_address = nas_address;
	}

	if (protocol == PW_PPP)
		ut.proto = 'P';
	else if (protocol == PW_SLIP)
		ut.proto = 'S';
	else
		ut.proto = 'T';
	ut.time = t - ut.delay;

	/*
	 *	See if this was a portmaster reboot.
	 */
	if (status == PW_STATUS_ACCOUNTING_ON && nas_address) {
		radlog(L_INFO, "NAS %s restarted (Accounting-On packet seen)",
			nas_name(nas_address));
		radutmp_zap(nas_address, -1, NULL, ut.time);
		return 0;
	}
	if (status == PW_STATUS_ACCOUNTING_OFF && nas_address) {
		radlog(L_INFO, "NAS %s rebooted (Accounting-Off packet seen)",
			nas_name(nas_address));
		radutmp_zap(nas_address, -1, NULL, ut.time);
		return 0;
	}

	/*
	 *	If we don't know this type of entry pretend we succeeded.
	 */
	if (status != PW_STATUS_START &&
	    status != PW_STATUS_STOP &&
	    status != PW_STATUS_ALIVE) {
		radlog(L_ERR, "NAS %s port %d unknown packet type %d)",
			nas_name(nas_address), ut.nas_port, status);
		return 0;
	}

	/*
	 *	Perhaps we don't want to store this record into
	 *	radutmp. We skip records:
	 *
	 *	- without a NAS-Port-Id (telnet / tcp access)
	 *	- with the username "!root" (console admin login)
	 */
	if (!port_seen || strncmp(ut.login, "!root", RUT_NAMESIZE) == 0)
		return 0;

	/*
	 *	Enter into the radutmp file.
	 */
	if ((fd = open(RADUTMP, O_RDWR|O_CREAT, 0644)) >= 0) {
		NAS_PORT *cache;
		int r;

		radutmp_lock(fd);

		/*
		 *	Find the entry for this NAS / portno combination.
		 */
		if ((cache = nas_port_find(ut.nas_address, ut.nas_port)) != NULL)
			lseek(fd, (off_t)cache->offset, SEEK_SET);

		r = 0;
		off = 0;
		while (read(fd, &u, sizeof(u)) == sizeof(u)) {
			off += sizeof(u);
			if (u.nas_address != ut.nas_address ||
			    u.nas_port	  != ut.nas_port)
				continue;

			if (status == PW_STATUS_STOP &&
			    strncmp(ut.session_id, u.session_id,
			     sizeof(u.session_id)) != 0) {
				/*
				 *	Don't complain if this is not a
				 *	login record (some clients can
				 *	send _only_ logout records).
				 */
				if (u.type == P_LOGIN)
					radlog(L_ERR,
		"Accounting: logout: entry for NAS %s port %d has wrong ID",
					nas_name(nas_address), u.nas_port);
				r = -1;
				break;
			}

			if (status == PW_STATUS_START &&
			    strncmp(ut.session_id, u.session_id,
			     sizeof(u.session_id)) == 0  &&
			    u.time >= ut.time) {
				if (u.type == P_LOGIN) {
					radlog(L_INFO,
		"Accounting: login: entry for NAS %s port %d duplicate",
					nas_name(nas_address), u.nas_port);
					r = -1;
					break;
				}
				radlog(L_ERR,
		"Accounting: login: entry for NAS %s port %d wrong order",
				nas_name(nas_address), u.nas_port);
				r = -1;
				break;
			}

			/*
			 *	FIXME: the ALIVE record could need
			 *	some more checking, but anyway I'd
			 *	rather rewrite this mess -- miquels.
			 */
			if (status == PW_STATUS_ALIVE &&
			    strncmp(ut.session_id, u.session_id,
			     sizeof(u.session_id)) == 0  &&
			    u.type == P_LOGIN) {
				/*
				 *	Keep the original login time.
				 */
				ut.time = u.time;
				if (u.login[0] != 0)
					just_an_update = 1;
			}

			if (lseek(fd, -(off_t)sizeof(u), SEEK_CUR) < 0) {
				radlog(L_ERR, "Accounting: negative lseek!\n");
				lseek(fd, (off_t)0, SEEK_SET);
				off = 0;
			} else
				off -= sizeof(u);
			r = 1;
			break;
		}

		if (r >= 0 &&  (status == PW_STATUS_START ||
				status == PW_STATUS_ALIVE)) {
			if (cache == NULL) {
				cache = rad_malloc(sizeof(NAS_PORT));
				cache->nasaddr = ut.nas_address;
				cache->port = ut.nas_port;
				cache->offset = off;
				cache->next = nas_port_list;
				nas_port_list = cache;
			}
			ut.type = P_LOGIN;
			write(fd, &ut, sizeof(u));
		}
		if (status == PW_STATUS_STOP) {
			if (r > 0) {
				u.type = P_IDLE;
				u.time = ut.time;
				u.delay = ut.delay;
				write(fd, &u, sizeof(u));
			} else if (r == 0) {
				radlog(L_ERR,
		"Accounting: logout: login entry for NAS %s port %d not found",
				nas_name(nas_address), ut.nas_port);
				r = -1;
			}
		}
		close(fd);
	} else {
		radlog(L_ERR, "Accounting: %s: %s", RADUTMP, strerror(errno));
		ret = -1;
	}

	return ret;
}


/*
 *	Timeout handler (10 secs)
 */
static int got_alrm;
static void alrm_handler(int sig)
{
	sig = sig; /* -Wunused */
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

/*
 *	See if a user is already logged in.
 *
 *	Check twice. If on the first pass the user exceeds his
 *	max. number of logins, do a second pass and validate all
 *	logins by querying the terminal server (using eg. SNMP).
 *
 *	Returns: 0 == OK, 1 == double logins, 2 == multilink attempt
 */
int radutmp_checksimul(char *name, VALUE_PAIR *request, int maxsimul)
{
	VALUE_PAIR	*fra;
	struct radutmp	u;
	uint32_t	ipno = 0;
	int		fd;
	int		count;
	int		mpp = 1;
	int		rcode;

	if ((fd = open(RADUTMP, O_CREAT|O_RDWR, 0644)) < 0)
		return 0;

	/*
	 *	We don't lock in the first pass.
	 */
	count = 0;
	while(read(fd, &u, sizeof(u)) == sizeof(u))
		if (strncmp(name, u.login, RUT_NAMESIZE) == 0
		    && u.type == P_LOGIN)
			count++;

	if (count < maxsimul) {
		close(fd);
		return 0;
	}
	lseek(fd, (off_t)0, SEEK_SET);

	/*
	 *	Setup some stuff, like for MPP detection.
	 */
	if ((fra = pairfind(request, PW_FRAMED_IP_ADDRESS)) != NULL)
		ipno = fra->lvalue;

	radutmp_lock(fd);

	/*
	 *	Allright, there are too many concurrent logins.
	 *	Check all registered logins by querying the
	 *	terminal server directly.
	 *	FIXME: rad_check_ts() runs with locked radutmp file!
	 */
	count = 0;
	while (read(fd, &u, sizeof(u)) == sizeof(u)) {
		if (strncmp(name, u.login, RUT_NAMESIZE) == 0
		    && u.type == P_LOGIN) {
			char session_id[sizeof u.session_id+1];
			strNcpy(session_id, u.session_id, sizeof session_id);

			/*
			 *	rad_check_ts may take seconds to return,
			 *	and we don't want to block everyone else
			 *	while that's happening.
			 */
			radutmp_unlock(fd);
			rcode = rad_check_ts(u.nas_address, u.nas_port,
					     u.login, session_id);
			radutmp_lock(fd);

			if (rcode == 1) {
				count++;
				/*
				 *	Does it look like a MPP attempt?
				 */
				if (strchr("SCPA", u.proto) &&
				    ipno && u.framed_address == ipno)
					mpp = 2;
			}
			else {
				/*
				 *	False record - zap it.
				 */

				lseek(fd, -(off_t)sizeof(u), SEEK_CUR);
				u.type = P_IDLE;
				write(fd, &u, sizeof(u));

#if 0 /* FIXME: should we fixup radwtmp as well or not ? */
				if ((wfp = fopen(RADWTMP, "a")) != NULL) {
					make_wtmp(&u, &wt, PW_STATUS_STOP);
					fwrite(&wt, sizeof(wt), 1, wfp);
					fclose(wfp);
				}
#endif
			}
		}
	}
	close(fd);

	return (count < maxsimul) ? 0 : mpp;
}

