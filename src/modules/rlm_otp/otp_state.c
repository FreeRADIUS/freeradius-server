/*
 * otp_state.c	
 * $Id$
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
 * Copyright 2005 Frank Cusack
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#ifdef __linux__
#include <sys/un.h>
#endif

#include "otp.h"
#include "otp_state.h"

static const char rcsid[] = "$Id$";


/* state manager fd for PAM */
#if defined(PAM)
static int lsmd_fd = -1;
#endif

/*
 * lock and retrieve state for a user
 * returns 0 on success (but state may be empty!), -1 on failure
 */
int
otp_state_get(const otp_option_t *opt, const char *username,
	      otp_user_state_t *user_state, const char *log_prefix)
{
    int *fdp;
    char buf[1024];	/* state manager max len */
    int buflen;

    fdp = otp_state_getfd(opt, log_prefix);
    if (*fdp == -1)
	return *fdp;

    user_state->fdp = fdp;
    (void) sprintf(buf, "G %s", username);	/* safe */
    if (xwrite(fdp, buf, strlen(buf) + 1, log_prefix) == -1)
	return -1;
    if ((buflen = xread(fdp, buf, sizeof(buf), log_prefix)) == -1)
	return -1;
    if (otp_state_parse(buf, buflen, username, user_state, log_prefix) == -1)
	return -1;

    return 0;
}


/*
 * update and release state for a user
 * returns 0 on success, -1 on failure
 */
int
otp_state_put(const char *username, otp_user_state_t *user_state,
	      const char *log_prefix)
{
    char buf[1024];	/* state manager max len */
    int rc = 0;
    ssize_t len;
    size_t ulen = strlen(username);

    if (!user_state->locked)
	return 0;

    if ((len = otp_state_unparse(buf, sizeof(buf), username, user_state,
				log_prefix)) == -1) {
	rc = -1;
	goto putfd;
    }
    if ((rc = xwrite(user_state->fdp, buf, len, log_prefix)) == -1)
	goto putfd;
    if ((len = xread(user_state->fdp, buf, sizeof(buf), log_prefix)) == -1) {
	rc = -1;
	goto putfd;
    }

    /* validate the state manager response */
    if (len < 3 + ulen) {
	otp_log(OTP_LOG_ERR, "%s: state manager invalid PUT response for [%s]",
		log_prefix, username);
	rc = -1;
	goto putfd;
    }
    if (!((buf[0] == 'A' || buf[0] == 'N') && buf[1] == ' ' &&
	  !strncmp(username, &buf[2], ulen) &&
	  (buf[ulen + 2] == ' ' || buf[ulen + 2] == '\0'))) {
	otp_log(OTP_LOG_ERR, "%s: state manager invalid PUT response for [%s]",
		log_prefix, username);
	rc = -1;
	goto putfd;
    }
    if (buf[0] == 'N') {
	char *reason;

	if (buf[ulen + 2] == '\0')
	    reason = "[no reason given]";
	else
	    reason = &buf[ulen + 2];
	otp_log(OTP_LOG_ERR, "%s: state manager PUT rejected for [%s]: %s",
		log_prefix, username, reason);
	rc = -1;
	goto putfd;
    }

putfd:
    otp_state_putfd(user_state->fdp, 0);
    return rc;
}


/*
 * Parse the state manager response into user_state.
 * Returns 0 on success, -1 on failure.
 * "Put"s state (releases lock, without update) on failure.
 */
static int
otp_state_parse(const char *buf, size_t buflen, const char *username,
		otp_user_state_t *user_state, const char *log_prefix)
{
    size_t i;
    char *p, *q;

    /* sanity checks */
    if (!buflen) {
	otp_log(OTP_LOG_ERR, "%s: no state for [%s]",
		log_prefix, username);
	otp_state_putfd(user_state->fdp, 0);
	return -1;
    }
    /*
     * This guarantees there is a char after strchr(p, ':'),
     * and that our 'q = strchr(p, ':'); *q++ = '\0', p = q;'
     * idiom works (there is always a char after the ':').
     */
    if (buf[buflen - 1] != '\0') {
	otp_log(OTP_LOG_ERR, "%s: invalid state for [%s]",
		log_prefix, username);
	otp_state_putfd(user_state->fdp, 0);
	return -1;
    }

    /* Is this an ack or a nak? */
    if (!(buf[0] == 'A' && buf[1] == ' ')) {
	otp_log(OTP_LOG_INFO /* ERR? */, "%s: unable to lock state for [%s]",
		log_prefix, username);
	otp_state_putfd(user_state->fdp, 0);
	return -1;
    }
    user_state->locked = 1;
    user_state->updated = 0;	/* just release lock on failures */

    /*
     * NOTE: Currently we do not support null state.
     * We don't do bounds checking for initial parsing,
     * so state manager response must contain at least
     * - ACK/NAK code + ' '
     * - username + ' '
     * - version + ':'
     * - username + ':'
     * - challenge + terminator.
     * Beginning with the challenge we use strchr() and need
     * no further bounds checking.
     */
    i = strlen(username);
    /* 'A <username> V:<username>:C' + terminator */
    if (buflen < 2 + i + 3 + i + 2 + 1) {
	if (buflen < 2 + i + 1)
	    otp_log(OTP_LOG_ERR, "%s: invalid state data for [%s]",
		    log_prefix, username);
	else if (buflen == 2 + i + 1)
	    otp_log(OTP_LOG_ERR, "%s: null state data for [%s]",
		    log_prefix, username);
	else
	    otp_log(OTP_LOG_ERR, "%s: short state data for [%s]",
		    log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    p = (char *) &buf[2];

    /* verify username (in state manager response, not state itself) */
    if (!(strncmp(p, username, i) == 0 && p[i] == ' ')) {
	otp_log(OTP_LOG_ERR, "%s: state manager username mismatch for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    p += i;	/* space after username */
    p += 1;	/* beginning of state */

    /* version */
    if (!(p[0] == '2' && p[1] == ':')) {
	otp_log(OTP_LOG_ERR, "%s: state data unacceptable version for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    p += 2;	/* username */

    /* sanity check username */
    if (!(strncmp(p, username, i) == 0 && p[i] == ':')) {
	otp_log(OTP_LOG_ERR, "%s: state data username mismatch for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    p += i;	/* challenge */

    /* extract challenge */
    if ((q = strchr(p, ':')) == NULL) {
	otp_log(OTP_LOG_ERR, "%s: state data invalid challenge for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    *q++ = '\0';
    if (strlen(p) > OTP_MAX_CHALLENGE_LEN) {
	otp_log(OTP_LOG_ERR, "%s: state data challenge too long for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    (void) strcpy(user_state->challenge, p);
    p = q;	/* csd */

    /* extract csd */
    if ((q = strchr(p, ':')) == NULL) {
	otp_log(OTP_LOG_ERR, "%s: state data invalid csd for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    *q++ = '\0';
    if (strlen(p) > OTP_MAX_CSD_LEN) {
	otp_log(OTP_LOG_ERR, "%s: state data csd too long for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    (void) strcpy(user_state->csd, p);
    p = q;	/* failcount */

    /* extract failcount */
    if ((q = strchr(p, ':')) == NULL) {
	otp_log(OTP_LOG_ERR, "%s: state data invalid failcount for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    *q++ = '\0';
    if (sscanf(p, "%u", &user_state->failcount) != 1) {
	otp_log(OTP_LOG_ERR, "%s: state data invalid failcount for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    p = q;	/* authtime */

    /* extract authtime */
    if ((q = strchr(p, ':')) == NULL) {
	otp_log(OTP_LOG_ERR, "%s: state data invalid authtime for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    *q++ = '\0';
    /* breaks if time_t is not long */
    if (sscanf(p, "%ld", &user_state->authtime) != 1) {
	otp_log(OTP_LOG_ERR, "%s: state data invalid authtime for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }
    p = q;	/* authpos */

    /* extract authpos */
    if (sscanf(p, "%d", &user_state->authpos) != 1) {
	otp_log(OTP_LOG_ERR, "%s: state data invalid authpos for [%s]",
		log_prefix, username);
	(void) otp_state_put(username, user_state, log_prefix);
	return -1;
    }

    return 0;
}

/*
 * Format user_state into a state manager update request.
 * Returns new (filled) buflen on success, -1 on failure.
 */
static ssize_t
otp_state_unparse(char *buf, size_t buflen, const char *username,
		  otp_user_state_t *user_state, const char *log_prefix)
{
    size_t len;

    /* perhaps this isn't our job, but it's safe */
    if (!user_state->locked)
	return -1;

    (void) snprintf(buf, buflen, "U %s 2:%s:%s:%s:%u:%ld:%d",
		    username, username, user_state->challenge, user_state->csd,
		    user_state->failcount, user_state->authtime,
		    user_state->authpos);
    buf[buflen - 1] = '\0';
    if ((len = strlen(buf) + 1) == buflen) {
	/*
	 * Short by one, but the best we can do b/c of different snprintf()'s
	 * without a lot of work.  Guaranteed anyway, due to small max
	 * username, challenge, csd len's, assuming maximally (1024) sized buf.
	 */
	otp_log(OTP_LOG_ERR, "%s: state data (unparse) too long for [%s]",
		log_prefix, username);
	return -1;
    }

    return len;
}


/*
 * Full read with logging, and close on failure.
 * Returns nread on success, -1 on failure.
 * buf[nread - 1] is guaranteed to be '\0'.
 */
static int
xread(int *fdp, char *buf, size_t len, const char *log_prefix)
{
    ssize_t n;
    int nread = 0;	/* bytes read into buf */

    for (;;) {
	if ((n = read(*fdp, &buf[nread], len - nread)) == -1) {
	    if (errno == EAGAIN || errno == EINTR) {
		continue;
	    } else {
		otp_log(OTP_LOG_ERR, "%s: read from state manager: %s",
			log_prefix, strerror(errno));
		otp_state_putfd(fdp, 1);
		return -1;
	    }
	}
	if (!n) {
	    /* XXX Can this happen? */
	    otp_log(OTP_LOG_ERR, "%s: read 0 bytes from state manager",
		    log_prefix);
	    continue;
	}
	nread += n;

	/*
	 * was last byte a NUL? (pipelining is not possible,
	 * so we only need to check the last byte to find
	 * the message boundary)
	 */
	if (buf[nread - 1] == '\0')
	    return nread;
    } /* for (;;) */
}


/*
 * Full write with logging, and close on failure.
 * Returns 0 on success, -1 on failure.
 */
static int
xwrite(int *fdp, const char *buf, size_t len, const char *log_prefix)
{
    size_t nleft = len;
    ssize_t nwrote;

    while (nleft) {
	if ((nwrote = write(*fdp, &buf[len - nleft], nleft)) == -1) {
	    if (errno != EINTR) {
		otp_log(OTP_LOG_ERR, "%s: write to state manager: %s",
			log_prefix, strerror(errno));
		otp_state_putfd(fdp, 1);
		return -1;
	    }
	}
	nleft -= nwrote;
    }

    return 0;
}


#if defined(PAM)
/* retrieve fd (possibly opening a new one) to state manager */
static int *
otp_state_getfd(const otp_option_t *opt, const char *log_prefix)
{
    int *fdp = &lsmd_fd;
    struct sockaddr_un sa;
    int sp_len;			/* sun_path length (strlen) */

    /* return existing fd if open */
    if (*fdp != -1)
	return fdp;

    /* setup for unix domain socket */
    sp_len = strlen(opt->lsmd_rp);
    if (sp_len > sizeof(sa.sun_path) - 1) {
	otp_log(OTP_LOG_ERR, "%s: rendezvous point name too long", log_prefix);
	return fdp;
    }
    sa.sun_family = AF_UNIX;
    (void) strcpy(sa.sun_path, opt->lsmd_rp);
    
    /* connect to state manager */
    if ((*fdp = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
	otp_log(OTP_LOG_ERR, "%s: socket: %s", log_prefix, strerror(errno));
	return fdp;
    }
    if (connect(*fdp, (struct sockaddr *) &sa,
		sizeof(sa.sun_family) + sp_len) == -1) {
	otp_log(OTP_LOG_ERR, "%s: connect: %s", log_prefix, strerror(errno));
	(void) close(*fdp);
	*fdp = -1;
	return fdp;
    }

    /* success */
    return fdp;
}


/* disconnect from state manager */
static void
otp_state_putfd(int *fdp, int close_p)
{
    if (close_p) {
	(void) close(*fdp);
    }
    *fdp = -1;
}
#elif defined(FREERADIUS)
#endif /* FREERADIUS */
