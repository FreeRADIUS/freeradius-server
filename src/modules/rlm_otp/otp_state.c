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

#ifdef FREERADIUS
#ifndef _REENTRANT
#define _REENTRANT
#endif
#include <pthread.h>
#endif

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


#if defined(PAM)
/* a single fd (no pool) */
static lsmd_fd_t lsmd_fd = { .fd = -1 };
#elif defined(FREERADIUS)
/* pointer to head of fd pool */
static lsmd_fd_t *lsmd_fd_head;
static pthread_mutex_t lsmd_fd_head_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/*
 * lock and retrieve state for a user
 * returns 0 on success (but state may be empty!), -1 on failure
 */
int
otp_state_get(const otp_option_t *opt, const char *username,
	      otp_user_state_t *user_state, const char *log_prefix)
{
    lsmd_fd_t *fdp;
    char buf[1024];	/* state manager max len */
    int buflen;

    fdp = otp_state_getfd(opt, log_prefix);
    if (!fdp || fdp->fd == -1)
	return -1;

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
    p += i + 1;	/* challenge */

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

    if (user_state->updated)
	(void) snprintf(buf, buflen, "P %s 2:%s:%s:%s:%u:%ld:%d",
			username, username, user_state->challenge,
			user_state->csd, user_state->failcount,
			user_state->authtime, user_state->authpos);
    else
	(void) snprintf(buf, buflen, "P %s", username);
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
xread(lsmd_fd_t *fdp, char *buf, size_t len, const char *log_prefix)
{
    ssize_t n;
    int nread = 0;	/* bytes read into buf */

    for (;;) {
	if ((n = read(fdp->fd, &buf[nread], len - nread)) == -1) {
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
	    otp_log(OTP_LOG_ERR, "%s: state manager disconnect",
		    log_prefix);
	    otp_state_putfd(fdp, 1);
	    return -1;
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
xwrite(lsmd_fd_t *fdp, const char *buf, size_t len, const char *log_prefix)
{
    size_t nleft = len;
    ssize_t nwrote;

    while (nleft) {
	if ((nwrote = write(fdp->fd, &buf[len - nleft], nleft)) == -1) {
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


/* connect to state manager and return fd */
static int
otp_state_connect(const char *path, const char *log_prefix)
{
    int fd;
    struct sockaddr_un sa;
    int sp_len;			/* sun_path length (strlen) */

    /* setup for unix domain socket */
    sp_len = strlen(path);
    if (sp_len > sizeof(sa.sun_path) - 1) {
	otp_log(OTP_LOG_ERR, "%s: rendezvous point name too long", log_prefix);
	return -1;
    }
    sa.sun_family = AF_UNIX;
    (void) strcpy(sa.sun_path, path);
    
    /* connect to state manager */
    if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
	otp_log(OTP_LOG_ERR, "%s: socket: %s", log_prefix, strerror(errno));
	return -1;
    }
    if (connect(fd, (struct sockaddr *) &sa,
		sizeof(sa.sun_family) + sp_len) == -1) {
	otp_log(OTP_LOG_ERR, "%s: connect: %s", log_prefix, strerror(errno));
	(void) close(fd);
	return -1;
    }
    return fd;
}


#if defined(PAM)
/* retrieve fd (possibly opening a new one) to state manager */
static lsmd_fd_t *
otp_state_getfd(const otp_option_t *opt, const char *log_prefix)
{
    lsmd_fd_t *fdp = &lsmd_fd;

    /* return existing fd if open */
    if (fdp->fd != -1)
	return fdp;

    fdp->fd = otp_state_connect(opt->lsmd_rp, log_prefix);
    return fdp;
}


/* disconnect from state manager */
static void
otp_state_putfd(lsmd_fd_t *fdp, int close_p)
{
    /* for PAM we always close the fd; leaving it open is a leak */
    (void) close(fdp->fd);
    fdp->fd = -1;
}

#elif defined(FREERADIUS)
/*
 * Retrieve fd (from pool) to state manager.
 * It'd be simpler to use TLS but FR can have lots of threads
 * and we don't want to waste fd's that way.
 * We can't have a global fd because we'd then be pipelining
 * requests to the state manager and we have no way to demultiplex
 * the responses.
 */
static lsmd_fd_t *
otp_state_getfd(const otp_option_t *opt, const char *log_prefix)
{
    int rc;
    lsmd_fd_t *fdp;

    /* walk the connection pool looking for an available fd */
    for (fdp = lsmd_fd_head; fdp; fdp = fdp->next) {
	rc = pthread_mutex_trylock(&fdp->mutex);
        if (!rc)
	    break;
	if (rc != EBUSY) {
	    otp_log(OTP_LOG_ERR, "%s: pthread_mutex_trylock: %s", log_prefix,
		    strerror(errno));
	    return NULL;
	}
    }

    if (!fdp) {
	/* no fd was available, add a new one */
	if ((rc = pthread_mutex_lock(&lsmd_fd_head_mutex))) {
	    otp_log(OTP_LOG_ERR, "%s: pthread_mutex_lock: %s", log_prefix,
		    strerror(errno));
	    return NULL;
	}
	fdp = rad_malloc(sizeof(*fdp));
	if ((rc = pthread_mutex_init(&fdp->mutex, NULL))) {
	    otp_log(OTP_LOG_ERR, "%s: pthread_mutex_init: %s", log_prefix,
		    strerror(errno));
	    free(fdp);
	    return NULL;
	}
	if ((rc = pthread_mutex_lock(&fdp->mutex))) {
	    otp_log(OTP_LOG_ERR, "%s: pthread_mutex_lock: %s", log_prefix,
		    strerror(errno));
	    free(fdp);
	    return NULL;
	}
	fdp->next = lsmd_fd_head;
	lsmd_fd_head = fdp;
	if ((rc = pthread_mutex_unlock(&lsmd_fd_head_mutex))) {
	    otp_log(OTP_LOG_ERR, "%s: pthread_mutex_unlock: %s", log_prefix,
		    strerror(errno));
	    /* deadlock */
	    exit(1);
	}
	fdp->fd = otp_state_connect(opt->lsmd_rp, log_prefix);
    }

    return fdp;
}

/* disconnect from state manager */
static void
otp_state_putfd(lsmd_fd_t *fdp, int close_p)
{
    int rc;

    /* close fd (used for errors) */
    if (close_p) {
	(void) close(fdp->fd);
	fdp->fd = -1;
    }
    /* make connection available to another thread */
    if ((rc = pthread_mutex_unlock(&fdp->mutex))) {
	otp_log(OTP_LOG_ERR, "%s: pthread_mutex_unlock: %s", log_prefix,
		strerror(errno));
	/* lost fd */
	exit(1);
    }
}
#endif /* FREERADIUS */
