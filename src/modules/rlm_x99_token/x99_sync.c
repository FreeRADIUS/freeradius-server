/*
 * x99_sync.c
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
 * Copyright 2001,2002  Google, Inc.
 */

#ifdef FREERADIUS
#include "autoconf.h"
#include "libradius.h"
#include "radiusd.h"
#endif
#include "x99.h"
#include "x99_sync.h"

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/des.h> /* des_cblock */

static const char rcsid[] = "$Id$";


/*
 * Get sync data for a given user.
 * Returns 0 on success, non-zero otherwise.
 *
 * username:  duh
 * card_id:   duh
 * ewin:      event window position (0 == now)
 * twin:      time window position (0 == now) (NOT IMPLEMENTED)
 * challenge: On successful return it will be filled in with the challenge
 *            expected for the given window slot.  On unsuccesful return,
 *            challenge may be overwritten and contain garbage.
 *            If ewin == 0, the stored "ewin 0" value is returned.
 *            If ewin > 0 and challenge points to a non-empty string, it
 *               will be taken as the challenge for (ewin - 1).  That is,
 *               ewin will not be used to calculate the next challenge;
 *               instead the passed in challenge is run through the sync
 *               calculation once to arrive at the next challenge.  This
 *               speeds things up since we don't have to iterate ewin times.
 *            If ewin > 0 and challenge points to an empty string, the
 *               stored "ewin 0" challenge value is run through the sync
 *               calculation ewin times. (NOT IMPLEMENTED)
 * keyblock:  Similar to challenge.  It may be updated for key changing
 *            sync modes. (NOT IMPLEMENTED)
 */
int
x99_get_sync_data(const char *syncdir, const char *username,
		  uint32_t card_id, int ewin, int twin,
		  char challenge[MAX_CHALLENGE_LEN + 1], des_cblock keyblock)
{
    /* ARGSUSED */
    des_cblock output;
    int i, rc;
    char *lock;

    if ((lock = x99_acquire_sd_lock(syncdir, username)) == NULL)
	return -1;

    if (ewin == 0) {
	rc = x99_get_sd(syncdir, username, challenge, NULL, NULL);

    } else if (challenge[0]) {
	if (card_id & X99_CF_CRYPTOCARD) {
	    if ((rc = x99_mac(challenge, output, keyblock)) == 0) {
		for (i = 0; i < 8; ++i) {
		    output[i] &= 0x0f;
		    if (output[i] > 9)
			output[i] -= 10;
		    output[i] |= 0x30;
		}
		(void) memcpy(challenge, output, 8);
		challenge[8] = '\0';
	    }
	} else {
	    /* No other vendors implemented yet. */
	    rc =-1;
	}

    } else {
	/* The hard way.  Might need to implement this someday. */
	rc = -1;
    }
    x99_release_sd_lock(lock);
    return rc;
}

/*
 * Set sync data for a given user.
 * Returns 0 on success, non-zero otherwise.
 * Side effects:
 * - Resets failure count to 0 on successful return.
 * - Sets last auth time to "now" on successful return.
 * Because of the failure count reset, this should only be called for/after
 * successful authentications.
 *
 * username:  duh
 * challenge: The challenge to be stored.
 * keyblock:  The key to be stored.  This is for sync modes in which the
 *            key changes for successive challenges. (NOT IMPLEMENTED)
 */
int
x99_set_sync_data(const char *syncdir, const char *username,
		  const char *challenge, const des_cblock keyblock)
{
    /* ARGSUSED */
    int rc;
    char *lock;

    if ((lock = x99_acquire_sd_lock(syncdir, username)) == NULL)
	return -1;

    rc = x99_set_sd(syncdir, username, challenge, 0, time(NULL));
    x99_release_sd_lock(lock);
    return rc;
}


/*
 * Return the last time the user authenticated.
 * Returns 0 on success, non-zero otherwise.
 */
int
x99_get_last_auth(const char *syncdir, const char *username, time_t *last_auth)
{
    int rc;
    char *lock;

    if ((lock = x99_acquire_sd_lock(syncdir, username)) == NULL)
	return -1;
    rc = x99_get_sd(syncdir, username, NULL, NULL, last_auth);
    x99_release_sd_lock(lock);
    return rc;
}

/*
 * Set the last auth time for a user to "now".
 * Returns 0 on success, non-zero otherwise.
 * Note that x99_set_sync_data() also resets the auth time.
 * This function is no longer called, (the failcount() routines do this work),
 * but I'm saving it here for reference.
 */
int
x99_upd_last_auth(const char *syncdir, const char *username)
{
    int failcount, rc;
    char *lock;
    char challenge[MAX_CHALLENGE_LEN + 1];

    if ((lock = x99_acquire_sd_lock(syncdir, username)) == NULL)
	return -1;

    rc = x99_get_sd(syncdir, username, challenge, &failcount, NULL);
    if (rc == 0)
	rc = x99_set_sd(syncdir, username, challenge, failcount, time(NULL));

    x99_release_sd_lock(lock);
    return rc;
}


/*
 * Atomically increment a user's failed login count.
 * Also updates last_auth.
 */
int
x99_incr_failcount(const char *syncdir, const char *username)
{
    int failcount, rc;
    char *lock;
    char challenge[MAX_CHALLENGE_LEN + 1];

    if ((lock = x99_acquire_sd_lock(syncdir, username)) == NULL)
	return -1;

    /* Get current value. */
    rc = x99_get_sd(syncdir, username, challenge, &failcount, NULL);
    if (rc == 0) {
	/* Increment. */
	if (++failcount == INT_MAX)
	    failcount--;
	rc = x99_set_sd(syncdir, username, challenge, failcount, time(NULL));
    }

    x99_release_sd_lock(lock);
    return rc;
}

/*
 * Reset failure count to 0.  Also updates last_auth.
 * Returns 0 on success, non-zero otherwise.
 * This is almost just like x99_incr_failcount().
 * x99_set_sync_data() resets the failcount also, but that's because
 * we keep the failcount and other sync data together; we don't want
 * to necessarily make that visible to our callers (x99_rlm.c).
 */
int
x99_reset_failcount(const char *syncdir, const char *username)
{
    int rc;
    char *lock;
    char challenge[MAX_CHALLENGE_LEN + 1];

    if ((lock = x99_acquire_sd_lock(syncdir, username)) == NULL)
	return -1;

    rc = x99_get_sd(syncdir, username, challenge, NULL, NULL);
    if (rc == 0)
	rc = x99_set_sd(syncdir, username, challenge, 0, time(NULL));

    x99_release_sd_lock(lock);
    return rc;
}


/*
 * checks the failure counter.
 * returns 0 if the user is allowed to authenticate, -1 otherwise.
 * caller does not need to log failures, we do it.
 */
int
x99_check_failcount(const char *username, const x99_token_t *inst)
{
    time_t last_auth;
    int failcount;

    if (x99_get_last_auth(inst->syncdir, username, &last_auth) != 0) {
	x99_log(X99_LOG_ERR,
		"auth: unable to get last auth time for [%s]", username);
	return -1;
    }
    if (x99_get_failcount(inst->syncdir, username, &failcount) != 0) {
	x99_log(X99_LOG_ERR,
		"auth: unable to get failure count for [%s]", username);
	return -1;
    }

    /* Check against hardfail setting. */
    if (inst->hardfail && failcount >= inst->hardfail) {
	x99_log(X99_LOG_AUTH,
		"auth: %d/%d failed/max authentications for [%s]",
		failcount, inst->hardfail, username);
	if (x99_incr_failcount(inst->syncdir, username) != 0) {
	    x99_log(X99_LOG_ERR,
		    "auth: unable to increment failure count for "
		    "locked out user [%s]", username);
	}
	return -1;
    }

    /* Check against softfail setting. */
    if (failcount >= inst->softfail) {
	time_t when;
	int fcount;

	/*
	 * Determine the next time this user can authenticate.
	 *
	 * Once we hit softfail, we introduce a 1m delay before the user
	 * can authenticate.  For each successive failed authentication,
	 * we double the delay time, up to a max of 32 minutes.  While in
	 * the "delay mode" of operation, all authentication ATTEMPTS are
	 * considered failures (we don't test if the password is correct).
	 * Also, each attempt during the delay period restarts the clock.
	 *
	 * The advantage of a delay instead of a simple lockout is that an
	 * attacker can't lock out a user as easily; the user need only wait
	 * a bit before he can authenticate.
	 */
	fcount = failcount - inst->softfail;
	when = last_auth + (fcount > 5 ? 32 * 60 : (1 << fcount) * 60);
	if (time(NULL) < when) {
	    x99_log(X99_LOG_AUTH,
		    "auth: user [%s] auth too soon while delayed, "
		    "%d/%d failed/softfail authentications",
		    username, failcount, inst->softfail);
	    if (x99_incr_failcount(inst->syncdir, username) != 0) {
		x99_log(X99_LOG_ERR,
			"auth: unable to increment failure count for "
			"delayed user [%s]", username);
	    }
	    return -1;
	}
    }

}


/*
 * Return the failed login count and last auth time for a user.
 * Returns 0 on success, non-zero otherwise.
 */
static int
x99_get_failcount(const char *syncdir, const char *username, int *failcount)
{
    int rc;
    char *lock;

    if ((lock = x99_acquire_sd_lock(syncdir, username)) == NULL)
	return -1;
    rc = x99_get_sd(syncdir, username, NULL, failcount, NULL);
    x99_release_sd_lock(lock);
    return rc;
}


/*
 * Sync data is kept in a flat file[s], only because it's easy to implement.
 * It might be worth looking at Berkeley DB, but the flat file implementation
 * gives maximal concurrency with minimal complexity.  Performance will be
 * better on filesystems like ext2fs, ffs w/ soft updates, etc, due to
 * the large number of ephemeral dot-files created/destroyed for locking.
 *
 * One file per user is created, and we typically expect that each thread
 * is handling a different user (even if a user is authenticating to
 * multiple NASs/ports, he can't really authenticate simultaneously to
 * each -- unless it's an attack), so this should give us maximal
 * concurrency.
 *
 * The file format is 'version:user:challenge:key:failures:last_auth:'.
 * Version is there to provide easy forward compatibility.  The trailing
 * colon is there for the same reason.  Future versions must add data to
 * the end.  The current version is 1.
 *
 * For performance enhancements, it might be more worthwhile to look at
 * caching the inst->pwdfile data.  Users who are disabled should also
 * be cached somehow, to reduce the impact of possible attacks.
 */


/*
 * x99_acquire_sd_lock() returns NULL on failure, or a char *
 * which must be passed to x99_release_sd_lock() later.
 */
static char *
x99_acquire_sd_lock(const char *syncdir, const char *username)
{
    char *lockfile;
    int i, fd = -1;
    struct stat st;

    /* Verify permissions first. */
    if (stat(syncdir, &st) != 0) {
	x99_log(X99_LOG_ERR, "syncdir %s error: %s",
		syncdir, strerror(errno));
	return NULL;
    }
    if (st.st_mode != (S_IFDIR|S_IRUSR|S_IWUSR|S_IXUSR)) {
	x99_log(X99_LOG_ERR, "syncdir %s has loose permissions", syncdir);
	return NULL;
    }

    /* We use dotfile locking. */
    lockfile = rad_malloc(strlen(syncdir) + strlen(username) + 3);
    (void) sprintf(lockfile, "%s/.%s", syncdir, username);

    /*
     * Try to obtain exclusive access.  10 should be *plenty* of
     * iterations, we don't expect concurrent accesses to the same file,
     * and any accesses should be very quick.  This is broken over NFS,
     * but you shouldn't have this data on NFS anyway.
     */
    for (i = 0; i < 10; ++i) {
	if ((fd = open(lockfile, O_CREAT|O_EXCL, S_IRUSR|S_IWUSR)) != -1) {
	    break;
	}
	/* FIXME: does usleep() reset/generate SIGALRM on any systems? */
	usleep(500000); /* 0.5 second */
    }
    if (fd == -1) {
	x99_log(X99_LOG_ERR,
		"x99_acquire_sd_lock: unable to acquire lock for [%s]",
		username);
	free(lockfile);
	return NULL;
    }

    (void) close(fd);
    return lockfile;
}

static void
x99_release_sd_lock(char *lockfile)
{
    (void) unlink(lockfile);
    free(lockfile);
}


/*
 * x99_get_sd() returns 0 on success, non-zero otherwise.
 * On successful returns, challenge, failures and last_auth are filled in,
 * if non-NULL.
 * On unsuccessful returns, challenge, failures and last_auth may be garbage.
 * challenge should be sized as indicated (if non-NULL).
 * The caller must have obtained an exclusive lock on the sync file.
 */
static int
x99_get_sd(const char *syncdir, const char *username,
	   char challenge[MAX_CHALLENGE_LEN + 1], int *failures,
	   time_t *last_auth)
{
    char syncfile[PATH_MAX + 1];
    FILE *fp;

    char syncdata[BUFSIZ];
    char *p, *q;

    (void) snprintf(syncfile, PATH_MAX, "%s/%s",  syncdir, username);
    syncfile[PATH_MAX] = '\0';

    /* Open sync file. */
    if ((fp = fopen(syncfile, "r")) == NULL) {
	if (errno != ENOENT) {
	    x99_log(X99_LOG_ERR, "x99_get_sd: unable to open sync file %s: %s",
		    syncfile, strerror(errno));
	    return -1;
	}
	/*
	 * Sync file did not exist.  If we can create it, all is well.
	 * Set the challenge to something "impossible".
	 */
	if (failures)
	    *failures = 0;
	return x99_set_sd(syncdir, username, "NEWSTATE", 0, 0);
    }

    /* Read sync data. */
    if ((fgets(syncdata, sizeof(syncdata), fp) == NULL) || !strlen(syncdata)) {
	x99_log(X99_LOG_ERR, "x99_get_sd: unable to read sync data from %s: %s",
		syncfile, strerror(errno));
	(void) fclose(fp);
	return -1;
    }
    (void) fclose(fp);
    p = syncdata;

    /* Now, parse the sync data. */
    /* Eat the version. */
    if ((p = strchr(p, ':')) == NULL) {
	x99_log(X99_LOG_ERR,
		"x99_get_sd: invalid sync data for user %s", username);
	return -1;
    }
    p++;

    /* Sanity check the username. */
    if ((q = strchr(p, ':')) == NULL) {
	x99_log(X99_LOG_ERR,
		"x99_get_sd: invalid sync data for user %s", username);
	return -1;
    }
    *q++ = '\0';
    if (strcmp(p, username)) {
	x99_log(X99_LOG_ERR,
		"x99_get_sd: sync data user mismatch for user %s", username);
	return -1;
    }
    p = q;

    /* Get challenge. */
    if ((q = strchr(p, ':')) == NULL) {
	x99_log(X99_LOG_ERR,
		"x99_get_sd: invalid sync data (challenge) for user %s",
		username);
	return -1;
    }
    *q++ = '\0';
    if (strlen(p) > MAX_CHALLENGE_LEN) {
	x99_log(X99_LOG_ERR,
		"x99_get_sd: invalid sync data (challenge length) for user %s",
		username);
	return -1;
    }
    if (challenge)
	strcpy(challenge, p);
    p = q;

    /* Eat key. */
    if ((p = strchr(p, ':')) == NULL) {
	x99_log(X99_LOG_ERR,
		"x99_get_sd: invalid sync data (key) for user %s", username);
	return -1;
    }
    p++;

    /* Get failures. */
    if ((q = strchr(p, ':')) == NULL) {
	x99_log(X99_LOG_ERR,
		"x99_get_sd: invalid sync data (failures) for user %s",
		username);
	return -1;
    }
    *q++ = '\0';
    if (failures && (sscanf(p, "%d", failures) != 1)) {
	x99_log(X99_LOG_ERR,
		"x99_get_sd: invalid sync data (failures) for user %s",
		username);
	return -1;
    }
    p = q;

    /* Get last_auth. */
    if ((q = strchr(p, ':')) == NULL) {
	x99_log(X99_LOG_ERR,
		"x99_get_sd: invalid sync data (last_auth) for user %s",
		username);
	return -1;
    }
    *q++ = '\0';
    if (last_auth && (sscanf(p, "%ld", last_auth) != 1)) {
	x99_log(X99_LOG_ERR,
		"x99_get_sd: invalid sync data (last_auth) for user %s",
		username);
	return -1;
    }

    return 0;
}


/*
 * See x99_get_sd().
 * The caller must have obtained an exclusive lock on the sync file.
 */
static int
x99_set_sd(const char *syncdir, const char *username,
	   const char *challenge, int failures, time_t last_auth)
{
    char syncfile[PATH_MAX + 1];
    FILE *fp;

    (void) snprintf(syncfile, PATH_MAX, "%s/%s",  syncdir, username);
    syncfile[PATH_MAX] = '\0';

    if ((fp = fopen(syncfile, "w")) == NULL) {
	x99_log(X99_LOG_ERR, "x99_set_sd: unable to open sync file %s: %s",
		syncfile, strerror(errno));
	return -1;
    }

    /* Write our (version 1) sync data. */
    (void) fprintf(fp, "1:%s:%s:%s:%d:%ld:\n", username, challenge, "",
		   failures, last_auth);
    if (fclose(fp) != 0) {
	x99_log(X99_LOG_ERR, "x99_set_sd: unable to write sync file %s: %s",
		syncfile, strerror(errno));
	return -1;
    }

    return 0;
}

