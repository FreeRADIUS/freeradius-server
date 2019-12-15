/*
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
 */

/**
 * $Id$
 *
 * @file lib/server/main_loop.c
 * @brief Creates a global event loop, and manages signalling between the forked child
 *	and its parent as the server starts.
 *
 * @copyright 2012 The FreeRADIUS server project
 * @copyright 2012 Alan DeKok (aland@deployingradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/main_loop.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/server/trigger.h>
#include <freeradius-devel/server/util.h>

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/syserror.h>

#include <signal.h>
#include <fcntl.h>

#ifdef HAVE_SYS_WAIT_H
#  include <sys/wait.h>
#endif

extern pid_t			radius_pid;
static bool			just_started = true;
static fr_event_list_t		*event_list = NULL;
static int			self_pipe[2] = { -1, -1 };

#ifdef HAVE_SYSTEMD_WATCHDOG
#include <systemd/sd-daemon.h>

static fr_time_delta_t		sd_watchdog_interval;
static fr_event_timer_t		const *sd_watchdog_ev;

/** Reoccurring watchdog event to inform systemd we're still alive
 *
 * Note actually a very good indicator of aliveness as the main event
 * loop doesn't actually do any packet processing.
 */
static void sd_watchdog_event(fr_event_list_t *our_el, UNUSED fr_time_t now, void *ctx)
{
	DEBUG("Emitting systemd watchdog notification");

	sd_notify(0, "WATCHDOG=1");

	if (fr_event_timer_in(NULL, our_el, &sd_watchdog_ev,
			      sd_watchdog_interval,
			      sd_watchdog_event, ctx) < 0) {
		ERROR("Failed to insert watchdog event");
	}
}
#endif

static void handle_signal_self(int flag)
{
	if ((flag & (RADIUS_SIGNAL_SELF_EXIT | RADIUS_SIGNAL_SELF_TERM)) != 0) {
		if ((flag & RADIUS_SIGNAL_SELF_EXIT) != 0) {
			INFO("Signalled to exit");
			fr_event_loop_exit(event_list, 1);
		} else {
			INFO("Signalled to terminate");
			fr_event_loop_exit(event_list, 2);
		}

		return;
	} /* else exit/term flags weren't set */

	/*
	 *	Tell the even loop to stop processing.
	 */
	if ((flag & RADIUS_SIGNAL_SELF_HUP) != 0) {
		time_t when;
		static time_t last_hup = 0;

		when = time(NULL);
		if ((int) (when - last_hup) < 5) {
			INFO("Ignoring HUP (less than 5s since last one)");
			return;
		}

		INFO("Received HUP signal");

		last_hup = when;

		trigger_exec(NULL, NULL, "server.signal.hup", true, NULL);
		fr_event_loop_exit(event_list, 0x80);
	}
}

/*
 *	Inform ourselves that we received a signal.
 */
void main_loop_signal_self(int flag)
{
	ssize_t rcode;
	uint8_t buffer[16];

	/*
	 *	The read MUST be non-blocking for this to work.
	 */
	rcode = read(self_pipe[0], buffer, sizeof(buffer));
	if (rcode > 0) {
		ssize_t i;

		for (i = 0; i < rcode; i++) {
			buffer[0] |= buffer[i];
		}
	} else {
		buffer[0] = 0;
	}

	buffer[0] |= flag;

	if (write(self_pipe[1], buffer, 1) < 0) fr_exit(0);
}

static void main_loop_signal_handler(UNUSED fr_event_list_t *xel,
				     UNUSED int fd, UNUSED int flags, UNUSED void *ctx)
{
	ssize_t i, rcode;
	uint8_t buffer[32];

	rcode = read(self_pipe[0], buffer, sizeof(buffer));
	if (rcode <= 0) return;

	/*
	 *	Merge pending signals.
	 */
	for (i = 0; i < rcode; i++) buffer[0] |= buffer[i];

	handle_signal_self(buffer[0]);
}

fr_event_list_t *main_loop_event_list(void)
{
	/* Currently we do not run a second event loop for modules. */
	return event_list;
}

#ifdef HAVE_SYSTEMD_WATCHDOG
void main_loop_set_sd_watchdog_interval(void)
{
	uint64_t interval_usec;

	if (sd_watchdog_enabled(0, &interval_usec) > 0) {
		/*
		 *	Convert microseconds to nanoseconds
		 *	and set the interval to be half what
		 *	systemd uses as its timeout value.
		 */
		sd_watchdog_interval = ((interval_usec * 1000) / 2);

		INFO("systemd watchdog interval is %pVs", fr_box_time_delta(sd_watchdog_interval));
	} else {
		INFO("systemd watchdog is disabled");
	}
}
#endif

void main_loop_free(void)
{
	TALLOC_FREE(event_list);
}

int main_loop_start(void)
{
	int	ret;

#ifdef HAVE_SYSTEMD_WATCHDOG
	bool	under_systemd = (getenv("NOTIFY_SOCKET") != NULL);
#endif

	if (!event_list) return 0;

#ifdef HAVE_SYSTEMD_WATCHDOG
	/*
	 *	Tell systemd we're ready!
	 */
	if (under_systemd) sd_notify(0, "READY=1");

	/*
	 *	Start placating the watchdog (if told to do so).
	 */
	if (sd_watchdog_interval > 0) sd_watchdog_event(event_list, 0, NULL);
#endif

	ret = fr_event_loop(event_list);
#ifdef HAVE_SYSTEMD_WATCHDOG
	if (ret != 0x80) {	/* Not HUP */
		if (under_systemd) {
			INFO("Informing systemd we're stopping");
			sd_notify(0, "STOPPING=1");
		}
	}
#endif
	return ret;
}

static int _loop_status(UNUSED void *ctx, fr_time_t wake)
{
	/*
	 *	Print this out right away.  If we're debugging, we
	 *	don't really care about "Waking up..." messages when
	 *	the server first starts up.
	 */
	if (just_started) {
		INFO("Ready to process requests");
		just_started = false;
		return 0;
	}

	/*
	 *	Only print out more information if we're debugging.
	 */
	if (!DEBUG_ENABLED) return 0;

	if (!wake) {
		if (main_config->drop_requests) return 0;
		INFO("Ready to process requests");

	} else if (wake > (NSEC / 10)) {
		DEBUG4("Waking up in %pV seconds", fr_box_time_delta(wake));
	}

	return 0;
}

/** Initialise the main event loop, setting up signal handlers
 *
 *  This has to be done post-fork in case we're using kqueue, where the
 *  queue isn't inherited by the child process.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int main_loop_init(void)
{
	event_list = fr_event_list_alloc(NULL, _loop_status, NULL);	/* Must not be allocated in mprotected ctx */
	if (!event_list) return -1;

	/*
	 *	Not actually running the server, just exit.
	 */
	if (check_config) return 0;

	/*
	 *	Child threads need a pipe to signal us, as do the
	 *	signal handlers.
	 */
	if (pipe(self_pipe) < 0) {
		ERROR("Error opening internal pipe: %s", fr_syserror(errno));
		return -1;
	}
	if ((fcntl(self_pipe[0], F_SETFL, O_NONBLOCK) < 0) ||
	    (fcntl(self_pipe[0], F_SETFD, FD_CLOEXEC) < 0)) {
		ERROR("Error setting internal flags: %s", fr_syserror(errno));
		return -1;
	}
	if ((fcntl(self_pipe[1], F_SETFL, O_NONBLOCK) < 0) ||
	    (fcntl(self_pipe[1], F_SETFD, FD_CLOEXEC) < 0)) {
		ERROR("Error setting internal flags: %s", fr_syserror(errno));
		return -1;
	}
	DEBUG4("Created signal pipe.  Read end FD %i, write end FD %i", self_pipe[0], self_pipe[1]);

	if (fr_event_fd_insert(NULL, event_list, self_pipe[0],
			       main_loop_signal_handler,
			       NULL,
			       NULL,
			       event_list) < 0) {
		PERROR("Failed creating signal pipe handler");
		return -1;
	}

	return 0;
}

