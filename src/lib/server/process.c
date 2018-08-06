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
 * @file process.c
 * @brief Defines the state machines that control how requests are processed.
 *
 * @copyright 2012  The FreeRADIUS server project
 * @copyright 2012  Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/process.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/state.h>

#include <freeradius-devel/server/rad_assert.h>

#include <signal.h>
#include <fcntl.h>

#ifdef HAVE_SYS_WAIT_H
#  include <sys/wait.h>
#endif

#ifdef HAVE_SYSTEMD_WATCHDOG
#  include <systemd/sd-daemon.h>
#endif

extern pid_t radius_pid;
extern fr_cond_t *debug_condition;

#ifdef HAVE_SYSTEMD_WATCHDOG
struct timeval sd_watchdog_interval;
static fr_event_timer_t const *sd_watchdog_ev;
#endif

static bool just_started = true;
time_t fr_start_time = (time_t)-1;
static fr_event_list_t *event_list = NULL;

fr_event_list_t *fr_global_event_list(void) {
	/* Currently we do not run a second event loop for modules. */
	return event_list;
}


/*
 *	Delete a request.
 */
void request_delete(UNUSED REQUEST *request)
{
}

int request_receive(UNUSED TALLOC_CTX *ctx, UNUSED rad_listen_t *listener, UNUSED RADIUS_PACKET *packet,
		    UNUSED RADCLIENT *client, UNUSED RAD_REQUEST_FUNP fun)
{
	return 0;
}


REQUEST *request_setup(UNUSED TALLOC_CTX *ctx, UNUSED rad_listen_t *listener, UNUSED RADIUS_PACKET *packet,
		       UNUSED RADCLIENT *client, UNUSED RAD_REQUEST_FUNP fun)
{
	rad_assert(0 == 1);
	return NULL;
}

static int event_status(UNUSED void *ctx, struct timeval *wake)
{
	if (rad_debug_lvl == 0) {
		if (just_started) {
			INFO("Ready to process requests");
			just_started = false;
		}
		return 0;
	}

	if (!wake) {
		if (main_config->drop_requests) return 0;
		INFO("Ready to process requests");
	} else if ((wake->tv_sec != 0) ||
		   (wake->tv_usec >= 100000)) {
		DEBUG("Waking up in %d.%01u seconds.",
		      (int) wake->tv_sec, (unsigned int) wake->tv_usec / 100000);
	}

	return 0;
}

static int event_new_fd(rad_listen_t *this)
{
	char buffer[1024];

	if (this->status == RAD_LISTEN_STATUS_KNOWN) return 1;

	this->print(this, buffer, sizeof(buffer));

	if (this->status == RAD_LISTEN_STATUS_INIT) {
		listen_socket_t *sock = this->data;

		rad_assert(sock != NULL);
		if (just_started) {
			DEBUG("Listening on %s", buffer);
		} else {
			INFO(" ... adding new socket %s", buffer);
		}

#ifdef WITH_PROXY
		if (!just_started && (this->type == RAD_LISTEN_PROXY)) {
			home_server_t *home;

			home = sock->home;
			if (!home || !home->limit.max_connections) {
				INFO(" ... adding new socket %s", buffer);
			} else {
				INFO(" ... adding new socket %s (%u of %u)", buffer,
				     home->limit.num_connections, home->limit.max_connections);
			}

#endif
		}

		switch (this->type) {
#ifdef WITH_DETAIL
		/*
		 *	Detail files are always known, and aren't
		 *	put into the socket event loop.
		 */
		case RAD_LISTEN_DETAIL:
			this->status = RAD_LISTEN_STATUS_KNOWN;
			break;	/* add the FD to the list */
#endif	/* WITH_DETAIL */

#ifdef WITH_PROXY
		/*
		 *	Add it to the list of sockets we can use.
		 *	Server sockets (i.e. auth/acct) are never
		 *	added to the packet list.
		 */
		case RAD_LISTEN_PROXY:
#ifdef WITH_TCP
			if (!fr_cond_assert((sock->proto == IPPROTO_UDP) || (sock->home != NULL))) fr_exit(1);

			/*
			 *	Add timers to outgoing child sockets, if necessary.
			 */
			if (sock->proto == IPPROTO_TCP && sock->opened &&
			    (sock->home->limit.lifetime || sock->home->limit.idle_timeout)) {
				this->when.tv_sec = sock->opened + 1;
				this->when.tv_usec = 0;

			}
#endif
			break;
#endif	/* WITH_PROXY */

			/*
			 *	FIXME: put idle timers on command sockets.
			 */

		default:
#ifdef WITH_TCP
			/*
			 *	Add timers to incoming child sockets, if necessary.
			 */
			if (sock->proto == IPPROTO_TCP && sock->opened &&
			    (sock->limit.lifetime || sock->limit.idle_timeout)) {
				this->when.tv_sec = sock->opened + 1;
				this->when.tv_usec = 0;

			}
#endif
			break;
		} /* switch over listener types */

		this->status = RAD_LISTEN_STATUS_KNOWN;
		return 1;
	} /* end of INIT */

	return 1;
}

void radius_update_listener(rad_listen_t *this)
{
	event_new_fd(this);
}

/*
 *	Emit a systemd watchdog notification and reschedule the event.
 */
#ifdef HAVE_SYSTEMD_WATCHDOG
#define rad_panic(_x, ...) log_fatal("%s[%u]: " _x, __FILE__, __LINE__, ## __VA_ARGS__)

static void sd_watchdog_event(fr_event_list_t *our_el, struct timeval *now, void *ctx)
{
	struct timeval when;

	DEBUG("Emitting systemd watchdog notification");
	sd_notify(0, "WATCHDOG=1");

	fr_timeval_add(&when, &sd_watchdog_interval, now);
	if (fr_event_timer_insert(NULL, our_el, &sd_watchdog_ev,
				  &when, sd_watchdog_event, ctx) < 0) {
		rad_panic("Failed to insert watchdog event");
	}
}
#endif

/***********************************************************************
 *
 *	Signal handlers.
 *
 ***********************************************************************/

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

static int self_pipe[2] = { -1, -1 };

/*
 *	Inform ourselves that we received a signal.
 */
void radius_signal_self(int flag)
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

static void event_signal_handler(UNUSED fr_event_list_t *xel,
				 UNUSED int fd, UNUSED int flags, UNUSED void *ctx)
{
	ssize_t i, rcode;
	uint8_t buffer[32];

	rcode = read(self_pipe[0], buffer, sizeof(buffer));
	if (rcode <= 0) return;

	/*
	 *	Merge pending signals.
	 */
	for (i = 0; i < rcode; i++) {
		buffer[0] |= buffer[i];
	}

	handle_signal_self(buffer[0]);
}

/***********************************************************************
 *
 *	Bootstrapping code.
 *
 ***********************************************************************/

/*
 *	Externally-visibly functions.
 */
int radius_event_init(void)
{
	event_list = fr_event_list_alloc(NULL, event_status, NULL);	/* Must not be allocated in mprotected ctx */
	if (!event_list) return 0;

#ifdef HAVE_SYSTEMD_WATCHDOG
	if (sd_watchdog_interval.tv_sec || sd_watchdog_interval.tv_usec) {
		struct timeval now;

		fr_event_list_time(&now, event_list);
		sd_watchdog_event(event_list, &now, NULL);
	}
#endif

	return 1;
}

/** Start the main event loop and initialise the listeners
 *
 * @param have_children Whether the server is threaded.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int radius_event_start(UNUSED bool have_children)
{
	if (fr_start_time != (time_t)-1) return 0;

	time(&fr_start_time);

	if (check_config) {
		DEBUG("%s: #### Skipping IP addresses and Ports ####", main_config->name);
		return 0;
	}

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
			       event_signal_handler,
			       NULL,
			       NULL,
			       event_list) < 0) {
		PERROR("Failed creating signal pipe handler");
		return -1;
	}

	/*
	 *	At this point, no one has any business *ever* going
	 *	back to root uid.
	 */
	rad_suid_down_permanent();

	/*
	 *	Dropping down may change the RLIMIT_CORE value, so
	 *	reset it back to what to should be here.
	 */
	fr_reset_dumpable();

	return 0;
}

void radius_event_free(void)
{
	TALLOC_FREE(event_list);

	if (debug_condition) talloc_free(debug_condition);
}

int radius_event_process(void)
{
	if (!event_list) return 0;

	return fr_event_loop(event_list);
}
