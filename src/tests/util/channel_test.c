/*
 * channel_test.c	Stress test for channels and the sleep/wake handshake
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * @copyright 2026 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/control.h>
#include <freeradius-devel/io/message.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/talloc.h>

#ifdef HAVE_STDATOMIC_H
#  include <stdatomic.h>
#else
#  include <freeradius-devel/util/stdatomic.h>
#endif

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <pthread.h>

#define MPRINT1 if (debug_lvl) printf
#define MPRINT2 if (debug_lvl > 1) printf

/** What travels in each request, and is echoed back in its reply
 */
typedef struct {
	uint64_t	requestor;
	uint64_t	responder;
	uint64_t	seq;
} payload_t;

#define PAYLOAD_SIZE	(sizeof(payload_t))

typedef struct requestor_s requestor_t;
typedef struct responder_s responder_t;

/** A requestor's view of one channel
 */
typedef struct {
	fr_channel_t		*ch;
	requestor_t		*requestor;
	size_t			responder;	//!< index of the responder at the other end.
	fr_message_set_t	*reply_ms;	//!< replies are allocated from this by the responder.

	uint64_t		sent;
	uint64_t		replied;
	uint64_t		outstanding;
	uint64_t		last_seq;	//!< of the last reply, replies must arrive in order.

	bool			closing;
	bool			closed;
} req_channel_t;

struct requestor_s {
	size_t			id;
	fr_event_list_t		*el;
	fr_control_t		*control;
	fr_message_set_t	*ms;		//!< requests are allocated from this.

	req_channel_t		*channel;	//!< one per responder.
	size_t			num_closed;
};

/** A responder's view of one channel
 */
typedef struct {
	fr_channel_t		*ch;
	fr_message_set_t	*reply_ms;
} resp_channel_t;

struct responder_s {
	size_t			id;
	fr_event_list_t		*el;
	fr_control_t		*control;

	resp_channel_t		*channel;	//!< one slot per requestor.
	size_t			num_channels;
	size_t			num_closed;
	bool			running;

	fr_channel_data_t	**pending;	//!< requests received but not yet replied to.
	size_t			pending_size;
	size_t			pending_head;
	size_t			pending_num;

	uint64_t		received;
	uint64_t		sleeps;		//!< times we blocked.
	uint64_t		rescued;	//!< final drains which found work, i.e. skipped signals we caught.
};

static int		debug_lvl = 0;
static size_t		num_requestors = 2;
static size_t		num_responders = 4;
static uint64_t		max_messages = 100000;
static uint64_t		max_outstanding = 64;
static uint32_t		max_work_usec = 2;
static uint32_t		max_pause_usec = 20;
static unsigned int	watchdog_secs = 5;
static bool		broken = false;
static size_t		set_messages = 0;	//!< message set size override, 0 for automatic.

static requestor_t	*requestors;
static responder_t	*responders;

static _Atomic(uint64_t) progress;		//!< total replies received, watched by the watchdog.

static pthread_mutex_t	wd_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t	wd_cond = PTHREAD_COND_INITIALIZER;
static bool		finished = false;

static NEVER_RETURNS void usage(void)
{
	fprintf(stderr, "usage: channel_test [OPTS]\n");
	fprintf(stderr, "  -r <requestors>  Number of requestor threads (default %zu).\n", num_requestors);
	fprintf(stderr, "  -w <responders>  Number of responder threads (default %zu).\n", num_responders);
	fprintf(stderr, "  -m <messages>    Requests to send per channel (default %" PRIu64 ").\n", max_messages);
	fprintf(stderr, "  -o <outstanding> Requests in flight per channel (default %" PRIu64 ").\n", max_outstanding);
	fprintf(stderr, "  -W <usec>        Max busy work per reply (default %u).\n", max_work_usec);
	fprintf(stderr, "  -P <usec>        Max pause between requestor bursts (default %u).\n", max_pause_usec);
	fprintf(stderr, "  -t <secs>        Watchdog interval, abort if no progress (default %u).\n", watchdog_secs);
	fprintf(stderr, "  -b               Block without announcing, to prove the watchdog catches a stall.\n");
	fprintf(stderr, "  -M <messages>    Messages per set, power of two (default: twice the window plus 64).\n");
	fprintf(stderr, "  -x               Debugging mode.\n");

	fr_exit_now(EXIT_FAILURE);
}

/** Burn a random amount of time without a syscall
 */
static void spin(uint32_t max_usec)
{
	fr_time_t until;

	if (!max_usec) return;

	until = fr_time_add(fr_time(), fr_time_delta_from_usec(fr_rand() % (max_usec + 1)));
	while (fr_time_lt(fr_time(), until)) {
		/* spin */
	}
}

/**********************************************************************
 *	Requestor
 **********************************************************************/

static void requestor_recv_reply(fr_channel_t *ch, fr_channel_data_t *cd, UNUSED void *uctx)
{
	req_channel_t	*rc = fr_channel_requestor_uctx_get(ch);
	payload_t	pl;

	memcpy(&pl, cd->m.data, sizeof(pl));
	fr_assert_msg((pl.requestor == rc->requestor->id) && (pl.responder == rc->responder),
		      "requestor %zu channel %zu: reply belongs to requestor %" PRIu64 " channel %" PRIu64,
		      rc->requestor->id, rc->responder, pl.requestor, pl.responder);
	fr_assert_msg(pl.seq == rc->last_seq + 1,
		      "requestor %zu channel %zu: reply %" PRIu64 " after %" PRIu64 " (sent %" PRIu64 " replied %" PRIu64 ")",
		      rc->requestor->id, rc->responder, pl.seq, rc->last_seq, rc->sent, rc->replied);
	rc->last_seq = pl.seq;

	fr_assert(rc->outstanding > 0);
	rc->outstanding--;
	rc->replied++;

	fr_message_done(&cd->m);

	atomic_fetch_add_explicit(&progress, 1, memory_order_relaxed);
}

static void requestor_closed(fr_channel_t *ch, UNUSED fr_time_t now, void *uctx)
{
	requestor_t	*r = uctx;
	req_channel_t	*rc = fr_channel_requestor_uctx_get(ch);

	fr_assert(rc->closing);
	rc->closed = true;
	r->num_closed++;
	MPRINT1("requestor %zu: responder %zu acked close\n", r->id, rc->responder);
}

static fr_channel_callbacks_t const requestor_callbacks = {
	.closed		= requestor_closed
};

static void *requestor_thread(void *arg)
{
	requestor_t	*r = arg;
	size_t		i;
	bool		wait;

	MPRINT1("requestor %zu: started\n", r->id);

	for (i = 0; i < num_responders; i++) {
		if (fr_channel_signal_open(r->channel[i].ch, r->channel[i].reply_ms) < 0) {
			fprintf(stderr, "requestor %zu: failed signalling open: %s\n", r->id, fr_strerror());
			fr_exit_now(EXIT_FAILURE);
		}
	}

	while (r->num_closed < num_responders) {
		int num_events;

		for (i = 0; i < num_responders; i++) {
			req_channel_t *rc = &r->channel[i];

			while (!rc->closing && (rc->sent < max_messages) && (rc->outstanding < max_outstanding)) {
				fr_message_t		*m;
				fr_channel_data_t	*cd;
				payload_t		pl = {
					.requestor = r->id,
					.responder = i,
					.seq = rc->sent + 1
				};

				m = fr_message_and_data_alloc(r->ms, PAYLOAD_SIZE);
				if (!m) {
					fr_message_set_gc(r->ms);
					m = fr_message_and_data_alloc(r->ms, PAYLOAD_SIZE);
					if (!m) break;		/* wait for replies to free some */
				}
				cd = (fr_channel_data_t *) m;

				memcpy(cd->m.data, &pl, sizeof(pl));
				cd->m.when = fr_time();

				if (fr_channel_send_request(rc->ch, cd) < 0) {
					MPRINT2("requestor %zu: channel %zu full\n", r->id, i);
					fr_message_done(&cd->m);
					break;			/* wait for the responder to drain */
				}

				rc->sent++;
				rc->outstanding++;
			}

			if (!rc->closing && (rc->sent == max_messages) && (rc->outstanding == 0)) {
				MPRINT1("requestor %zu: closing channel to responder %zu\n", r->id, i);
				rc->closing = true;
				if (fr_channel_signal_responder_close(rc->ch) < 0) {
					fprintf(stderr, "requestor %zu: failed signalling close: %s\n", r->id, fr_strerror());
					fr_exit_now(EXIT_FAILURE);
				}
			}
		}

		/*
		 *	Go quiet for a bit so the responders run dry,
		 *	announce, and block.  The next burst then lands
		 *	on a responder which is sleeping, or is in the
		 *	middle of deciding to.
		 */
		spin(max_pause_usec);

		/*
		 *	Everything we can send is sent.  Announce that
		 *	we are about to block, drain every channel one
		 *	last time, and only block if that found nothing.
		 */
		wait = !fr_control_sleeping(r->control);
		for (i = 0; i < num_responders; i++) {
			while (fr_channel_recv_reply(r->channel[i].ch)) wait = false;
		}
		if (!wait) fr_control_awake(r->control);

		num_events = fr_event_corral(r->el, fr_time(), wait);
		fr_control_awake(r->control);
		if (num_events < 0) {
			fprintf(stderr, "requestor %zu: failed waiting for events: %s\n", r->id, fr_syserror(errno));
			fr_exit_now(EXIT_FAILURE);
		}
		if (num_events > 0) fr_event_service(r->el);
	}

	MPRINT1("requestor %zu: exiting\n", r->id);

	return NULL;
}

/**********************************************************************
 *	Responder
 **********************************************************************/

static void responder_recv_request(fr_channel_t *ch, fr_channel_data_t *cd, void *uctx)
{
	responder_t	*w = uctx;
	size_t		tail;

	cd->channel.ch = ch;

	fr_assert_msg(w->pending_num < w->pending_size, "responder %zu: pending overflow", w->id);
	tail = (w->pending_head + w->pending_num) % w->pending_size;
	w->pending[tail] = cd;
	w->pending_num++;
	w->received++;
}

static void responder_open(fr_channel_t *ch, fr_message_set_t *reply_ms, UNUSED fr_time_t now, void *uctx)
{
	responder_t	*w = uctx;
	resp_channel_t	*slot;
	size_t		i;

	for (i = 0; i < num_requestors; i++) {
		if (w->channel[i].ch) continue;

		slot = &w->channel[i];
		slot->ch = ch;
		slot->reply_ms = reply_ms;
		fr_channel_responder_uctx_add(ch, slot);
		fr_channel_set_recv_request(ch, responder_recv_request, w);
		w->num_channels++;
		MPRINT1("responder %zu: channel %zu opened\n", w->id, i);
		return;
	}
	fr_assert_fail("responder has no free channel slot");
}

static void responder_close(fr_channel_t *ch, UNUSED fr_time_t now, void *uctx)
{
	responder_t	*w = uctx;
	resp_channel_t	*slot = fr_channel_responder_uctx_get(ch);
	unsigned int	num;

	/*
	 *	The requestor only closes once every reply is
	 *	in, so nothing can be queued or pending.
	 */
	num = fr_channel_responder_discard(ch);
	if (num > 0) {
		fprintf(stderr, "responder %zu: %u requests queued at close\n", w->id, num);
		fr_exit_now(EXIT_FAILURE);
	}

	(void) fr_channel_responder_ack_close(ch);
	slot->ch = NULL;
	w->num_channels--;
	w->num_closed++;
	MPRINT1("responder %zu: channel closed, %zu remain\n", w->id, w->num_channels);
	if (w->num_closed == num_requestors) w->running = false;
}

static fr_channel_callbacks_t const responder_callbacks = {
	.open		= responder_open,
	.close		= responder_close
};

/** The responder half of the handshake, as fr_worker() does it
 *
 * @return true if the final drain found work, so the caller must not block.
 */
static bool responder_sleeping(responder_t *w)
{
	size_t	i;
	bool	received;

	received = fr_control_sleeping(w->control);

	for (i = 0; i < num_requestors; i++) {
		if (!w->channel[i].ch) continue;
		if (!fr_channel_active(w->channel[i].ch)) continue;

		while (fr_channel_recv_request(w->channel[i].ch)) received = true;
	}

	if (received) {
		w->rescued++;
		fr_control_awake(w->control);
	}

	return received;
}

/** Reply to everything pending at the start of this pass
 *
 * Replies made during the pass may queue more requests, which wait for
 * the next pass, as they would in the worker.
 */
static void responder_run(responder_t *w)
{
	size_t batch = w->pending_num;

	while (batch--) {
		fr_channel_data_t	*cd = w->pending[w->pending_head];
		fr_channel_t		*ch = cd->channel.ch;
		resp_channel_t		*slot = fr_channel_responder_uctx_get(ch);
		fr_message_t		*m;
		fr_channel_data_t	*reply;
		fr_time_t		start = fr_time();

		spin(max_work_usec);

		m = fr_message_and_data_alloc(slot->reply_ms, PAYLOAD_SIZE);
		if (!m) {
			fr_message_set_gc(slot->reply_ms);
			m = fr_message_and_data_alloc(slot->reply_ms, PAYLOAD_SIZE);
			if (!m) return;			/* requestor has not freed replies yet */
		}
		reply = (fr_channel_data_t *) m;

		memcpy(reply->m.data, cd->m.data, PAYLOAD_SIZE);
		reply->m.when = fr_time();
		reply->reply.processing_time = fr_time_sub(reply->m.when, start);
		reply->reply.cpu_time = reply->reply.processing_time;
		reply->reply.request_time = cd->m.when;

		if (fr_channel_send_reply(ch, reply) < 0) {
			MPRINT2("responder %zu: reply queue full\n", w->id);
			fr_message_done(&reply->m);
			return;				/* leave the request pending */
		}

		fr_message_done(&cd->m);
		w->pending_head = (w->pending_head + 1) % w->pending_size;
		w->pending_num--;
	}
}

static void *responder_thread(void *arg)
{
	responder_t	*w = arg;

	MPRINT1("responder %zu: started\n", w->id);

	while (w->running || (w->pending_num > 0)) {
		bool	wait, announced = false;
		int	num_events;

		wait = (w->pending_num == 0);
		if (wait && !broken) {
			announced = true;
			if (responder_sleeping(w)) wait = false;
		}
		if (wait) w->sleeps++;

		num_events = fr_event_corral(w->el, fr_time(), wait);
		if (announced) fr_control_awake(w->control);

		if (num_events < 0) {
			fprintf(stderr, "responder %zu: failed waiting for events: %s\n", w->id, fr_syserror(errno));
			fr_exit_now(EXIT_FAILURE);
		}
		if (num_events > 0) fr_event_service(w->el);

		responder_run(w);
	}

	MPRINT1("responder %zu: exiting\n", w->id);

	return NULL;
}

/**********************************************************************
 *	Watchdog
 **********************************************************************/

static void dump_state(void)
{
	size_t i, j;

	for (i = 0; i < num_requestors; i++) {
		for (j = 0; j < num_responders; j++) {
			req_channel_t *rc = &requestors[i].channel[j];

			fprintf(stderr, "requestor %zu -> responder %zu: sent %" PRIu64 " replied %" PRIu64
				" outstanding %" PRIu64 "%s%s\n",
				i, j, rc->sent, rc->replied, rc->outstanding,
				rc->closing ? " closing" : "", rc->closed ? " closed" : "");
		}
	}

	for (i = 0; i < num_responders; i++) {
		responder_t *w = &responders[i];

		fprintf(stderr, "responder %zu: received %" PRIu64 " pending %zu"
			" sleeps %" PRIu64 " %s\n",
			i, w->received, w->pending_num, w->sleeps,
			fr_control_is_sleeping(w->control) ? "SLEEPING" : "awake");
	}
}

static void *watchdog_thread(UNUSED void *arg)
{
	uint64_t last = 0;

	pthread_mutex_lock(&wd_mutex);
	while (!finished) {
		struct timespec	ts;
		int		ret;

		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += watchdog_secs;

		ret = pthread_cond_timedwait(&wd_cond, &wd_mutex, &ts);
		if (finished) break;
		if (ret != ETIMEDOUT) continue;

		{
			uint64_t now = atomic_load_explicit(&progress, memory_order_relaxed);

			if (now == last) {
				fprintf(stderr, "STALL: no replies in %u seconds\n", watchdog_secs);
				dump_state();
				fr_exit_now(EXIT_FAILURE);
			}
			MPRINT1("watchdog: %" PRIu64 " replies\n", now);
			last = now;
		}
	}
	pthread_mutex_unlock(&wd_mutex);

	return NULL;
}

/**********************************************************************
 *	Main
 **********************************************************************/

int main(int argc, char *argv[])
{
	int		c;
	size_t		i, j;
	TALLOC_CTX	*ctx;
	pthread_attr_t	attr;
	pthread_t	*req_id, *resp_id, wd_id;
	fr_time_t	start;
	int64_t		elapsed_usec;
	uint64_t	sent = 0, replied = 0, signals = 0, spurious_req = 0, spurious_rep = 0, sleeps = 0, rescued = 0;
	size_t		num_messages;

	while ((c = getopt(argc, argv, "bhm:M:o:P:r:t:w:W:x")) != -1) switch (c) {
		case 'b':
			broken = true;
			break;

		case 'M':
			set_messages = strtoul(optarg, NULL, 10);
			break;

		case 'm':
			max_messages = strtoull(optarg, NULL, 10);
			break;

		case 'o':
			max_outstanding = strtoull(optarg, NULL, 10);
			break;

		case 'P':
			max_pause_usec = (uint32_t) strtoul(optarg, NULL, 10);
			break;

		case 'r':
			num_requestors = strtoul(optarg, NULL, 10);
			break;

		case 't':
			watchdog_secs = (unsigned int) strtoul(optarg, NULL, 10);
			break;

		case 'w':
			num_responders = strtoul(optarg, NULL, 10);
			break;

		case 'W':
			max_work_usec = (uint32_t) strtoul(optarg, NULL, 10);
			break;

		case 'x':
			debug_lvl++;
			break;

		case 'h':
		default:
			usage();
	}

	if (!num_requestors || !num_responders || !max_messages || !max_outstanding) usage();
	if (max_outstanding > max_messages) max_outstanding = max_messages;

	fr_time_start();

	MEM(ctx = talloc_init_const("channel_test"));

	/*
	 *	Each thread owns an event list, a control plane, and
	 *	the atomic queue behind it.  All of them are built here
	 *	before any thread starts, so no thread ever touches
	 *	another's event list.
	 */
	MEM(requestors = talloc_zero_array(ctx, requestor_t, num_requestors));
	MEM(responders = talloc_zero_array(ctx, responder_t, num_responders));

	/*
	 *	Message sets want a power of two.  They are also sized
	 *	well above the window on purpose: a set which fills and
	 *	spills into a second message ring corrupts live messages
	 *	when their replies complete out of order, which is a
	 *	message set bug and not what this test is for.  Pass a
	 *	small -M to reproduce it.
	 */
	num_messages = 1024;
	while (num_messages < (max_outstanding * 32)) num_messages <<= 1;
	if (set_messages) num_messages = set_messages;

	for (i = 0; i < num_responders; i++) {
		responder_t *w = &responders[i];

		w->id = i;
		w->running = true;
		MEM(w->el = fr_event_list_alloc(ctx, NULL, NULL));
		MEM(w->control = fr_control_create(ctx, w->el, FR_CONTROL_MAX_MESSAGES, FR_CONTROL_MAX_SIZE));
		if ((fr_channel_callbacks_add(w->control, &responder_callbacks, w) < 0) ||
		    (fr_control_open(w->control) < 0)) {
			fprintf(stderr, "failed setting up responder %zu control plane: %s\n", i, fr_strerror());
			fr_exit_now(EXIT_FAILURE);
		}
		MEM(w->channel = talloc_zero_array(ctx, resp_channel_t, num_requestors));
		w->pending_size = (max_outstanding * num_requestors) + 1;
		MEM(w->pending = talloc_zero_array(ctx, fr_channel_data_t *, w->pending_size));
	}

	for (i = 0; i < num_requestors; i++) {
		requestor_t *r = &requestors[i];

		r->id = i;
		MEM(r->el = fr_event_list_alloc(ctx, NULL, NULL));
		MEM(r->control = fr_control_create(ctx, r->el, FR_CONTROL_MAX_MESSAGES, FR_CONTROL_MAX_SIZE));
		if ((fr_channel_callbacks_add(r->control, &requestor_callbacks, r) < 0) ||
		    (fr_control_open(r->control) < 0)) {
			fprintf(stderr, "failed setting up requestor %zu control plane: %s\n", i, fr_strerror());
			fr_exit_now(EXIT_FAILURE);
		}
		{
			size_t n = num_messages;

			while (n < (num_messages * num_responders)) n <<= 1;
			MEM(r->ms = fr_message_set_create(ctx, (int) n, sizeof(fr_channel_data_t), n * 256, false));
		}
		MEM(r->channel = talloc_zero_array(ctx, req_channel_t, num_responders));

		for (j = 0; j < num_responders; j++) {
			req_channel_t *rc = &r->channel[j];

			rc->requestor = r;
			rc->responder = j;
			MEM(rc->reply_ms = fr_message_set_create(ctx, (int) num_messages, sizeof(fr_channel_data_t),
								 num_messages * 256, false));
			MEM(rc->ch = fr_channel_create(ctx, r->control, responders[j].control, false));
			fr_channel_requestor_uctx_add(rc->ch, rc);
			fr_channel_set_recv_reply(rc->ch, requestor_recv_reply, r);
		}
	}

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	MEM(req_id = talloc_array(ctx, pthread_t, num_requestors));
	MEM(resp_id = talloc_array(ctx, pthread_t, num_responders));

	start = fr_time();

	(void) pthread_create(&wd_id, &attr, watchdog_thread, NULL);
	for (i = 0; i < num_responders; i++) (void) pthread_create(&resp_id[i], &attr, responder_thread, &responders[i]);
	for (i = 0; i < num_requestors; i++) (void) pthread_create(&req_id[i], &attr, requestor_thread, &requestors[i]);

	for (i = 0; i < num_requestors; i++) (void) pthread_join(req_id[i], NULL);
	for (i = 0; i < num_responders; i++) (void) pthread_join(resp_id[i], NULL);

	pthread_mutex_lock(&wd_mutex);
	finished = true;
	pthread_cond_signal(&wd_cond);
	pthread_mutex_unlock(&wd_mutex);
	(void) pthread_join(wd_id, NULL);

	elapsed_usec = fr_time_delta_to_usec(fr_time_sub(fr_time(), start));

	/*
	 *	Every request got exactly one reply, and every message
	 *	buffer came back.
	 */
	for (i = 0; i < num_requestors; i++) {
		requestor_t *r = &requestors[i];

		for (j = 0; j < num_responders; j++) {
			req_channel_t *rc = &r->channel[j];

			fr_assert(rc->sent == max_messages);
			fr_assert(rc->replied == max_messages);
			fr_assert(rc->outstanding == 0);
			sent += rc->sent;
			replied += rc->replied;

			fr_message_set_gc(rc->reply_ms);
			fr_assert(fr_message_set_messages_used(rc->reply_ms) == 0);

			/*
			 *	The channel holds both ends' counters.
			 */
			signals += fr_channel_requestor_stats(rc->ch)->signals;
			spurious_req += fr_channel_responder_stats(rc->ch)->spurious;
			spurious_rep += fr_channel_requestor_stats(rc->ch)->spurious;
		}

		fr_message_set_gc(r->ms);
		fr_assert(fr_message_set_messages_used(r->ms) == 0);
	}

	for (i = 0; i < num_responders; i++) {
		responder_t *w = &responders[i];

		fr_assert(w->pending_num == 0);
		sleeps += w->sleeps;
		rescued += w->rescued;
	}

	fr_assert(sent == replied);

	printf("requests          %" PRIu64 "\n", sent);
	printf("replies           %" PRIu64 "\n", replied);
	printf("request signals   %" PRIu64 " (%.1f%% of requests skipped the signal)\n",
	       signals, 100.0 * (double) (sent - signals) / (double) sent);
	printf("spurious signals  %" PRIu64 " request, %" PRIu64 " reply\n", spurious_req, spurious_rep);
	printf("responder sleeps  %" PRIu64 "\n", sleeps);
	printf("rescued by drain  %" PRIu64 "\n", rescued);
	printf("elapsed           %.3fs, %.0f requests/s\n",
	       (double) elapsed_usec / 1e6, ((double) sent * 1e6) / (double) elapsed_usec);

	fflush(stdout);
	talloc_free(ctx);

	fr_exit_now(EXIT_SUCCESS);
}
