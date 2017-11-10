/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file radsniff.c
 * @brief Capture, filter, and generate statistics for RADIUS traffic
 *
 * @copyright 2013 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2006 The FreeRADIUS server project
 * @copyright 2006 Nicolas Baradakis <nicolas.baradakis@cegetel.net>
 */

RCSID("$Id$")

#define _LIBRADIUS 1
#include <time.h>
#include <math.h>
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/event.h>

#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/pcap.h>
#include <freeradius-devel/radsniff.h>

#ifdef HAVE_COLLECTDC_H
#  include <collectd/client.h>
#endif

#define RS_ASSERT(_x) if (!(_x) && !fr_assert(_x)) exit(1)

static rs_t *conf;
static struct timeval start_pcap = {0, 0};
static char timestr[50];

static rbtree_t *request_tree = NULL;
static rbtree_t *link_tree = NULL;
static fr_event_list_t *events;
static bool cleanup;

static int self_pipe[2] = {-1, -1};		//!< Signals from sig handlers

typedef int (*rbcmp)(void const *, void const *);

static char const *radsniff_version = "radsniff version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
#ifndef ENABLE_REPRODUCIBLE_BUILDS
", built on " __DATE__ " at " __TIME__
#endif
;

static int rs_useful_codes[] = {
	PW_CODE_ACCESS_REQUEST,			//!< RFC2865 - Authentication request
	PW_CODE_ACCESS_ACCEPT,			//!< RFC2865 - Access-Accept
	PW_CODE_ACCESS_REJECT,			//!< RFC2865 - Access-Reject
	PW_CODE_ACCOUNTING_REQUEST,		//!< RFC2866 - Accounting-Request
	PW_CODE_ACCOUNTING_RESPONSE,		//!< RFC2866 - Accounting-Response
	PW_CODE_ACCESS_CHALLENGE,		//!< RFC2865 - Access-Challenge
	PW_CODE_STATUS_SERVER,			//!< RFC2865/RFC5997 - Status Server (request)
	PW_CODE_STATUS_CLIENT,			//!< RFC2865/RFC5997 - Status Server (response)
	PW_CODE_DISCONNECT_REQUEST,		//!< RFC3575/RFC5176 - Disconnect-Request
	PW_CODE_DISCONNECT_ACK,			//!< RFC3575/RFC5176 - Disconnect-Ack (positive)
	PW_CODE_DISCONNECT_NAK,			//!< RFC3575/RFC5176 - Disconnect-Nak (not willing to perform)
	PW_CODE_COA_REQUEST,			//!< RFC3575/RFC5176 - CoA-Request
	PW_CODE_COA_ACK,			//!< RFC3575/RFC5176 - CoA-Ack (positive)
	PW_CODE_COA_NAK,			//!< RFC3575/RFC5176 - CoA-Nak (not willing to perform)
};

static const FR_NAME_NUMBER rs_events[] = {
	{ "received",	RS_NORMAL	},
	{ "norsp",	RS_LOST		},
	{ "rtx",	RS_RTX		},
	{ "noreq",	RS_UNLINKED	},
	{ "reused",	RS_REUSED	},
	{ "error",	RS_ERROR	},
	{  NULL , -1 }
};

static void NEVER_RETURNS usage(int status);

/** Fork and kill the parent process, writing out our PID
 *
 * @param pidfile the PID file to write our PID to
 */
static void rs_daemonize(char const *pidfile)
{
	FILE *fp;
	pid_t pid, sid;

	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	/*
	 *	Kill the parent...
	 */
	if (pid > 0) {
		close(self_pipe[0]);
		close(self_pipe[1]);
		exit(EXIT_SUCCESS);
	}

	/*
	 *	Continue as the child.
	 */

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		exit(EXIT_FAILURE);
	}

	/*
	 *	Change the current working directory. This prevents the current
	 *	directory from being locked; hence not being able to remove it.
	 */
	if ((chdir("/")) < 0) {
		exit(EXIT_FAILURE);
	}

	/*
	 *	And write it AFTER we've forked, so that we write the
	 *	correct PID.
	 */
	fp = fopen(pidfile, "w");
	if (fp != NULL) {
		fprintf(fp, "%d\n", (int) sid);
		fclose(fp);
	} else {
		ERROR("Failed creating PID file %s: %s", pidfile, fr_syserror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 *	Close stdout and stderr if they've not been redirected.
	 */
	if (isatty(fileno(stdout))) {
		if (!freopen("/dev/null", "w", stdout)) {
			exit(EXIT_FAILURE);
		}
	}

	if (isatty(fileno(stderr))) {
		if (!freopen("/dev/null", "w", stderr)) {
			exit(EXIT_FAILURE);
		}
	}
}

#define USEC 1000000
static void rs_tv_sub(struct timeval const *end, struct timeval const *start, struct timeval *elapsed)
{
	elapsed->tv_sec = end->tv_sec - start->tv_sec;
	if (elapsed->tv_sec > 0) {
		elapsed->tv_sec--;
		elapsed->tv_usec = USEC;
	} else {
		elapsed->tv_usec = 0;
	}
	elapsed->tv_usec += end->tv_usec;
	elapsed->tv_usec -= start->tv_usec;

	if (elapsed->tv_usec >= USEC) {
		elapsed->tv_usec -= USEC;
		elapsed->tv_sec++;
	}
}

static void rs_tv_add_ms(struct timeval const *start, unsigned long interval, struct timeval *result) {
    result->tv_sec = start->tv_sec + (interval / 1000);
    result->tv_usec = start->tv_usec + ((interval % 1000) * 1000);

    if (result->tv_usec > USEC) {
	result->tv_usec -= USEC;
	result->tv_sec++;
    }
}

static void rs_time_print(char *out, size_t len, struct timeval const *t)
{
	size_t ret;
	struct timeval now;
	uint32_t usec;

	if (!t) {
		gettimeofday(&now, NULL);
		t = &now;
	}

	ret = strftime(out, len, "%Y-%m-%d %H:%M:%S", localtime(&t->tv_sec));
	if (ret >= len) {
		return;
	}

	usec = t->tv_usec;

	if (usec) {
		while (usec < 100000) usec *= 10;
		snprintf(out + ret, len - ret, ".%i", usec);
	} else {
		snprintf(out + ret, len - ret, ".000000");
	}
}

static size_t rs_prints_csv(char *out, size_t outlen, char const *in, size_t inlen)
{
	char const	*start = out;
	uint8_t const	*str = (uint8_t const *) in;

	if (!in) {
		if (outlen) {
			*out = '\0';
		}

		return 0;
	}

	if (inlen == 0) {
		inlen = strlen(in);
	}

	while ((inlen > 0) && (outlen > 2)) {
		/*
		 *	Escape double quotes with... MORE DOUBLE QUOTES!
		 */
		if (*str == '"') {
			*out++ = '"';
			outlen--;
		}

		/*
		 *	Safe chars which require no escaping
		 */
		if ((*str == '\r') || (*str == '\n') || ((*str >= '\x20') && (*str <= '\x7E'))) {
			*out++ = *str++;
			outlen--;
			inlen--;

			continue;
		}

		/*
		 *	Everything else is dropped
		 */
		str++;
		inlen--;
	}
	*out = '\0';

	return out - start;
}

static void rs_packet_print_csv_header(void)
{
	char buffer[2048];
	char *p = buffer;
	int i;

	ssize_t len, s = sizeof(buffer);

	len = strlcpy(p, "\"Status\",\"Count\",\"Time\",\"Latency\",\"Type\",\"Interface\","
		      "\"Src IP\",\"Src Port\",\"Dst IP\",\"Dst Port\",\"ID\",", s);
	p += len;
	s -= len;

	if (s <= 0) return;

	for (i = 0; i < conf->list_da_num; i++) {
		char const *in;

		*p++ = '"';
		s -= 1;
		if (s <= 0) return;

		for (in = conf->list_da[i]->name; *in; in++) {
			*p++ = *in;
			s -= len;
			if (s <= 0) return;
		}

		*p++ = '"';
		s -= 1;
		if (s <= 0) return;
		*p++ = ',';
		s -= 1;
		if (s <= 0) return;
	}

	*--p = '\0';

	fprintf(stdout , "%s\n", buffer);
}

static void rs_packet_print_csv(uint64_t count, rs_status_t status, fr_pcap_t *handle, RADIUS_PACKET *packet,
				UNUSED struct timeval *elapsed, struct timeval *latency, UNUSED bool response,
				bool body)
{
	char const *status_str;
	char buffer[2048];
	char *p = buffer;

	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];

	ssize_t len, s = sizeof(buffer);

	inet_ntop(packet->src_ipaddr.af, &packet->src_ipaddr.ipaddr, src, sizeof(src));
	inet_ntop(packet->dst_ipaddr.af, &packet->dst_ipaddr.ipaddr, dst, sizeof(dst));

	status_str = fr_int2str(rs_events, status, NULL);
	RS_ASSERT(status_str);

	len = snprintf(p, s, "%s,%" PRIu64 ",%s,", status_str, count, timestr);
	p += len;
	s -= len;

	if (s <= 0) return;

	if (latency) {
		len = snprintf(p, s, "%u.%03u,",
			       (unsigned int) latency->tv_sec, ((unsigned int) latency->tv_usec / 1000));
		p += len;
		s -= len;
	} else {
		*p = ',';
		p += 1;
		s -= 1;
	}

	if (s <= 0) return;

	/* Status, Type, Interface, Src, Src port, Dst, Dst port, ID */
	if (is_radius_code(packet->code)) {
		len = snprintf(p, s, "%s,%s,%s,%i,%s,%i,%i,", fr_packet_codes[packet->code], handle->name,
			       src, packet->src_port, dst, packet->dst_port, packet->id);
	} else {
		len = snprintf(p, s, "%u,%s,%s,%i,%s,%i,%i,", packet->code, handle->name,
			       src, packet->src_port, dst, packet->dst_port, packet->id);
	}
	p += len;
	s -= len;

	if (s <= 0) return;

	if (body) {
		int i;
		VALUE_PAIR *vp;

		for (i = 0; i < conf->list_da_num; i++) {
			vp = fr_pair_find_by_da(packet->vps, conf->list_da[i], TAG_ANY);
			if (vp && (vp->vp_length > 0)) {
				if (conf->list_da[i]->type == PW_TYPE_STRING) {
					*p++ = '"';
					s--;
					if (s <= 0) return;

					len = rs_prints_csv(p, s, vp->vp_strvalue, vp->vp_length);
					p += len;
					s -= len;
					if (s <= 0) return;

					*p++ = '"';
					s--;
					if (s <= 0) return;
				} else {
					len = vp_prints_value(p, s, vp, 0);
					p += len;
					s -= len;
					if (s <= 0) return;
				}
			}

			*p++ = ',';
			s -= 1;
			if (s <= 0) return;
		}
	} else {
		s -= conf->list_da_num;
		if (s <= 0) return;

		memset(p, ',', conf->list_da_num);
		p += conf->list_da_num;
	}

	*--p = '\0';
	fprintf(stdout , "%s\n", buffer);
}

static void rs_packet_print_fancy(uint64_t count, rs_status_t status, fr_pcap_t *handle, RADIUS_PACKET *packet,
				  struct timeval *elapsed, struct timeval *latency, bool response, bool body)
{
	char buffer[2048];
	char *p = buffer;

	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];

	ssize_t len, s = sizeof(buffer);

	inet_ntop(packet->src_ipaddr.af, &packet->src_ipaddr.ipaddr, src, sizeof(src));
	inet_ntop(packet->dst_ipaddr.af, &packet->dst_ipaddr.ipaddr, dst, sizeof(dst));

	/* Only print out status str if something's not right */
	if (status != RS_NORMAL) {
		char const *status_str;

		status_str = fr_int2str(rs_events, status, NULL);
		RS_ASSERT(status_str);

		len = snprintf(p, s, "** %s ** ", status_str);
		p += len;
		s -= len;
		if (s <= 0) return;
	}

	if (is_radius_code(packet->code)) {
		len = snprintf(p, s, "%s Id %i %s:%s:%d %s %s:%i ",
			       fr_packet_codes[packet->code],
			       packet->id,
			       handle->name,
			       response ? dst : src,
			       response ? packet->dst_port : packet->src_port,
			       response ? "<-" : "->",
			       response ? src : dst ,
			       response ? packet->src_port : packet->dst_port);
	} else {
		len = snprintf(p, s, "%u Id %i %s:%s:%i %s %s:%i ",
			       packet->code,
			       packet->id,
			       handle->name,
			       response ? dst : src,
			       response ? packet->dst_port : packet->src_port,
			       response ? "<-" : "->",
			       response ? src : dst ,
			       response ? packet->src_port : packet->dst_port);
	}
	p += len;
	s -= len;
	if (s <= 0) return;

	if (elapsed) {
		len = snprintf(p, s, "+%u.%03u ",
			       (unsigned int) elapsed->tv_sec, ((unsigned int) elapsed->tv_usec / 1000));
		p += len;
		s -= len;
		if (s <= 0) return;
	}

	if (latency) {
		len = snprintf(p, s, "+%u.%03u ",
			       (unsigned int) latency->tv_sec, ((unsigned int) latency->tv_usec / 1000));
		p += len;
		s -= len;
		if (s <= 0) return;
	}

	*--p = '\0';

	RIDEBUG("%s", buffer);

	if (body) {
		/*
		 *	Print out verbose HEX output
		 */
		if (conf->print_packet && (fr_debug_lvl > 3)) {
			rad_print_hex(packet);
		}

		if (conf->print_packet && (fr_debug_lvl > 1)) {
			char vector[(AUTH_VECTOR_LEN * 2) + 1];

			if (packet->vps) {
				fr_pair_list_sort(&packet->vps, fr_pair_cmp_by_da_tag);
				vp_printlist(fr_log_fp, packet->vps);
			}

			fr_bin2hex(vector, packet->vector, AUTH_VECTOR_LEN);
			INFO("\tAuthenticator-Field = 0x%s", vector);
		}
	}
}

static inline void rs_packet_print(rs_request_t *request, uint64_t count, rs_status_t status, fr_pcap_t *handle,
				   RADIUS_PACKET *packet, struct timeval *elapsed, struct timeval *latency,
				   bool response, bool body)
{
	if (!conf->logger) return;

	if (request) request->logged = true;
	conf->logger(count, status, handle, packet, elapsed, latency, response, body);
}

static void rs_stats_print(rs_latency_t *stats, PW_CODE code)
{
	int i;
	bool have_rt = false;

	for (i = 0; i <= RS_RETRANSMIT_MAX; i++) {
		if (stats->interval.rt[i]) {
			have_rt = true;
		}
	}

	if (!stats->interval.received && !have_rt && !stats->interval.reused) {
		return;
	}

	if (stats->interval.received || stats->interval.linked) {
		INFO("%s counters:", fr_packet_codes[code]);
		if (stats->interval.received > 0) {
			INFO("\tTotal     : %.3lf/s" , stats->interval.received);
		}
	}

	if (stats->interval.linked > 0) {
		INFO("\tLinked    : %.3lf/s", stats->interval.linked);
		INFO("\tUnlinked  : %.3lf/s", stats->interval.unlinked);
		INFO("%s latency:", fr_packet_codes[code]);
		INFO("\tHigh      : %.3lfms", stats->interval.latency_high);
		INFO("\tLow       : %.3lfms", stats->interval.latency_low);
		INFO("\tAverage   : %.3lfms", stats->interval.latency_average);
		INFO("\tMA        : %.3lfms", stats->latency_smoothed);
	}

	if (have_rt || stats->interval.lost || stats->interval.reused) {
		INFO("%s retransmits & loss:",  fr_packet_codes[code]);

		if (stats->interval.lost) {
			INFO("\tLost      : %.3lf/s", stats->interval.lost);
		}

		if (stats->interval.reused) {
			INFO("\tID Reused : %.3lf/s", stats->interval.reused);
		}

		for (i = 0; i <= RS_RETRANSMIT_MAX; i++) {
			if (!stats->interval.rt[i]) {
				continue;
			}

			if (i != RS_RETRANSMIT_MAX) {
				INFO("\tRT (%i)    : %.3lf/s", i, stats->interval.rt[i]);
			} else {
				INFO("\tRT (%i+)   : %.3lf/s", i, stats->interval.rt[i]);
			}
		}
	}
}

/** Query libpcap to see if it dropped any packets
 *
 * We need to check to see if libpcap dropped any packets and if it did, we need to stop stats output for long
 * enough for inaccurate statistics to be cleared out.
 *
 * @param in pcap handle to check.
 * @param interval time between checks (used for debug output)
 * @return 0, no drops, -1 we couldn't check, -2 dropped because of buffer exhaustion, -3 dropped because of NIC.
 */
static int rs_check_pcap_drop(fr_pcap_t *in, int interval) {
	int ret = 0;
	struct pcap_stat pstats;

	if (pcap_stats(in->handle, &pstats) != 0) {
		ERROR("%s failed retrieving pcap stats: %s", in->name, pcap_geterr(in->handle));
		return -1;
	}

	INFO("\t%s%*s: %.3lf/s", in->name, (int) (10 - strlen(in->name)), "",
	     ((double) (pstats.ps_recv - in->pstats.ps_recv)) / interval);

	if (pstats.ps_drop - in->pstats.ps_drop > 0) {
		ERROR("%s dropped %i packets: Buffer exhaustion", in->name, pstats.ps_drop - in->pstats.ps_drop);
		ret = -2;
	}

	if (pstats.ps_ifdrop - in->pstats.ps_ifdrop > 0) {
		ERROR("%s dropped %i packets: Interface", in->name, pstats.ps_ifdrop - in->pstats.ps_ifdrop);
		ret = -3;
	}

	in->pstats = pstats;

	return ret;
}

/** Update smoothed average
 *
 */
static void rs_stats_process_latency(rs_latency_t *stats)
{
	/*
	 *	If we didn't link any packets during this interval, we don't have a value to return.
	 *	returning 0 is misleading as it would be like saying the latency had dropped to 0.
	 *	We instead set NaN which libcollectd converts to a 'U' or unknown value.
	 *
	 *	This will cause gaps in graphs, but is completely legitimate as we are missing data.
	 *	This is unfortunately an effect of being just a passive observer.
	 */
	if (stats->interval.linked_total == 0) {
		double unk = strtod("NAN()", (char **) NULL);

		stats->interval.latency_average = unk;
		stats->interval.latency_high = unk;
		stats->interval.latency_low = unk;

		/*
		 *	We've not yet been able to determine latency, so latency_smoothed is also NaN
		 */
		if (stats->latency_smoothed_count == 0) {
			stats->latency_smoothed = unk;
		}
		return;
	}

	if (stats->interval.linked_total && stats->interval.latency_total) {
		stats->interval.latency_average = (stats->interval.latency_total / stats->interval.linked_total);
	}

	if (isnan(stats->latency_smoothed)) {
		stats->latency_smoothed = 0;
	}
	if (stats->interval.latency_average > 0) {
		stats->latency_smoothed_count++;
		stats->latency_smoothed += ((stats->interval.latency_average - stats->latency_smoothed) /
				       ((stats->latency_smoothed_count < 100) ? stats->latency_smoothed_count : 100));
	}
}

static void rs_stats_process_counters(rs_latency_t *stats)
{
	int i;

	stats->interval.received = ((long double) stats->interval.received_total) / conf->stats.interval;
	stats->interval.linked = ((long double) stats->interval.linked_total) / conf->stats.interval;
	stats->interval.unlinked = ((long double) stats->interval.unlinked_total) / conf->stats.interval;
	stats->interval.reused = ((long double) stats->interval.reused_total) / conf->stats.interval;
	stats->interval.lost = ((long double) stats->interval.lost_total) / conf->stats.interval;

	for (i = 0; i < RS_RETRANSMIT_MAX; i++) {
		stats->interval.rt[i] = ((long double) stats->interval.rt_total[i]) / conf->stats.interval;
	}
}

/** Process stats for a single interval
 *
 */
static void rs_stats_process(void *ctx)
{
	size_t i;
	size_t rs_codes_len = (sizeof(rs_useful_codes) / sizeof(*rs_useful_codes));
	fr_pcap_t		*in_p;
	rs_update_t		*this = ctx;
	rs_stats_t		*stats = this->stats;
	struct timeval		now;

	gettimeofday(&now, NULL);

	stats->intervals++;

	INFO("######### Stats Iteration %i #########", stats->intervals);

	/*
	 *	Verify that none of the pcap handles have dropped packets.
	 */
	INFO("Interface capture rate:");
	for (in_p = this->in;
	     in_p;
	     in_p = in_p->next) {
		if (rs_check_pcap_drop(in_p, conf->stats.interval) < 0) {
			ERROR("Muting stats for the next %i milliseconds", conf->stats.timeout);

			rs_tv_add_ms(&now, conf->stats.timeout, &stats->quiet);
			goto clear;
		}
	}

	if ((stats->quiet.tv_sec + (stats->quiet.tv_usec / 1000000.0)) -
	    (now.tv_sec + (now.tv_usec / 1000000.0)) > 0) {
		INFO("Stats muted because of warmup, or previous error");
		goto clear;
	}

	/*
	 *	Latency stats need a bit more work to calculate the SMA.
	 *
	 *	No further work is required for codes.
	 */
	for (i = 0; i < rs_codes_len; i++) {
		rs_stats_process_latency(&stats->exchange[rs_useful_codes[i]]);
		rs_stats_process_counters(&stats->exchange[rs_useful_codes[i]]);
		if (fr_debug_lvl > 0) {
			rs_stats_print(&stats->exchange[rs_useful_codes[i]], rs_useful_codes[i]);
		}
	}

#ifdef HAVE_COLLECTDC_H
	/*
	 *	Update stats in collectd using the complex structures we
	 *	initialised earlier.
	 */
	if ((conf->stats.out == RS_STATS_OUT_COLLECTD) && conf->stats.handle) {
		rs_stats_collectd_do_stats(conf, conf->stats.tmpl, &now);
	}
#endif

	clear:
	/*
	 *	Rinse and repeat...
	 */
	for (i = 0; i < rs_codes_len; i++) {
		memset(&stats->exchange[rs_useful_codes[i]].interval, 0,
		       sizeof(stats->exchange[rs_useful_codes[i]].interval));
	}

	{
		static fr_event_t *event;

		now.tv_sec += conf->stats.interval;
		now.tv_usec = 0;

		if (!fr_event_insert(this->list, rs_stats_process, ctx, &now, &event)) {
			ERROR("Failed inserting stats interval event");
		}
	}
}


/** Update latency statistics for request/response and forwarded packets
 *
 */
static void rs_stats_update_latency(rs_latency_t *stats, struct timeval *latency)
{
	double lint;

	stats->interval.linked_total++;
	/* More useful is this in milliseconds */
	lint = (latency->tv_sec + (latency->tv_usec / 1000000.0)) * 1000;
	if (lint > stats->interval.latency_high) {
		stats->interval.latency_high = lint;
	}
	if (!stats->interval.latency_low || (lint < stats->interval.latency_low)) {
		stats->interval.latency_low = lint;
	}
	stats->interval.latency_total += lint;

}

/** Copy a subset of attributes from one list into the other
 *
 * Should be O(n) if all the attributes exist.  List must be pre-sorted.
 */
static int rs_get_pairs(TALLOC_CTX *ctx, VALUE_PAIR **out, VALUE_PAIR *vps, DICT_ATTR const *da[], int num)
{
	vp_cursor_t list_cursor, out_cursor;
	VALUE_PAIR *match, *last_match, *copy;
	uint64_t count = 0;
	int i;

	last_match = vps;

	fr_cursor_init(&list_cursor, &last_match);
	fr_cursor_init(&out_cursor, out);
	for (i = 0; i < num; i++) {
		match = fr_cursor_next_by_da(&list_cursor, da[i], TAG_ANY);
		if (!match) {
			fr_cursor_init(&list_cursor, &last_match);
			continue;
		}

		do {
			copy = fr_pair_copy(ctx, match);
			if (!copy) {
				fr_pair_list_free(out);
				return -1;
			}
			fr_cursor_insert(&out_cursor, copy);
			last_match = match;

			count++;
		} while ((match = fr_cursor_next_by_da(&list_cursor, da[i], TAG_ANY)));
	}

	return count;
}

static int _request_free(rs_request_t *request)
{
	bool ret;

	/*
	 *	If were attempting to cleanup the request, and it's no longer in the request_tree
	 *	something has gone very badly wrong.
	 */
	if (request->in_request_tree) {
		ret = rbtree_deletebydata(request_tree, request);
		RS_ASSERT(ret);
	}

	if (request->in_link_tree) {
		ret = rbtree_deletebydata(link_tree, request);
		RS_ASSERT(ret);
	}

	if (request->event) {
		ret = fr_event_delete(events, &request->event);
		RS_ASSERT(ret);
	}

	rad_free(&request->packet);
	rad_free(&request->expect);
	rad_free(&request->linked);

	return 0;
}

static void rs_packet_cleanup(rs_request_t *request)
{

	RADIUS_PACKET *packet = request->packet;
	uint64_t count = request->id;

	RS_ASSERT(request->stats_req);
	RS_ASSERT(!request->rt_rsp || request->stats_rsp);
	RS_ASSERT(packet);

	/*
	 *	Don't pollute stats or print spurious messages as radsniff closes.
	 */
	if (cleanup) {
		talloc_free(request);
		return;
	}

	if (RIDEBUG_ENABLED()) {
		rs_time_print(timestr, sizeof(timestr), &request->when);
	}

	/*
	 *	Were at packet cleanup time which is when the packet was received + timeout
	 *	and it's not been linked with a forwarded packet or a response.
	 *
	 *	We now count it as lost.
	 */
	if (!request->silent_cleanup) {
		if (!request->linked) {
			if (!request->stats_req) return;

			request->stats_req->interval.lost_total++;

			if (conf->event_flags & RS_LOST) {
				/* @fixme We should use flags in the request to indicate whether it's been dumped
				 * to a PCAP file or logged yet, this simplifies the body logging logic */
				rs_packet_print(request, request->id, RS_LOST, request->in, packet, NULL, NULL, false,
					        conf->filter_response_vps || !(conf->event_flags & RS_NORMAL));
			}
		}

		if ((request->in->type == PCAP_INTERFACE_IN) && request->logged) {
			RDEBUG("Cleaning up request packet ID %i", request->expect->id);
		}
	}

	/*
	 *	Now the request is done, we can update the retransmission stats
	 */
	if (request->rt_req > RS_RETRANSMIT_MAX) {
		request->stats_req->interval.rt_total[RS_RETRANSMIT_MAX]++;
	} else {
		request->stats_req->interval.rt_total[request->rt_req]++;
	}

	if (request->rt_rsp) {
		if (request->rt_rsp > RS_RETRANSMIT_MAX) {
			request->stats_rsp->interval.rt_total[RS_RETRANSMIT_MAX]++;
		} else {
			request->stats_rsp->interval.rt_total[request->rt_rsp]++;
		}
	}

	talloc_free(request);
}

static void _rs_event(void *ctx)
{
	rs_request_t *request = talloc_get_type_abort(ctx, rs_request_t);
	request->event = NULL;
	rs_packet_cleanup(request);
}

/** Wrapper around fr_packet_cmp to strip off the outer request struct
 *
 */
static int rs_packet_cmp(rs_request_t const *a, rs_request_t const *b)
{
	return fr_packet_cmp(a->expect, b->expect);
}

static inline int rs_response_to_pcap(rs_event_t *event, rs_request_t *request, struct pcap_pkthdr const *header,
				      uint8_t const *data)
{
	if (!event->out) return 0;

	/*
	 *	If we're filtering by response then the requests then the capture buffer
	 *	associated with the request should contain buffered request packets.
	 */
	if (conf->filter_response && request) {
		rs_capture_t *start;

		/*
		 *	Record the current position in the header
		 */
		start = request->capture_p;

		/*
		 *	Buffer hasn't looped set capture_p to the start of the buffer
		 */
		if (!start->header) request->capture_p = request->capture;

		/*
		 *	If where capture_p points to, has a header set, write out the
		 *	packet to the PCAP file, looping over the buffer until we
		 *	hit our start point.
		 */
		if (request->capture_p->header) do {
			pcap_dump((void *)event->out->dumper, request->capture_p->header,
				  request->capture_p->data);
			TALLOC_FREE(request->capture_p->header);
			TALLOC_FREE(request->capture_p->data);

			/* Reset the pointer to the start of the circular buffer */
			if (request->capture_p++ >=
					(request->capture +
					 sizeof(request->capture) / sizeof(*request->capture))) {
				request->capture_p = request->capture;
			}
		} while (request->capture_p != start);
	}

	/*
	 *	Now log the response
	 */
	pcap_dump((void *)event->out->dumper, header, data);

	return 0;
}

static inline int rs_request_to_pcap(rs_event_t *event, rs_request_t *request, struct pcap_pkthdr const *header,
				     uint8_t const *data)
{
	if (!event->out) return 0;

	/*
	 *	If we're filtering by response, then we need to wait to write out the requests
	 */
	if (conf->filter_response) {
		/* Free the old capture */
		if (request->capture_p->header) {
			talloc_free(request->capture_p->header);
			TALLOC_FREE(request->capture_p->data);
		}

		if (!(request->capture_p->header = talloc(request, struct pcap_pkthdr))) return -1;
		if (!(request->capture_p->data = talloc_array(request, uint8_t, header->caplen))) {
			TALLOC_FREE(request->capture_p->header);
			return -1;
		}
		memcpy(request->capture_p->header, header, sizeof(struct pcap_pkthdr));
		memcpy(request->capture_p->data, data, header->caplen);

		/* Reset the pointer to the start of the circular buffer */
		if (++request->capture_p >=
				(request->capture +
				 sizeof(request->capture) / sizeof(*request->capture))) {
			request->capture_p = request->capture;
		}
		return 0;
	}

	pcap_dump((void *)event->out->dumper, header, data);

	return 0;
}

/* This is the same as immediately scheduling the cleanup event */
#define RS_CLEANUP_NOW(_x, _s)\
	{\
		_x->silent_cleanup = _s;\
		_x->when = header->ts;\
		rs_packet_cleanup(_x);\
		_x = NULL;\
	} while (0)

static void rs_packet_process(uint64_t count, rs_event_t *event, struct pcap_pkthdr const *header, uint8_t const *data)
{
	rs_stats_t		*stats = event->stats;
	struct timeval		elapsed = {0, 0};
	struct timeval		latency;

	/*
	 *	Pointers into the packet data we just received
	 */
	ssize_t len;
	uint8_t const		*p = data;

	ip_header_t const	*ip = NULL;		/* The IP header */
	ip_header6_t const	*ip6 = NULL;		/* The IPv6 header */
	udp_header_t const	*udp;			/* The UDP header */
	uint8_t			version;		/* IP header version */
	bool			response;		/* Was it a response code */

	decode_fail_t		reason;			/* Why we failed decoding the packet */
	static uint64_t		captured = 0;

	rs_status_t		status = RS_NORMAL;	/* Any special conditions (RTX, Unlinked, ID-Reused) */
	RADIUS_PACKET		*current;		/* Current packet were processing */
	rs_request_t		*original = NULL;

	rs_request_t		search;

	memset(&search, 0, sizeof(search));

	if (!start_pcap.tv_sec) {
		start_pcap = header->ts;
	}

	if (RIDEBUG_ENABLED()) {
		rs_time_print(timestr, sizeof(timestr), &header->ts);
	}

	len = fr_link_layer_offset(data, header->caplen, event->in->link_layer);
	if (len < 0) {
		REDEBUG("Failed determining link layer header offset");
		return;
	}
	p += len;

	version = (p[0] & 0xf0) >> 4;
	switch (version) {
	case 4:
		ip = (ip_header_t const *)p;
		len = (0x0f & ip->ip_vhl) * 4;	/* ip_hl specifies length in 32bit words */
		p += len;
		break;

	case 6:
		ip6 = (ip_header6_t const *)p;
		p += sizeof(ip_header6_t);

		break;

	default:
		REDEBUG("IP version invalid %i", version);
		return;
	}

	/*
	 *	End of variable length bits, do basic check now to see if packet looks long enough
	 */
	len = (p - data) + sizeof(udp_header_t) + sizeof(radius_packet_t);	/* length value */
	if ((size_t) len > header->caplen) {
		REDEBUG("Packet too small, we require at least %zu bytes, captured %i bytes",
			(size_t) len, header->caplen);
		return;
	}

	/*
	 *	UDP header validation.
	 */
	udp = (udp_header_t const *)p;
	{
		uint16_t udp_len;
		ssize_t diff;

		udp_len = ntohs(udp->len);
		diff = udp_len - (header->caplen - (p - data));
		/* Truncated data */
		if (diff > 0) {
			REDEBUG("Packet too small by %zi bytes, UDP header + Payload should be %hu bytes",
				diff, udp_len);
			return;
		}

#if 0
		/*
		 *	It seems many probes add trailing garbage to the end
		 *	of each capture frame.  This has been observed with
		 *	the F5 and Netscout.
		 *
		 *	Leaving the code here in case it's ever needed for
		 *	debugging.
		 */
		else if (diff < 0) {
			REDEBUG("Packet too big by %zi bytes, UDP header + Payload should be %hu bytes",
				diff * -1, udp_len);
			return;
		}
#endif
	}
	if ((version == 4) && conf->verify_udp_checksum) {
		uint16_t expected;

		expected = fr_udp_checksum((uint8_t const *) udp, ntohs(udp->len), udp->checksum,
					   ip->ip_src, ip->ip_dst);
		if (udp->checksum != expected) {
			REDEBUG("UDP checksum invalid, packet: 0x%04hx calculated: 0x%04hx",
				ntohs(udp->checksum), ntohs(expected));
			/* Not a fatal error */
		}
	}
	p += sizeof(udp_header_t);

	/*
	 *	With artificial talloc memory limits there's a good chance we can
	 *	recover once some requests timeout, so make an effort to deal
	 *	with allocation failures gracefully.
	 */
	current = rad_alloc(conf, false);
	if (!current) {
		REDEBUG("Failed allocating memory to hold decoded packet");
		rs_tv_add_ms(&header->ts, conf->stats.timeout, &stats->quiet);
		return;
	}

	current->timestamp = header->ts;
	current->data_len = header->caplen - (p - data);
	memcpy(&current->data, &p, sizeof(current->data));

	/*
	 *	Populate IP/UDP fields from PCAP data
	 */
	if (ip) {
		current->src_ipaddr.af = AF_INET;
		current->src_ipaddr.ipaddr.ip4addr.s_addr = ip->ip_src.s_addr;

		current->dst_ipaddr.af = AF_INET;
		current->dst_ipaddr.ipaddr.ip4addr.s_addr = ip->ip_dst.s_addr;
	} else {
		current->src_ipaddr.af = AF_INET6;
		memcpy(current->src_ipaddr.ipaddr.ip6addr.s6_addr, ip6->ip_src.s6_addr,
		       sizeof(current->src_ipaddr.ipaddr.ip6addr.s6_addr));

		current->dst_ipaddr.af = AF_INET6;
		memcpy(current->dst_ipaddr.ipaddr.ip6addr.s6_addr, ip6->ip_dst.s6_addr,
		       sizeof(current->dst_ipaddr.ipaddr.ip6addr.s6_addr));
	}

	current->src_port = ntohs(udp->src);
	current->dst_port = ntohs(udp->dst);

	if (!rad_packet_ok(current, 0, &reason)) {
		REDEBUG("%s", fr_strerror());
		if (conf->event_flags & RS_ERROR) {
			rs_packet_print(NULL, count, RS_ERROR, event->in, current, &elapsed, NULL, false, false);
		}
		rad_free(&current);

		return;
	}

	switch (current->code) {
	case PW_CODE_ACCOUNTING_RESPONSE:
	case PW_CODE_ACCESS_REJECT:
	case PW_CODE_ACCESS_ACCEPT:
	case PW_CODE_ACCESS_CHALLENGE:
	case PW_CODE_COA_NAK:
	case PW_CODE_COA_ACK:
	case PW_CODE_DISCONNECT_NAK:
	case PW_CODE_DISCONNECT_ACK:
	case PW_CODE_STATUS_CLIENT:
	{
		/* look for a matching request and use it for decoding */
		search.expect = current;
		original = rbtree_finddata(request_tree, &search);

		/*
		 *	Verify this code is allowed
		 */
		if (conf->filter_response_code && (conf->filter_response_code != current->code)) {
			drop_response:
			RDEBUG2("Response dropped by filter");
			rad_free(&current);

			/* We now need to cleanup the original request too */
			if (original) {
				RS_CLEANUP_NOW(original, true);
			}
			return;
		}

		/*
		 *	Only decode attributes if we want to print them or filter on them
		 *	rad_packet_ok does checks to verify the packet is actually valid.
		 */
		if (conf->decode_attrs) {
			int ret;
			FILE *log_fp = fr_log_fp;

			fr_log_fp = NULL;
			ret = rad_decode(current, original ? original->expect : NULL, conf->radius_secret);
			fr_log_fp = log_fp;
			if (ret != 0) {
				rad_free(&current);
				REDEBUG("Failed decoding");
				return;
			}
		}

		/*
		 *	Check if we've managed to link it to a request
		 */
		if (original) {
			/*
			 *	Now verify the packet passes the attribute filter
			 */
			if (conf->filter_response_vps) {
				fr_pair_list_sort(&current->vps, fr_pair_cmp_by_da_tag);
				if (!fr_pair_validate_relaxed(NULL, conf->filter_response_vps, current->vps)) {
					goto drop_response;
				}
			}

			/*
			 *	Is this a retransmission?
			 */
			if (original->linked) {
				status = RS_RTX;
				original->rt_rsp++;

				rad_free(&original->linked);
				fr_event_delete(event->list, &original->event);
			/*
			 *	...nope it's the first response to a request.
			 */
			} else {
				original->stats_rsp = &stats->exchange[current->code];
			}

			/*
			 *	Insert a callback to remove the request and response
			 *	from the tree after the timeout period.
			 *	The delay is so we can detect retransmissions.
			 */
			original->linked = talloc_steal(original, current);
			rs_tv_add_ms(&header->ts, conf->stats.timeout, &original->when);
			if (!fr_event_insert(event->list, _rs_event, original, &original->when,
					     &original->event)) {
				REDEBUG("Failed inserting new event");
				/*
				 *	Delete the original request/event, it's no longer valid
				 *	for statistics.
				 */
				talloc_free(original);
				return;
			}
		/*
		 *	No request seen, or request was dropped by attribute filter
		 */
		} else {
			/*
			 *	If conf->filter_request_vps are set assume the original request was dropped,
			 *	the alternative is maintaining another 'filter', but that adds
			 *	complexity, reduces max capture rate, and is generally a PITA.
			 */
			if (conf->filter_request) {
				rad_free(&current);
				RDEBUG2("Original request dropped by filter");
				return;
			}

			status = RS_UNLINKED;
			stats->exchange[current->code].interval.unlinked_total++;
		}

		rs_response_to_pcap(event, original, header, data);
		response = true;
		break;
	}

	case PW_CODE_ACCOUNTING_REQUEST:
	case PW_CODE_ACCESS_REQUEST:
	case PW_CODE_COA_REQUEST:
	case PW_CODE_DISCONNECT_REQUEST:
	case PW_CODE_STATUS_SERVER:
	{
		/*
		 *	Verify this code is allowed
		 */
		if (conf->filter_request_code && (conf->filter_request_code != current->code)) {
			drop_request:

			RDEBUG2("Request dropped by filter");
			rad_free(&current);

			return;
		}

		/*
		 *	Only decode attributes if we want to print them or filter on them
		 *	rad_packet_ok does checks to verify the packet is actually valid.
		 */
		if (conf->decode_attrs) {
			int ret;
			FILE *log_fp = fr_log_fp;

			fr_log_fp = NULL;
			ret = rad_decode(current, NULL, conf->radius_secret);
			fr_log_fp = log_fp;

			if (ret != 0) {
				rad_free(&current);
				REDEBUG("Failed decoding");
				return;
			}

			fr_pair_list_sort(&current->vps, fr_pair_cmp_by_da_tag);
		}

		/*
		 *	Save the request for later matching
		 */
		search.expect = rad_alloc_reply(current, current);
		if (!search.expect) {
			REDEBUG("Failed allocating memory to hold expected reply");
			rs_tv_add_ms(&header->ts, conf->stats.timeout, &stats->quiet);
			rad_free(&current);
			return;
		}
		search.expect->code = current->code;

		if ((conf->link_da_num > 0) && current->vps) {
			int ret;
			ret = rs_get_pairs(current, &search.link_vps, current->vps, conf->link_da,
					   conf->link_da_num);
			if (ret < 0) {
				ERROR("Failed extracting RTX linking pairs from request");
				rad_free(&current);
				return;
			}
		}

		/*
		 *	If we have linking attributes set, attempt to find a request in the linking tree.
		 */
		if (search.link_vps) {
			rs_request_t *tuple;

			original = rbtree_finddata(link_tree, &search);
			tuple = rbtree_finddata(request_tree, &search);

			/*
			 *	If the packet we matched using attributes is not the same
			 *	as the packet in the request tree, then we need to clean up
			 *	the packet in the request tree.
			 */
			if (tuple && (original != tuple)) {
				RS_CLEANUP_NOW(tuple, true);
			}
		/*
		 *	Detect duplicates using the normal 5-tuple of src/dst ips/ports id
		 */
		} else {
			original = rbtree_finddata(request_tree, &search);
			if (original && (memcmp(original->expect->vector, current->vector,
			    			sizeof(original->expect->vector)) != 0)) {
				/*
				 *	ID reused before the request timed out (which may be an issue)...
				 */
				if (!original->linked) {
					status = RS_REUSED;
					stats->exchange[current->code].interval.reused_total++;
					/* Occurs regularly downstream of proxy servers (so don't complain) */
					RS_CLEANUP_NOW(original, true);
				/*
				 *	...and before we saw a response (which may be a bigger issue).
				 */
				} else {
					RS_CLEANUP_NOW(original, false);
				}
				/* else it's a proper RTX with the same src/dst id authenticator/nonce */
			}
		}

		/*
		 *	Now verify the packet passes the attribute filter
		 */
		if (conf->filter_request_vps) {
			if (!fr_pair_validate_relaxed(NULL, conf->filter_request_vps, current->vps)) {
				goto drop_request;
			}
		}

		/*
		 *	Is this a retransmission?
		 */
		if (original) {
			status = RS_RTX;
			original->rt_req++;

			rad_free(&original->packet);

			/* We may of seen the response, but it may of been lost upstream */
			rad_free(&original->linked);

			original->packet = talloc_steal(original, current);

			/* Request may need to be reinserted as the 5 tuple of the response may of changed */
			if (rs_packet_cmp(original, &search) != 0) {
				rbtree_deletebydata(request_tree, original);
			}

			rad_free(&original->expect);
			original->expect = talloc_steal(original, search.expect);

			/* Disarm the timer for the cleanup event for the original request */
			fr_event_delete(event->list, &original->event);
		/*
		 *	...nope it's a new request.
		 */
		} else {
			original = talloc_zero(conf, rs_request_t);
			talloc_set_destructor(original, _request_free);

			original->id = count;
			original->in = event->in;
			original->stats_req = &stats->exchange[current->code];

			/* Set the packet pointer to the start of the buffer*/
			original->capture_p = original->capture;

			original->packet = talloc_steal(original, current);
			original->expect = talloc_steal(original, search.expect);

			if (search.link_vps) {
				bool ret;
				vp_cursor_t cursor;
				VALUE_PAIR *vp;

				for (vp = fr_cursor_init(&cursor, &search.link_vps);
				     vp;
				     vp = fr_cursor_next(&cursor)) {
					fr_pair_steal(original, search.link_vps);
				}
				original->link_vps = search.link_vps;

				/* We should never have conflicts */
				ret = rbtree_insert(link_tree, original);
				RS_ASSERT(ret);
				original->in_link_tree = true;
			}

			/*
			 *	Special case for when were filtering by response,
			 *	we never count any requests as lost, because we
			 *	don't know what the response to that request would
			 *	of been.
			 */
			if (conf->filter_response_vps) {
				original->silent_cleanup = true;
			}
		}

		if (!original->in_request_tree) {
			bool ret;

			/* We should never have conflicts */
			ret = rbtree_insert(request_tree, original);
			RS_ASSERT(ret);
			original->in_request_tree = true;
		}

		/*
		 *	Insert a callback to remove the request from the tree
		 */
		original->packet->timestamp = header->ts;
		rs_tv_add_ms(&header->ts, conf->stats.timeout, &original->when);
		if (!fr_event_insert(event->list, _rs_event, original,
				     &original->when, &original->event)) {
			REDEBUG("Failed inserting new event");

			talloc_free(original);
			return;
		}
		rs_request_to_pcap(event, original, header, data);
		response = false;
		break;
	}

	default:
		REDEBUG("Unsupported code %i", current->code);
		rad_free(&current);

		return;
	}

	rs_tv_sub(&header->ts, &start_pcap, &elapsed);

	/*
	 *	Increase received count
	 */
	stats->exchange[current->code].interval.received_total++;

	/*
	 *	It's a linked response
	 */
	if (original && original->linked) {
		rs_tv_sub(&current->timestamp, &original->packet->timestamp, &latency);

		/*
		 *	Update stats for both the request and response types.
		 *
		 *	This isn't useful for things like Access-Requests, but will be useful for
		 *	CoA and Disconnect Messages, as we get the average latency across both
		 *	response types.
		 *
		 *	It also justifies allocating PW_CODE_MAX instances of rs_latency_t.
		 */
		rs_stats_update_latency(&stats->exchange[current->code], &latency);
		rs_stats_update_latency(&stats->exchange[original->expect->code], &latency);

		/*
		 *	Were filtering on response, now print out the full data from the request
		 */
		if (conf->filter_response && RIDEBUG_ENABLED() && (conf->event_flags & RS_NORMAL)) {
			rs_time_print(timestr, sizeof(timestr), &original->packet->timestamp);
			rs_tv_sub(&original->packet->timestamp, &start_pcap, &elapsed);
			rs_packet_print(original, original->id, RS_NORMAL, original->in,
					original->packet, &elapsed, NULL, false, true);
			rs_tv_sub(&header->ts, &start_pcap, &elapsed);
			rs_time_print(timestr, sizeof(timestr), &header->ts);
		}

		if (conf->event_flags & status) {
			rs_packet_print(original, count, status, event->in, current,
					&elapsed, &latency, response, true);
		}
	/*
	 *	It's the original request
	 *
	 *	If were filtering on responses we can only indicate we received it on response, or timeout.
	 */
	} else if (!conf->filter_response && (conf->event_flags & status)) {
		rs_packet_print(original, original ? original->id : count, status, event->in,
				current, &elapsed, NULL, response, true);
	}

	fflush(fr_log_fp);

	/*
	 *	If it's a unlinked response, we need to free it explicitly, as it will
	 *	not be done by the event queue.
	 */
	if (response && !original) {
		rad_free(&current);
	}

	captured++;
	/*
	 *	We've hit our capture limit, break out of the event loop
	 */
	if ((conf->limit > 0) && (captured >= conf->limit)) {
		INFO("Captured %" PRIu64 " packets, exiting...", captured);
		fr_event_loop_exit(events, 1);
	}
}

static void rs_got_packet(fr_event_list_t *el, int fd, void *ctx)
{
	static uint64_t	count = 0;	/* Packets seen */
	rs_event_t	*event = ctx;
	pcap_t		*handle = event->in->handle;

	int i;
	int ret;
	const uint8_t *data;
	struct pcap_pkthdr *header;

	/*
	 *	Consume entire capture, interleaving not currently possible
	 */
	if ((event->in->type == PCAP_FILE_IN) || (event->in->type == PCAP_STDIO_IN)) {
		while (!fr_event_loop_exiting(el)) {
			struct timeval now;

			ret = pcap_next_ex(handle, &header, &data);
			if (ret == 0) {
				/* No more packets available at this time */
				return;
			}
			if (ret == -2) {
				DEBUG("Done reading packets (%s)", event->in->name);
				fr_event_fd_delete(events, 0, fd);

				/* Signal pipe takes one slot which is why this is == 1 */
				if (fr_event_list_num_fds(events) == 1) {
					fr_event_loop_exit(events, 1);
				}

				return;
			}
			if (ret < 0) {
				ERROR("Error requesting next packet, got (%i): %s", ret, pcap_geterr(handle));
				return;
			}

			do {
				now = header->ts;
			} while (fr_event_run(el, &now) == 1);
			count++;

			rs_packet_process(count, event, header, data);
		}
		return;
	}

	/*
	 *	Consume multiple packets from the capture buffer.
	 *	We occasionally need to yield to allow events to run.
	 */
	for (i = 0; i < RS_FORCE_YIELD; i++) {
		ret = pcap_next_ex(handle, &header, &data);
		if (ret == 0) {
			/* No more packets available at this time */
			return;
		}
		if (ret < 0) {
			ERROR("Error requesting next packet, got (%i): %s", ret, pcap_geterr(handle));
			return;
		}

		count++;
		rs_packet_process(count, event, header, data);
	}
}

static void _rs_event_status(struct timeval *wake)
{
	if (wake && ((wake->tv_sec != 0) || (wake->tv_usec >= 100000))) {
		DEBUG2("Waking up in %d.%01u seconds.", (int) wake->tv_sec, (unsigned int) wake->tv_usec / 100000);

		if (RIDEBUG_ENABLED()) {
			rs_time_print(timestr, sizeof(timestr), wake);
		}
	}
}

/** Compare requests using packet info and lists of attributes
 *
 */
static int rs_rtx_cmp(rs_request_t const *a, rs_request_t const *b)
{
	int rcode;

	RS_ASSERT(a->link_vps);
	RS_ASSERT(b->link_vps);

	rcode = (int) a->expect->code - (int) b->expect->code;
	if (rcode != 0) return rcode;

	rcode = a->expect->sockfd - b->expect->sockfd;
	if (rcode != 0) return rcode;

	rcode = fr_ipaddr_cmp(&a->expect->src_ipaddr, &b->expect->src_ipaddr);
	if (rcode != 0) return rcode;

	rcode = fr_ipaddr_cmp(&a->expect->dst_ipaddr, &b->expect->dst_ipaddr);
	if (rcode != 0) return rcode;

	return fr_pair_list_cmp(a->link_vps, b->link_vps);
}

static int rs_build_dict_list(DICT_ATTR const **out, size_t len, char *list)
{
	size_t i = 0;
	char *p, *tok;

	p = list;
	while ((tok = strsep(&p, "\t ,")) != NULL) {
		DICT_ATTR const *da;
		if ((*tok == '\t') || (*tok == ' ') || (*tok == '\0')) {
			continue;
		}

		if (i == len) {
			ERROR("Too many attributes, maximum allowed is %zu", len);
			return -1;
		}

		da = dict_attrbyname(tok);
		if (!da) {
			ERROR("Error parsing attribute name \"%s\"", tok);
			return -1;
		}

		out[i] = da;
		i++;
	}

	/*
	 *	This allows efficient list comparisons later
	 */
	if (i > 1) fr_quick_sort((void const **)out, 0, i - 1, fr_pointer_cmp);

	return i;
}

static int rs_build_filter(VALUE_PAIR **out, char const *filter)
{
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	FR_TOKEN code;

	code = fr_pair_list_afrom_str(conf, filter, out);
	if (code == T_INVALID) {
		ERROR("Invalid RADIUS filter \"%s\" (%s)", filter, fr_strerror());
		return -1;
	}

	if (!*out) {
		ERROR("Empty RADIUS filter '%s'", filter);
		return -1;
	}

	for (vp = fr_cursor_init(&cursor, out);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	xlat expansion isn't supported here
		 */
		if (vp->type == VT_XLAT) {
			vp->type = VT_DATA;
			vp->vp_strvalue = vp->value.xlat;
			vp->vp_length = talloc_array_length(vp->vp_strvalue) - 1;
		}
	}

	/*
	 *	This allows efficient list comparisons later
	 */
	fr_pair_list_sort(out, fr_pair_cmp_by_da_tag);

	return 0;
}

static int rs_build_event_flags(int *flags, FR_NAME_NUMBER const *map, char *list)
{
	size_t i = 0;
	char *p, *tok;

	p = list;
	while ((tok = strsep(&p, "\t ,")) != NULL) {
		int flag;

		if ((*tok == '\t') || (*tok == ' ') || (*tok == '\0')) {
			continue;
		}

		*flags |= flag = fr_str2int(map, tok, -1);
		if (flag < 0) {
			ERROR("Invalid flag \"%s\"", tok);
			return -1;
		}

		i++;
	}

	return i;
}

/** Callback for when the request is removed from the request tree
 *
 * @param request being removed.
 */
static void _unmark_request(void *request)
{
	rs_request_t *this = request;
	this->in_request_tree = false;
}

/** Callback for when the request is removed from the link tree
 *
 * @param request being removed.
 */
static void _unmark_link(void *request)
{
	rs_request_t *this = request;
	this->in_link_tree = false;
}

#ifdef HAVE_COLLECTDC_H
/** Re-open the collectd socket
 *
 */
static void rs_collectd_reopen(void *ctx)
{
	fr_event_list_t *list = ctx;
	static fr_event_t *event;
	struct timeval now, when;

	if (rs_stats_collectd_open(conf) == 0) {
		DEBUG2("Stats output socket (re)opened");
		return;
	}

	ERROR("Will attempt to re-establish connection in %i ms", RS_SOCKET_REOPEN_DELAY);

	gettimeofday(&now, NULL);
	rs_tv_add_ms(&now, RS_SOCKET_REOPEN_DELAY, &when);
	if (!fr_event_insert(list, rs_collectd_reopen, list, &when, &event)) {
		ERROR("Failed inserting re-open event");
		RS_ASSERT(0);
	}
}
#endif

/** Write the last signal to the signal pipe
 *
 * @param sig raised
 */
static void rs_signal_self(int sig)
{
	if (write(self_pipe[1], &sig, sizeof(sig)) < 0) {
		ERROR("Failed writing signal %s to pipe: %s", strsignal(sig), fr_syserror(errno));
		exit(EXIT_FAILURE);
	}
}

/** Read the last signal from the signal pipe
 *
 */
static void rs_signal_action(
#ifndef HAVE_COLLECTDC_H
UNUSED
#endif
fr_event_list_t *list, int fd, UNUSED void *ctx)
{
	int sig;
	ssize_t ret;

	ret = read(fd, &sig, sizeof(sig));
	if (ret < 0) {
		ERROR("Failed reading signal from pipe: %s", fr_syserror(errno));
		exit(EXIT_FAILURE);
	}

	if (ret != sizeof(sig)) {
		ERROR("Failed reading signal from pipe: "
		      "Expected signal to be %zu bytes but only read %zu byes", sizeof(sig), ret);
		exit(EXIT_FAILURE);
	}

	switch (sig) {
#ifdef HAVE_COLLECTDC_H
	case SIGPIPE:
		rs_collectd_reopen(list);
		break;
#endif

	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
		DEBUG2("Signalling event loop to exit");
		fr_event_loop_exit(events, 1);
		break;

	default:
		ERROR("Unhandled signal %s", strsignal(sig));
		exit(EXIT_FAILURE);
	}
}

static void NEVER_RETURNS usage(int status)
{
	FILE *output = status ? stderr : stdout;
	fprintf(output, "Usage: radsniff [options][stats options] -- [pcap files]\n");
	fprintf(output, "options:\n");
	fprintf(output, "  -a                    List all interfaces available for capture.\n");
	fprintf(output, "  -c <count>            Number of packets to capture.\n");
	fprintf(output, "  -C                    Enable UDP checksum validation.\n");
	fprintf(output, "  -d <directory>        Set dictionary directory.\n");
	fprintf(output, "  -d <raddb>            Set configuration directory (defaults to " RADDBDIR ").\n");
	fprintf(output, "  -D <dictdir>          Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(output, "  -e <event>[,<event>]  Only log requests with these event flags.\n");
	fprintf(output, "                        Event may be one of the following:\n");
	fprintf(output, "                        - received - a request or response.\n");
	fprintf(output, "                        - norsp    - seen for a request.\n");
	fprintf(output, "                        - rtx      - of a request that we've seen before.\n");
	fprintf(output, "                        - noreq    - could be matched with the response.\n");
	fprintf(output, "                        - reused   - ID too soon.\n");
	fprintf(output, "                        - error    - decoding the packet.\n");
	fprintf(output, "  -f <filter>           PCAP filter (default is 'udp port <port> or <port + 1> or 3799')\n");
	fprintf(output, "  -h                    This help message.\n");
	fprintf(output, "  -i <interface>        Capture packets from interface (defaults to all if supported).\n");
	fprintf(output, "  -I <file>             Read packets from file (overrides input of -F).\n");
	fprintf(output, "  -l <attr>[,<attr>]    Output packet sig and a list of attributes.\n");
	fprintf(output, "  -L <attr>[,<attr>]    Detect retransmissions using these attributes to link requests.\n");
	fprintf(output, "  -m                    Don't put interface(s) into promiscuous mode.\n");
	fprintf(output, "  -p <port>             Filter packets by port (default is 1812).\n");
	fprintf(output, "  -P <pidfile>          Daemonize and write out <pidfile>.\n");
	fprintf(output, "  -q                    Print less debugging information.\n");
	fprintf(output, "  -r <filter>           RADIUS attribute request filter.\n");
	fprintf(output, "  -R <filter>           RADIUS attribute response filter.\n");
	fprintf(output, "  -s <secret>           RADIUS secret.\n");
	fprintf(output, "  -S                    Write PCAP data to stdout.\n");
	fprintf(output, "  -v                    Show program version information.\n");
	fprintf(output, "  -w <file>             Write output packets to file.\n");
	fprintf(output, "  -x                    Print more debugging information.\n");
	fprintf(output, "stats options:\n");
	fprintf(output, "  -W <interval>         Periodically write out statistics every <interval> seconds.\n");
	fprintf(output, "  -T <timeout>          How many milliseconds before the request is counted as lost "
		"(defaults to %i).\n", RS_DEFAULT_TIMEOUT);
#ifdef HAVE_COLLECTDC_H
	fprintf(output, "  -N <prefix>           The instance name passed to the collectd plugin.\n");
	fprintf(output, "  -O <server>           Write statistics to this collectd server.\n");
#endif
	exit(status);
}

int main(int argc, char *argv[])
{
	fr_pcap_t *in = NULL, *in_p;
	fr_pcap_t **in_head = &in;
	fr_pcap_t *out = NULL;

	int ret = 1;					/* Exit status */

	char errbuf[PCAP_ERRBUF_SIZE];			/* Error buffer */
	int port = 1812;

	char buffer[1024];

	int opt;
	char const *radius_dir = RADDBDIR;
	char const *dict_dir = DICTDIR;

	rs_stats_t stats;

	fr_debug_lvl = 1;
	fr_log_fp = stdout;

	/*
	 *	Useful if using radsniff as a long running stats daemon
	 */
#ifndef NDEBUG
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radsniff");
		exit(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	conf = talloc_zero(NULL, rs_t);
	RS_ASSERT(conf);

	/*
	 *  We don't really want probes taking down machines
	 */
#ifdef HAVE_TALLOC_SET_MEMLIMIT
	/*
	 *	@fixme causes hang in talloc steal
	 */
	 //talloc_set_memlimit(conf, 524288000);		/* 50 MB */
#endif

	/*
	 *	Set some defaults
	 */
	conf->print_packet = true;
	conf->limit = 0;
	conf->promiscuous = true;
#ifdef HAVE_COLLECTDC_H
	conf->stats.prefix = RS_DEFAULT_PREFIX;
#endif
	conf->radius_secret = RS_DEFAULT_SECRET;
	conf->logger = NULL;

#ifdef HAVE_COLLECTDC_H
	conf->stats.prefix = RS_DEFAULT_PREFIX;
#endif

	/*
	 *  Get options
	 */
	while ((opt = getopt(argc, argv, "ab:c:Cd:D:e:Ff:hi:I:l:L:mp:P:qr:R:s:Svw:xXW:T:P:N:O:")) != EOF) {
		switch (opt) {
		case 'a':
		{
			pcap_if_t *all_devices = NULL;
			pcap_if_t *dev_p;

			if (pcap_findalldevs(&all_devices, errbuf) < 0) {
				ERROR("Error getting available capture devices: %s", errbuf);
				goto finish;
			}

			int i = 1;
			for (dev_p = all_devices;
			     dev_p;
			     dev_p = dev_p->next) {
				INFO("%i.%s", i++, dev_p->name);
			}
			ret = 0;
			goto finish;
		}

		/* super secret option */
		case 'b':
			conf->buffer_pkts = atoi(optarg);
			if (conf->buffer_pkts == 0) {
				ERROR("Invalid buffer length \"%s\"", optarg);
				usage(1);
			}
			break;

		case 'c':
			conf->limit = atoi(optarg);
			if (conf->limit == 0) {
				ERROR("Invalid number of packets \"%s\"", optarg);
				usage(1);
			}
			break;

		/* udp checksum */
		case 'C':
			conf->verify_udp_checksum = true;
			break;

		case 'd':
			radius_dir = optarg;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'e':
			if (rs_build_event_flags((int *) &conf->event_flags, rs_events, optarg) < 0) {
				usage(64);
			}
			break;

		case 'f':
			conf->pcap_filter = optarg;
			break;

		case 'h':
			usage(0);	/* never returns */

		case 'i':
			*in_head = fr_pcap_init(conf, optarg, PCAP_INTERFACE_IN);
			if (!*in_head) goto finish;
			in_head = &(*in_head)->next;
			conf->from_dev = true;
			break;

		case 'I':
			*in_head = fr_pcap_init(conf, optarg, PCAP_FILE_IN);
			if (!*in_head) {
				goto finish;
			}
			in_head = &(*in_head)->next;
			conf->from_file = true;
			break;

		case 'l':
			conf->list_attributes = optarg;
			break;

		case 'L':
			conf->link_attributes = optarg;
			break;

		case 'm':
			conf->promiscuous = false;
			break;

		case 'p':
			port = atoi(optarg);
			break;

		case 'P':
			conf->daemonize = true;
			conf->pidfile = optarg;
			break;

		case 'q':
			if (fr_debug_lvl > 0) {
				fr_debug_lvl--;
			}
			break;

		case 'r':
			conf->filter_request = optarg;
			break;

		case 'R':
			conf->filter_response = optarg;
			break;

		case 's':
			conf->radius_secret = optarg;
			break;

		case 'S':
			conf->to_stdout = true;
			break;

		case 'v':
#ifdef HAVE_COLLECTDC_H
			INFO("%s, %s, collectdclient version %s", radsniff_version, pcap_lib_version(),
			     lcc_version_string());
#else
			INFO("%s %s", radsniff_version, pcap_lib_version());
#endif
			exit(EXIT_SUCCESS);

		case 'w':
			out = fr_pcap_init(conf, optarg, PCAP_FILE_OUT);
			if (!out) {
				ERROR("Failed creating pcap file \"%s\"", optarg);
				exit(EXIT_FAILURE);
			}
			conf->to_file = true;
			break;

		case 'x':
		case 'X':
			fr_debug_lvl++;
			break;

		case 'W':
			conf->stats.interval = atoi(optarg);
			conf->print_packet = false;
			if (conf->stats.interval <= 0) {
				ERROR("Stats interval must be > 0");
				usage(64);
			}
			break;

		case 'T':
			conf->stats.timeout = atoi(optarg);
			if (conf->stats.timeout <= 0) {
				ERROR("Timeout value must be > 0");
				usage(64);
			}
			break;

#ifdef HAVE_COLLECTDC_H
		case 'N':
			conf->stats.prefix = optarg;
			break;

		case 'O':
			conf->stats.collectd = optarg;
			conf->stats.out = RS_STATS_OUT_COLLECTD;
			break;
#endif
		default:
			usage(64);
		}
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radsniff");
		exit(EXIT_FAILURE);
	}

	/* Useful for file globbing */
	while (optind < argc) {
		*in_head = fr_pcap_init(conf, argv[optind], PCAP_FILE_IN);
		if (!*in_head) {
			goto finish;
		}
		in_head = &(*in_head)->next;
		conf->from_file = true;
		optind++;
	}

	/* Is stdin not a tty? If so it's probably a pipe */
	if (!isatty(fileno(stdin))) {
		conf->from_stdin = true;
	}

	/* What's the point in specifying -F ?! */
	if (conf->from_stdin && conf->from_file && conf->to_file) {
		usage(64);
	}

	/* Can't read from both... */
	if (conf->from_file && conf->from_dev) {
		usage(64);
	}

	/* Reading from file overrides stdin */
	if (conf->from_stdin && (conf->from_file || conf->from_dev)) {
		conf->from_stdin = false;
	}

	/* Writing to file overrides stdout */
	if (conf->to_file && conf->to_stdout) {
		conf->to_stdout = false;
	}

	if (conf->to_stdout) {
		out = fr_pcap_init(conf, "stdout", PCAP_STDIO_OUT);
		if (!out) {
			goto finish;
		}
	}

	if (conf->from_stdin) {
		*in_head = fr_pcap_init(conf, "stdin", PCAP_STDIO_IN);
		if (!*in_head) {
			goto finish;
		}
		in_head = &(*in_head)->next;
	}

	if (conf->stats.interval && !conf->stats.out) {
		conf->stats.out = RS_STATS_OUT_STDIO;
	}

	if (conf->stats.timeout == 0) {
		conf->stats.timeout = RS_DEFAULT_TIMEOUT;
	}

	/*
	 *	If were writing pcap data, or CSV to stdout we *really* don't want to send
	 *	logging there as well.
	 */
	if (conf->to_stdout || conf->list_attributes) {
		fr_log_fp = stderr;
	}

	if (conf->list_attributes) {
		conf->logger = rs_packet_print_csv;
	} else if (fr_debug_lvl > 0) {
		conf->logger = rs_packet_print_fancy;
	}

#if !defined(HAVE_PCAP_FOPEN_OFFLINE) || !defined(HAVE_PCAP_DUMP_FOPEN)
	if (conf->from_stdin || conf->to_stdout) {
		ERROR("PCAP streams not supported");
		goto finish;
	}
#endif

	if (!conf->pcap_filter) {
		snprintf(buffer, sizeof(buffer), "udp port %d or %d or %d",
			 port, port + 1, 3799);
		conf->pcap_filter = buffer;
	}

	if (dict_init(dict_dir, RADIUS_DICTIONARY) < 0) {
		fr_perror("radsniff");
		ret = 64;
		goto finish;
	}

	if (dict_read(radius_dir, RADIUS_DICTIONARY) == -1) {
		fr_perror("radsniff");
		ret = 64;
		goto finish;
	}

	fr_strerror();	/* Clear out any non-fatal errors */

	if (conf->list_attributes) {
		conf->list_da_num = rs_build_dict_list(conf->list_da, sizeof(conf->list_da) / sizeof(*conf->list_da),
						       conf->list_attributes);
		if (conf->list_da_num < 0) {
			usage(64);
		}
		rs_packet_print_csv_header();
	}

	if (conf->link_attributes) {
		conf->link_da_num = rs_build_dict_list(conf->link_da, sizeof(conf->link_da) / sizeof(*conf->link_da),
						       conf->link_attributes);
		if (conf->link_da_num < 0) {
			usage(64);
		}

		link_tree = rbtree_create(conf, (rbcmp) rs_rtx_cmp, _unmark_link, 0);
		if (!link_tree) {
			ERROR("Failed creating RTX tree");
			goto finish;
		}
	}

	if (conf->filter_request) {
		vp_cursor_t cursor;
		VALUE_PAIR *type;

		if (rs_build_filter(&conf->filter_request_vps, conf->filter_request) < 0) {
			usage(64);
		}

		fr_cursor_init(&cursor, &conf->filter_request_vps);
		type = fr_cursor_next_by_num(&cursor, PW_PACKET_TYPE, 0, TAG_ANY);
		if (type) {
			fr_cursor_remove(&cursor);
			conf->filter_request_code = type->vp_integer;
			talloc_free(type);
		}
	}

	if (conf->filter_response) {
		vp_cursor_t cursor;
		VALUE_PAIR *type;

		if (rs_build_filter(&conf->filter_response_vps, conf->filter_response) < 0) {
			usage(64);
		}

		fr_cursor_init(&cursor, &conf->filter_response_vps);
		type = fr_cursor_next_by_num(&cursor, PW_PACKET_TYPE, 0, TAG_ANY);
		if (type) {
			fr_cursor_remove(&cursor);
			conf->filter_response_code = type->vp_integer;
			talloc_free(type);
		}
	}

	/*
	 *	Default to logging and capturing all events
	 */
	if (conf->event_flags == 0) {
		DEBUG("Logging all events");
		memset(&conf->event_flags, 0xff, sizeof(conf->event_flags));
	}

	/*
	 *	If we need to list attributes, link requests using attributes, filter attributes
	 *	or print the packet contents, we need to decode the attributes.
	 *
	 *	But, if were just logging requests, or graphing packets, we don't need to decode
	 *	attributes.
	 */
	if (conf->list_da_num || conf->link_da_num || conf->filter_response_vps || conf->filter_request_vps ||
	    conf->print_packet) {
		conf->decode_attrs = true;
	}

	/*
	 *	Setup the request tree
	 */
	request_tree = rbtree_create(conf, (rbcmp) rs_packet_cmp, _unmark_request, 0);
	if (!request_tree) {
		ERROR("Failed creating request tree");
		goto finish;
	}

	/*
	 *	Get the default capture device
	 */
	if (!conf->from_stdin && !conf->from_file && !conf->from_dev) {
		pcap_if_t *all_devices;			/* List of all devices libpcap can listen on */
		pcap_if_t *dev_p;

		if (pcap_findalldevs(&all_devices, errbuf) < 0) {
			ERROR("Error getting available capture devices: %s", errbuf);
			goto finish;
		}

		if (!all_devices) {
			ERROR("No capture files specified and no live interfaces available");
			ret = 64;
			goto finish;
		}

		for (dev_p = all_devices;
		     dev_p;
		     dev_p = dev_p->next) {
			int link_layer;

			/* Don't use the any devices, it's horribly broken */
			if (!strcmp(dev_p->name, "any")) continue;

			link_layer = fr_pcap_if_link_layer(errbuf, dev_p);
			if (link_layer < 0) {
				DEBUG2("Skipping %s: %s", dev_p->name, errbuf);
				continue;
			}

			if (!fr_link_layer_supported(link_layer)) {
				DEBUG2("Skipping %s: datalink type %s not supported",
				       dev_p->name, pcap_datalink_val_to_name(link_layer));
				continue;
			}

			*in_head = fr_pcap_init(conf, dev_p->name, PCAP_INTERFACE_IN);
			in_head = &(*in_head)->next;
		}
		conf->from_auto = true;
		conf->from_dev = true;
		INFO("Defaulting to capture on all interfaces");
	}

	/*
	 *	Print captures values which will be used
	 */
	if (fr_debug_lvl > 2) {
		DEBUG2("Sniffing with options:");
		if (conf->from_dev)	{
			char *buff = fr_pcap_device_names(conf, in, ' ');
			DEBUG2("  Device(s)               : [%s]", buff);
			talloc_free(buff);
		}
		if (out) {
			DEBUG2("  Writing to              : [%s]", out->name);
		}
		if (conf->limit > 0)	{
			DEBUG2("  Capture limit (packets) : [%" PRIu64 "]", conf->limit);
		}
			DEBUG2("  PCAP filter             : [%s]", conf->pcap_filter);
			DEBUG2("  RADIUS secret           : [%s]", conf->radius_secret);

		if (conf->filter_request_code) {
			DEBUG2("  RADIUS request code     : [%s]", fr_packet_codes[conf->filter_request_code]);
		}

		if (conf->filter_request_vps){
			DEBUG2("  RADIUS request filter   :");
			vp_printlist(fr_log_fp, conf->filter_request_vps);
		}

		if (conf->filter_response_code) {
			DEBUG2("  RADIUS response code    : [%s]", fr_packet_codes[conf->filter_response_code]);
		}

		if (conf->filter_response_vps){
			DEBUG2("  RADIUS response filter  :");
			vp_printlist(fr_log_fp, conf->filter_response_vps);
		}
	}

	/*
	 *	Setup collectd templates
	 */
#ifdef HAVE_COLLECTDC_H
	if (conf->stats.out == RS_STATS_OUT_COLLECTD) {
		size_t i;
		rs_stats_tmpl_t *tmpl, **next;

		if (rs_stats_collectd_open(conf) < 0) {
			exit(EXIT_FAILURE);
		}

		next = &conf->stats.tmpl;

		for (i = 0; i < (sizeof(rs_useful_codes) / sizeof(*rs_useful_codes)); i++) {
			tmpl = rs_stats_collectd_init_latency(conf, next, conf, "exchanged",
							      &stats.exchange[rs_useful_codes[i]],
							      rs_useful_codes[i]);
			if (!tmpl) {
				ERROR("Error allocating memory for stats template");
				goto finish;
			}
			next = &(tmpl->next);
		}
	}
#endif

	/*
	 *	This actually opens the capture interfaces/files (we just allocated the memory earlier)
	 */
	{
		fr_pcap_t *tmp;
		fr_pcap_t **tmp_p = &tmp;

		for (in_p = in;
		     in_p;
		     in_p = in_p->next) {
			in_p->promiscuous = conf->promiscuous;
			in_p->buffer_pkts = conf->buffer_pkts;
			if (fr_pcap_open(in_p) < 0) {
				ERROR("Failed opening pcap handle (%s): %s", in_p->name, fr_strerror());
				if (conf->from_auto || (in_p->type == PCAP_FILE_IN)) {
					continue;
				}

				goto finish;
			}

			if (!fr_link_layer_supported(in_p->link_layer)) {
				ERROR("Failed opening pcap handle (%s): Datalink type %s not supported",
				      in_p->name, pcap_datalink_val_to_name(in_p->link_layer));
				goto finish;
			}

			if (conf->pcap_filter) {
				if (fr_pcap_apply_filter(in_p, conf->pcap_filter) < 0) {
					ERROR("Failed applying filter");
					goto finish;
				}
			}

			*tmp_p = in_p;
			tmp_p = &(in_p->next);
		}
		*tmp_p = NULL;
		in = tmp;

		if (!in) {
			ERROR("No PCAP sources available");
			exit(EXIT_FAILURE);
		}

		/* Clear any irrelevant errors */
		fr_strerror();
	}

	/*
	 *	Open our output interface (if we have one);
	 */
	if (out) {
		out->link_layer = -1;	/* Infer output link type from input */

		for (in_p = in;
		     in_p;
		     in_p = in_p->next) {
			if (out->link_layer < 0) {
				out->link_layer = in_p->link_layer;
				continue;
			}

			if (out->link_layer != in_p->link_layer) {
				ERROR("Asked to write to output file, but inputs do not have the same link type");
				ret = 64;
				goto finish;
			}
		}

		RS_ASSERT(out->link_layer >= 0);

		if (fr_pcap_open(out) < 0) {
			ERROR("Failed opening pcap output (%s): %s", out->name, fr_strerror());
			goto finish;
		}
	}

	/*
	 *	Setup and enter the main event loop. Who needs libev when you can roll your own...
	 */
	 {
		struct timeval now;
		rs_update_t update;

		char *buff;

		memset(&stats, 0, sizeof(stats));
		memset(&update, 0, sizeof(update));

		events = fr_event_list_create(conf, _rs_event_status);
		if (!events) {
			ERROR();
			goto finish;
		}

		/*
		 *  Initialise the signal handler pipe
		 */
		if (pipe(self_pipe) < 0) {
			ERROR("Couldn't open signal pipe: %s", fr_syserror(errno));
			exit(EXIT_FAILURE);
		}

		if (!fr_event_fd_insert(events, 0, self_pipe[0], rs_signal_action, events)) {
			ERROR("Failed inserting signal pipe descriptor: %s", fr_strerror());
			goto finish;
		}

		/*
		 *  Now add fd's for each of the pcap sessions we opened
		 */
		for (in_p = in;
		     in_p;
		     in_p = in_p->next) {
			rs_event_t *event;

			event = talloc_zero(events, rs_event_t);
			event->list = events;
			event->in = in_p;
			event->out = out;
			event->stats = &stats;

			if (!fr_event_fd_insert(events, 0, in_p->fd, rs_got_packet, event)) {
				ERROR("Failed inserting file descriptor");
				goto finish;
			}
		}

		buff = fr_pcap_device_names(conf, in, ' ');
		DEBUG("Sniffing on (%s)", buff);
		talloc_free(buff);

		gettimeofday(&now, NULL);

		/*
		 *  Insert our stats processor
		 */
		if (conf->stats.interval) {
			static fr_event_t *event;

			update.list = events;
			update.stats = &stats;
			update.in = in;

			now.tv_sec += conf->stats.interval;
			now.tv_usec = 0;
			if (!fr_event_insert(events, rs_stats_process, (void *) &update, &now, &event)) {
				ERROR("Failed inserting stats event");
			}

			INFO("Muting stats for the next %i milliseconds (warmup)", conf->stats.timeout);
			rs_tv_add_ms(&now, conf->stats.timeout, &stats.quiet);
		}
	}


	/*
	 *	Do this as late as possible so we can return an error code if something went wrong.
	 */
	if (conf->daemonize) {
		rs_daemonize(conf->pidfile);
	}

	/*
	 *	Setup signal handlers so we always exit gracefully, ensuring output buffers are always
	 *	flushed.
	 */
	fr_set_signal(SIGPIPE, rs_signal_self);
	fr_set_signal(SIGINT, rs_signal_self);
	fr_set_signal(SIGTERM, rs_signal_self);
#ifdef SIGQUIT
	fr_set_signal(SIGQUIT, rs_signal_self);
#endif

	fr_event_loop(events);	/* Enter the main event loop */

	DEBUG("Done sniffing");

	finish:

	cleanup = true;

	/*
	 *	Free all the things! This also closes all the sockets and file descriptors
	 */
	talloc_free(conf);

	if (conf->daemonize) {
		unlink(conf->pidfile);
	}

	return ret;
}
