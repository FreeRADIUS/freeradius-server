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
 * @copyright 2013 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2006 The FreeRADIUS server project
 * @copyright 2006 Nicolas Baradakis (nicolas.baradakis@cegetel.net)
 */

RCSID("$Id$")

#include <time.h>
#include <math.h>

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/radius/list.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/pcap.h>
#include <freeradius-devel/util/timeval.h>

#ifdef HAVE_COLLECTDC_H
#  include <collectd/client.h>
#endif

#include "radsniff.h"

#define RS_ASSERT(_x) if (!(_x) && !fr_cond_assert(_x)) exit(1)

static rs_t *conf;
static struct timeval start_pcap = {0, 0};
static char timestr[50];

static rbtree_t *request_tree = NULL;
static rbtree_t *link_tree = NULL;
static fr_event_list_t *events;
static bool cleanup;

static int self_pipe[2] = {-1, -1};		//!< Signals from sig handlers

typedef int (*rbcmp)(void const *, void const *);

static char const *radsniff_version = RADIUSD_VERSION_STRING_BUILD("radsniff");

static int rs_useful_codes[] = {
	FR_CODE_ACCESS_REQUEST,			//!< RFC2865 - Authentication request
	FR_CODE_ACCESS_ACCEPT,			//!< RFC2865 - Access-Accept
	FR_CODE_ACCESS_REJECT,			//!< RFC2865 - Access-Reject
	FR_CODE_ACCOUNTING_REQUEST,		//!< RFC2866 - Accounting-Request
	FR_CODE_ACCOUNTING_RESPONSE,		//!< RFC2866 - Accounting-Response
	FR_CODE_ACCESS_CHALLENGE,		//!< RFC2865 - Access-Challenge
	FR_CODE_STATUS_SERVER,			//!< RFC2865/RFC5997 - Status Server (request)
	FR_CODE_STATUS_CLIENT,			//!< RFC2865/RFC5997 - Status Server (response)
	FR_CODE_DISCONNECT_REQUEST,		//!< RFC3575/RFC5176 - Disconnect-Request
	FR_CODE_DISCONNECT_ACK,			//!< RFC3575/RFC5176 - Disconnect-Ack (positive)
	FR_CODE_DISCONNECT_NAK,			//!< RFC3575/RFC5176 - Disconnect-Nak (not willing to perform)
	FR_CODE_COA_REQUEST,			//!< RFC3575/RFC5176 - CoA-Request
	FR_CODE_COA_ACK,			//!< RFC3575/RFC5176 - CoA-Ack (positive)
	FR_CODE_COA_NAK,			//!< RFC3575/RFC5176 - CoA-Nak (not willing to perform)
};

static fr_table_num_sorted_t const rs_events[] = {
	{ L("error"),		RS_ERROR	},
	{ L("noreq"),		RS_UNLINKED	},
	{ L("norsp"),		RS_LOST		},
	{ L("received"),	RS_NORMAL	},
	{ L("reused"),		RS_REUSED	},
	{ L("rtx"),		RS_RTX		}
};
static size_t rs_events_len = NUM_ELEMENTS(rs_events);

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t radsniff_dict[];
fr_dict_autoload_t radsniff_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t radsniff_dict_attr[];
fr_dict_attr_autoload_t radsniff_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ NULL }
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
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Kill the parent...
	 */
	if (pid > 0) {
		close(self_pipe[0]);
		close(self_pipe[1]);
		fr_exit_now(EXIT_SUCCESS);
	}

	/*
	 *	Continue as the child.
	 */

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Change the current working directory. This prevents the current
	 *	directory from being locked; hence not being able to remove it.
	 */
	if ((chdir("/")) < 0) {
		fr_exit_now(EXIT_FAILURE);
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
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Close stdout and stderr if they've not been redirected.
	 */
	if (isatty(fileno(stdout))) {
		if (!freopen("/dev/null", "w", stdout)) {
			fr_exit_now(EXIT_FAILURE);
		}
	}

	if (isatty(fileno(stderr))) {
		if (!freopen("/dev/null", "w", stderr)) {
			fr_exit_now(EXIT_FAILURE);
		}
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
	struct tm result;

	if (!t) {
		now = fr_time_to_timeval(fr_time());
		t = &now;
	}

	ret = strftime(out, len, "%Y-%m-%d %H:%M:%S", localtime_r(&t->tv_sec, &result));
	if (ret >= len) {
		return;
	}

	usec = t->tv_usec;

	if (usec) {
		while (usec < 100000) usec *= 10;
		snprintf(out + ret, len - ret, ".%u", usec);
	} else {
		snprintf(out + ret, len - ret, ".000000");
	}
}

static size_t rs_snprint_csv(char *out, size_t outlen, char const *in, size_t inlen)
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

static void rs_packet_print_csv(uint64_t count, rs_status_t status, fr_pcap_t *handle, fr_radius_packet_t *packet,
				UNUSED struct timeval *elapsed, struct timeval *latency, UNUSED bool response,
				bool body)
{
	char const	*status_str;
	char		buffer[1024];
	fr_sbuff_t	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];

	inet_ntop(packet->socket.inet.src_ipaddr.af, &packet->socket.inet.src_ipaddr.addr, src, sizeof(src));
	inet_ntop(packet->socket.inet.dst_ipaddr.af, &packet->socket.inet.dst_ipaddr.addr, dst, sizeof(dst));

	status_str = fr_table_str_by_value(rs_events, status, NULL);
	RS_ASSERT(status_str);

	if (fr_sbuff_in_sprintf(&sbuff, "%s,%" PRIu64 ",%s,", status_str, count, timestr) < 0) return;

	if (latency) {
		if (fr_sbuff_in_sprintf(&sbuff, "%u.%03u,",
			       		(unsigned int) latency->tv_sec,
			       		((unsigned int) latency->tv_usec / 1000)) < 0) return;
	} else {
		if (fr_sbuff_in_char(&sbuff, ',') < 0) return;
	}

	/* Status, Type, Interface, Src, Src port, Dst, Dst port, ID */
	if (is_radius_code(packet->code)) {
		if (fr_sbuff_in_sprintf(&sbuff, "%s,%s,%s,%i,%s,%i,%i,",
					fr_packet_codes[packet->code], handle->name,
					src, packet->socket.inet.src_port, dst, packet->socket.inet.dst_port, packet->id) < 0) return;
	} else {
		if (fr_sbuff_in_sprintf(&sbuff, "%u,%s,%s,%i,%s,%i,%i,", packet->code, handle->name,
					src, packet->socket.inet.src_port, dst, packet->socket.inet.dst_port, packet->id) < 0) return;
	}

	if (body) {
		int i;
		fr_pair_t *vp;

		for (i = 0; i < conf->list_da_num; i++) {
			vp = fr_pair_find_by_da(&packet->vps, conf->list_da[i]);
			if (vp && (vp->vp_length > 0)) {
				if (conf->list_da[i]->type == FR_TYPE_STRING) {
					ssize_t slen;

					if (fr_sbuff_in_char(&sbuff, '"') < 0) return;

					slen = rs_snprint_csv(fr_sbuff_current(&sbuff), fr_sbuff_remaining(&sbuff),
							      vp->vp_strvalue, vp->vp_length);
					if (slen < 0) return;
					fr_sbuff_advance(&sbuff, (size_t)slen);

					if (fr_sbuff_in_char(&sbuff, '"') < 0) return;
				} else {
					if (fr_pair_print_value_quoted(&sbuff, vp, T_BARE_WORD) < 0) return;
				}
			}

			if (fr_sbuff_in_char(&sbuff, ',') < 0) return;
		}
	} else {
		if (fr_sbuff_remaining(&sbuff) < (size_t)conf->list_da_num) return;

		memset(fr_sbuff_current(&sbuff), ',', conf->list_da_num);
		fr_sbuff_advance(&sbuff, conf->list_da_num);
		*fr_sbuff_current(&sbuff) = '\0';
	}

	fprintf(stdout , "%s\n", buffer);
}

static void rs_packet_print_fancy(uint64_t count, rs_status_t status, fr_pcap_t *handle, fr_radius_packet_t *packet,
				  struct timeval *elapsed, struct timeval *latency, bool response, bool body)
{
	char buffer[2048];
	char *p = buffer;

	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];

	ssize_t len, s = sizeof(buffer);

	inet_ntop(packet->socket.inet.src_ipaddr.af, &packet->socket.inet.src_ipaddr.addr, src, sizeof(src));
	inet_ntop(packet->socket.inet.dst_ipaddr.af, &packet->socket.inet.dst_ipaddr.addr, dst, sizeof(dst));

	/* Only print out status str if something's not right */
	if (status != RS_NORMAL) {
		char const *status_str;

		status_str = fr_table_str_by_value(rs_events, status, NULL);
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
			       response ? packet->socket.inet.dst_port : packet->socket.inet.src_port,
			       response ? "<-" : "->",
			       response ? src : dst ,
			       response ? packet->socket.inet.src_port : packet->socket.inet.dst_port);
	} else {
		len = snprintf(p, s, "%u Id %i %s:%s:%i %s %s:%i ",
			       packet->code,
			       packet->id,
			       handle->name,
			       response ? dst : src,
			       response ? packet->socket.inet.dst_port : packet->socket.inet.src_port,
			       response ? "<-" : "->",
			       response ? src : dst ,
			       response ? packet->socket.inet.src_port : packet->socket.inet.dst_port);
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
		if (conf->print_packet && (fr_debug_lvl >= L_DBG_LVL_4)) {
			fr_radius_packet_log_hex(&default_log, packet);
		}

		if (conf->print_packet && (fr_debug_lvl >= L_DBG_LVL_2)) {
			char vector[(RADIUS_AUTH_VECTOR_LENGTH * 2) + 1];

			if (packet->vps) {
				fr_pair_list_sort(&packet->vps, fr_pair_cmp_by_da);
				fr_pair_list_log(&default_log, packet->vps);
			}

			fr_bin2hex(&FR_SBUFF_OUT(vector, sizeof(vector)),
						 &FR_DBUFF_TMP(packet->vector, RADIUS_AUTH_VECTOR_LENGTH), SIZE_MAX);
			INFO("\tAuthenticator-Field = 0x%s", vector);
		}
	}
}

static inline void rs_packet_print(rs_request_t *request, uint64_t count, rs_status_t status, fr_pcap_t *handle,
				   fr_radius_packet_t *packet, struct timeval *elapsed, struct timeval *latency,
				   bool response, bool body)
{
	if (!conf->logger) return;

	if (request) request->logged = true;
	conf->logger(count, status, handle, packet, elapsed, latency, response, body);
}

/** Query libpcap to see if it dropped any packets
 *
 * We need to check to see if libpcap dropped any packets and if it did, we need to stop stats output for long
 * enough for inaccurate statistics to be cleared out.
 *
 * @param in pcap handle to check.
 * @return
 *	- 0 No drops.
 *	- -1 We couldn't check.
 *	- -2 Dropped because of buffer exhaustion.
 *	- -3 Dropped because of NIC.
 */
static int rs_check_pcap_drop(fr_pcap_t *in)
{
	int ret = 0;
	struct pcap_stat pstats;

	if (pcap_stats(in->handle, &pstats) != 0) {
		ERROR("%s failed retrieving pcap stats: %s", in->name, pcap_geterr(in->handle));
		return -1;
	}

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

	if (isnan((long double)stats->latency_smoothed)) {
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

	for (i = 1; i < RS_RETRANSMIT_MAX; i++) {
		stats->interval.rt[i] = ((long double) stats->interval.rt_total[i]) / conf->stats.interval;
	}
}

static void rs_stats_print_code_fancy(rs_latency_t *stats, FR_CODE code)
{
	int i;
	bool have_rt = false;

	for (i = 1; i <= RS_RETRANSMIT_MAX; i++) if (stats->interval.rt[i]) have_rt = true;

	if (!stats->interval.received && !have_rt && !stats->interval.reused) return;

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
		INFO("%s retransmits & loss:", fr_packet_codes[code]);

		if (stats->interval.lost)	INFO("\tLost      : %.3lf/s", stats->interval.lost);
		if (stats->interval.reused)	INFO("\tID Reused : %.3lf/s", stats->interval.reused);

		for (i = 1; i <= RS_RETRANSMIT_MAX; i++) {
			if (!stats->interval.rt[i]) continue;

			if (i != RS_RETRANSMIT_MAX) {
				INFO("\tRT (%i)    : %.3lf/s", i, stats->interval.rt[i]);
			} else {
				INFO("\tRT (%i+)   : %.3lf/s", i, stats->interval.rt[i]);
			}
		}
	}
}

static void rs_stats_print_fancy(rs_update_t *this, rs_stats_t *stats, struct timeval *now)
{
	fr_pcap_t		*in_p;
	size_t			i;
	size_t			rs_codes_len = (NUM_ELEMENTS(rs_useful_codes));

	/*
	 *	Clear and reset the screen
	 */
	INFO("\x1b[0;0f");
	INFO("\x1b[2J");

	if ((stats->quiet.tv_sec + (stats->quiet.tv_usec / 1000000.0)) -
	    (now->tv_sec + (now->tv_usec / 1000000.0)) > 0) {
		INFO("Stats muted because of warmup, or previous error");
		return;
	}

	INFO("######### Stats Iteration %i #########", stats->intervals);

	if (this->in) INFO("Interface capture rate:");
	for (in_p = this->in;
	     in_p;
	     in_p = in_p->next) {
		struct pcap_stat pstats;

		if (pcap_stats(in_p->handle, &pstats) != 0) {
			ERROR("%s failed retrieving pcap stats: %s", in_p->name, pcap_geterr(in_p->handle));
			return;
		}

		INFO("\t%s%*s: %.3lf/s", in_p->name, (int) (10 - strlen(in_p->name)), "",
		     ((double) (pstats.ps_recv - in_p->pstats.ps_recv)) / conf->stats.interval);
	}

	/*
	 *	Latency stats need a bit more work to calculate the SMA.
	 *
	 *	No further work is required for codes.
	 */
	for (i = 0; i < rs_codes_len; i++) {
		if (fr_debug_lvl > 0) {
			rs_stats_print_code_fancy(&stats->exchange[rs_useful_codes[i]], rs_useful_codes[i]);
		}
	}
}

static void rs_stats_print_csv_header(rs_update_t *this)
{
	fr_pcap_t	*in_p;
	size_t		rs_codes_len = (NUM_ELEMENTS(rs_useful_codes));
	size_t		i;
	int		j;

	fprintf(stdout, "\"Iteration\"");

	for (in_p = this->in; in_p; in_p = in_p->next) {
		fprintf(stdout, ",\"%s PPS\"", in_p->name);
	}

	for (i = 0; i < rs_codes_len; i++) {
		char const *name = fr_packet_codes[rs_useful_codes[i]];

		fprintf(stdout,
			",\"%s received/s\""
			",\"%s linked/s\""
			",\"%s unlinked/s\""
			",\"%s lat high (ms)\""
			",\"%s lat low (ms)\""
			",\"%s lat avg (ms)\""
			",\"%s lat ma (ms)\""
			",\"%s lost/s\""
			",\"%s reused/s\"",
			name,
			name,
			name,
			name,
			name,
			name,
			name,
			name,
			name);

		for (j = 0; j <= RS_RETRANSMIT_MAX; j++) {
			if (j != RS_RETRANSMIT_MAX) {
				fprintf(stdout, ",\"%s rtx (%i)\"", name, j);
			} else {
				fprintf(stdout, ",\"%s rtx (%i+)\"", name, j);
			}
		}
	}

	fprintf(stdout , "\n");
}

static ssize_t rs_stats_print_code_csv(char *out, size_t outlen, rs_latency_t *stats)
{
	size_t	i;
	char	*p = out, *end = out + outlen;

	p += snprintf(out, outlen, ",%.3lf,%.3lf,%.3lf,%.3lf,%.3lf,%.3lf,%.3lf,%.3lf,%.3lf",
		      stats->interval.received,
		      stats->interval.linked,
		      stats->interval.unlinked,
		      stats->interval.latency_high,
		      stats->interval.latency_low,
		      stats->interval.latency_average,
		      stats->latency_smoothed,
		      stats->interval.lost,
		      stats->interval.reused);
	if (p >= end) return -1;

	for (i = 1; i <= RS_RETRANSMIT_MAX; i++) {
		p += snprintf(p, outlen - (p - out), ",%.3lf", stats->interval.rt[i]);
		if (p >= end) return -1;
	}

	return p - out;
}

static void rs_stats_print_csv(rs_update_t *this, rs_stats_t *stats, UNUSED struct timeval *now)
{
	char buffer[2048], *p = buffer, *end = buffer + sizeof(buffer);
	fr_pcap_t	*in_p;
	size_t		i;
	size_t		rs_codes_len = (NUM_ELEMENTS(rs_useful_codes));

	p += snprintf(buffer, sizeof(buffer) - (p - buffer), "%i", stats->intervals);
	if (p >= end) {
	oob:
		ERROR("Exceeded line buffer size");
		return;
	}

	for (in_p = this->in;
	     in_p;
	     in_p = in_p->next) {
		struct pcap_stat pstats;

		if (pcap_stats(in_p->handle, &pstats) != 0) {
			ERROR("%s failed retrieving pcap stats: %s", in_p->name, pcap_geterr(in_p->handle));
			return;
		}

		p += snprintf(p, sizeof(buffer) - (p - buffer), ",%.3lf",
			      ((double) (pstats.ps_recv - in_p->pstats.ps_recv)) / conf->stats.interval);
		if (p >= end) goto oob;
	}

	for (i = 0; i < rs_codes_len; i++) {
		ssize_t slen;

		slen = rs_stats_print_code_csv(p, sizeof(buffer) - (p - buffer), &stats->exchange[rs_useful_codes[i]]);
		if (slen < 0) goto oob;

		p += (size_t)slen;
		if (p >= end) goto oob;
	}

	fprintf(stdout , "%s\n", buffer);
}

/** Process stats for a single interval
 *
 */
static void rs_stats_process(fr_event_list_t *el, fr_time_t now_t, void *ctx)
{
	size_t		i;
	size_t		rs_codes_len = (NUM_ELEMENTS(rs_useful_codes));
	fr_pcap_t	*in_p;
	rs_update_t	*this = ctx;
	rs_stats_t	*stats = this->stats;
	struct timeval	now;

	now = fr_time_to_timeval(now_t);

	if (!this->done_header) {
		if (this->head) this->head(this);
		this->done_header = true;
	}

	stats->intervals++;

	for (in_p = this->in;
	     in_p;
	     in_p = in_p->next) {
		if (rs_check_pcap_drop(in_p) < 0) {
			ERROR("Muting stats for the next %i milliseconds", conf->stats.timeout);

			rs_tv_add_ms(&now, conf->stats.timeout, &stats->quiet);
			goto clear;
		}
	}

	/*
	 *	Stats temporarily muted
	 */
	if ((stats->quiet.tv_sec + (stats->quiet.tv_usec / 1000000.0)) -
	    (now.tv_sec + (now.tv_usec / 1000000.0)) > 0) goto clear;

	for (i = 0; i < rs_codes_len; i++) {
		rs_stats_process_latency(&stats->exchange[rs_useful_codes[i]]);
		rs_stats_process_counters(&stats->exchange[rs_useful_codes[i]]);
	}

	if (this->body) this->body(this, stats, &now);

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
		static fr_event_timer_t const *event;

		now.tv_sec += conf->stats.interval;
		now.tv_usec = 0;

		if (fr_event_timer_at(NULL, el, &event,
				      fr_time_from_timeval(&now), rs_stats_process, ctx) < 0) {
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
	stats->interval.latency_total += (long double) lint;

}

static int rs_install_stats_processor(rs_stats_t *stats, fr_event_list_t *el,
				      fr_pcap_t *in, struct timeval *now, bool live)
{
	static fr_event_timer_t	const *event;
	static rs_update_t	update;

	memset(&update, 0, sizeof(update));

	update.list = el;
	update.stats = stats;
	update.in = in;

	switch (conf->stats.out) {
	default:
	case RS_STATS_OUT_STDIO_FANCY:
		update.head = NULL;
		update.body = rs_stats_print_fancy;
		break;

	case RS_STATS_OUT_STDIO_CSV:
		update.head = rs_stats_print_csv_header;
		update.body = rs_stats_print_csv;
		break;

#ifdef HAVE_COLLECTDC_H
	case RS_STATS_OUT_COLLECTD:
		update.head = NULL;
		update.body = NULL;
		break;
#endif
	}
	/*
	 *	Set the first time we print stats
	 */
	now->tv_sec += conf->stats.interval;
	now->tv_usec = 0;

	if (live) {
		INFO("Muting stats for the next %i milliseconds (warmup)", conf->stats.timeout);
		rs_tv_add_ms(now, conf->stats.timeout, &(stats->quiet));
	}

	if (fr_event_timer_at(NULL, events, (void *) &event,
			      fr_time_from_timeval(now), rs_stats_process, &update) < 0) {
		ERROR("Failed inserting stats event");
		return -1;
	}

	return 0;
}

/** Copy a subset of attributes from one list into the other
 *
 * Should be O(n) if all the attributes exist.  List must be pre-sorted.
 */
static int rs_get_pairs(TALLOC_CTX *ctx, fr_pair_t **out, fr_pair_t *vps, fr_dict_attr_t const *da[], int num)
{
	fr_cursor_t list_cursor, out_cursor;
	fr_pair_t *match, *copy;
	fr_pair_list_t last_match;
	uint64_t count = 0;
	int i;

	last_match = vps;

	fr_cursor_init(&list_cursor, &last_match);
	fr_cursor_init(&out_cursor, out);
	for (i = 0; i < num; i++) {
		match = fr_cursor_filter_next(&list_cursor, fr_pair_matches_da, da[i]);
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
			fr_cursor_append(&out_cursor, copy);
			last_match = match;

			count++;
		} while ((match = fr_cursor_filter_next(&list_cursor, fr_pair_matches_da, da[i])));
	}

	return count;
}

static int _request_free(rs_request_t *request)
{
	int ret;

	/*
	 *	If we're attempting to cleanup the request, and it's no longer in the request_tree
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
		ret = fr_event_timer_delete(&request->event);
		if (ret < 0) {
			fr_perror("Failed deleting timer");
			RS_ASSERT(0 == 1);
		}
	}

	fr_radius_packet_free(&request->packet);
	fr_radius_packet_free(&request->expect);
	fr_radius_packet_free(&request->linked);

	return 0;
}

static void rs_packet_cleanup(rs_request_t *request)
{

	fr_radius_packet_t *packet = request->packet;
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
	 *	We're at packet cleanup time which is when the packet was received + timeout
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
	if (request->rt_req) {
		if (request->rt_req > RS_RETRANSMIT_MAX) {
			request->stats_req->interval.rt_total[RS_RETRANSMIT_MAX]++;
		} else {
			request->stats_req->interval.rt_total[request->rt_req]++;
		}
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

static void _rs_event(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *ctx)
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
					 NUM_ELEMENTS(request->capture))) {
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
				 NUM_ELEMENTS(request->capture))) {
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
	ssize_t			len;
	uint8_t const		*p = data;

	ip_header_t const	*ip = NULL;		/* The IP header */
	ip_header6_t const	*ip6 = NULL;		/* The IPv6 header */
	udp_header_t const	*udp;			/* The UDP header */
	uint8_t			version;		/* IP header version */
	bool			response;		/* Was it a response code */

	decode_fail_t		reason;			/* Why we failed decoding the packet */
	static uint64_t		captured = 0;

	rs_status_t		status = RS_NORMAL;	/* Any special conditions (RTX, Unlinked, ID-Reused) */
	fr_radius_packet_t		*packet;		/* Current packet were processing */
	rs_request_t		*original = NULL;

	rs_request_t		search;

	memset(&search, 0, sizeof(search));
	fr_pair_list_init(&search.link_vps);

	if (!start_pcap.tv_sec) {
		start_pcap = header->ts;
	}

	if (RIDEBUG_ENABLED()) {
		rs_time_print(timestr, sizeof(timestr), &header->ts);
	}

	len = fr_pcap_link_layer_offset(data, header->caplen, event->in->link_layer);
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
		 *	F5 load balancers and Netscout.
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
	packet = fr_radius_alloc(conf, false);
	if (!packet) {
		REDEBUG("Failed allocating memory to hold decoded packet");
		rs_tv_add_ms(&header->ts, conf->stats.timeout, &stats->quiet);
		return;
	}

	packet->timestamp = fr_time_from_timeval(&header->ts);
	packet->data_len = header->caplen - (p - data);
	memcpy(&packet->data, &p, sizeof(packet->data));

	packet->socket.proto = IPPROTO_UDP;

	/*
	 *	Populate IP/UDP fields from PCAP data
	 */
	if (ip) {
		packet->socket.inet.src_ipaddr.af = AF_INET;
		packet->socket.inet.src_ipaddr.addr.v4.s_addr = ip->ip_src.s_addr;

		packet->socket.inet.dst_ipaddr.af = AF_INET;
		packet->socket.inet.dst_ipaddr.addr.v4.s_addr = ip->ip_dst.s_addr;
	} else {
		packet->socket.inet.src_ipaddr.af = AF_INET6;
		memcpy(packet->socket.inet.src_ipaddr.addr.v6.s6_addr, ip6->ip_src.s6_addr,
		       sizeof(packet->socket.inet.src_ipaddr.addr.v6.s6_addr));

		packet->socket.inet.dst_ipaddr.af = AF_INET6;
		memcpy(packet->socket.inet.dst_ipaddr.addr.v6.s6_addr, ip6->ip_dst.s6_addr,
		       sizeof(packet->socket.inet.dst_ipaddr.addr.v6.s6_addr));
	}

	packet->socket.inet.src_port = ntohs(udp->src);
	packet->socket.inet.dst_port = ntohs(udp->dst);

	if (!fr_radius_packet_ok(packet, RADIUS_MAX_ATTRIBUTES, false, &reason)) {
		fr_perror("radsniff");
		if (conf->event_flags & RS_ERROR) {
			rs_packet_print(NULL, count, RS_ERROR, event->in, packet, &elapsed, NULL, false, false);
		}
		fr_radius_packet_free(&packet);

		return;
	}

	switch (packet->code) {
	case FR_CODE_ACCOUNTING_RESPONSE:
	case FR_CODE_ACCESS_REJECT:
	case FR_CODE_ACCESS_ACCEPT:
	case FR_CODE_ACCESS_CHALLENGE:
	case FR_CODE_COA_NAK:
	case FR_CODE_COA_ACK:
	case FR_CODE_DISCONNECT_NAK:
	case FR_CODE_DISCONNECT_ACK:
	case FR_CODE_STATUS_CLIENT:
	{
		/* look for a matching request and use it for decoding */
		search.expect = packet;
		original = rbtree_finddata(request_tree, &search);

		/*
		 *	Verify this code is allowed
		 */
		if (conf->filter_response_code && (conf->filter_response_code != packet->code)) {
			drop_response:
			RDEBUG2("Response dropped by filter");
			fr_radius_packet_free(&packet);

			/* We now need to cleanup the original request too */
			if (original) {
				RS_CLEANUP_NOW(original, true);
			}
			return;
		}

		if (conf->verify_radius_authenticator && original) {
			int ret;
			FILE *log_fp = fr_log_fp;

			fr_log_fp = NULL;
			ret = fr_radius_packet_verify(packet, original->expect, conf->radius_secret);
			fr_log_fp = log_fp;
			if (ret != 0) {
				fr_perror("Failed verifying packet ID %d", packet->id);
				fr_radius_packet_free(&packet);
				return;
			}
		}

		/*
		 *	Only decode attributes if we want to print them or filter on them
		 *	fr_radius_packet_ok( does checks to verify the packet is actually valid.
		 */
		if (conf->decode_attrs) {
			int ret;
			FILE *log_fp = fr_log_fp;

			fr_log_fp = NULL;
			ret = fr_radius_packet_decode(packet, original ? original->expect : NULL,
						      RADIUS_MAX_ATTRIBUTES, false, conf->radius_secret);
			fr_log_fp = log_fp;
			if (ret != 0) {
				fr_radius_packet_free(&packet);
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
				fr_pair_list_sort(&packet->vps, fr_pair_cmp_by_da);
				if (!fr_pair_validate_relaxed(NULL, &conf->filter_response_vps, &packet->vps)) {
					goto drop_response;
				}
			}

			/*
			 *	Is this a retransmission?
			 */
			if (original->linked) {
				status = RS_RTX;
				original->rt_rsp++;

				fr_radius_packet_free(&original->linked);
				fr_event_timer_delete(&original->event);
			/*
			 *	...nope it's the first response to a request.
			 */
			} else {
				original->stats_rsp = &stats->exchange[packet->code];
			}

			/*
			 *	Insert a callback to remove the request and response
			 *	from the tree after the timeout period.
			 *	The delay is so we can detect retransmissions.
			 */
			original->linked = talloc_steal(original, packet);
			rs_tv_add_ms(&header->ts, conf->stats.timeout, &original->when);
			if (fr_event_timer_at(NULL, event->list, &original->event,
					      fr_time_from_timeval(&original->when), _rs_event, original) < 0) {
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
				fr_radius_packet_free(&packet);
				RDEBUG2("Original request dropped by filter");
				return;
			}

			status = RS_UNLINKED;
			stats->exchange[packet->code].interval.unlinked_total++;
		}

		rs_response_to_pcap(event, original, header, data);
		response = true;
		break;
	}

	case FR_CODE_ACCOUNTING_REQUEST:
	case FR_CODE_ACCESS_REQUEST:
	case FR_CODE_COA_REQUEST:
	case FR_CODE_DISCONNECT_REQUEST:
	case FR_CODE_STATUS_SERVER:
	{
		/*
		 *	Verify this code is allowed
		 */
		if (conf->filter_request_code && (conf->filter_request_code != packet->code)) {
			drop_request:

			RDEBUG2("Request dropped by filter");
			fr_radius_packet_free(&packet);

			return;
		}

		if (conf->verify_radius_authenticator) {
			switch (packet->code) {
			case FR_CODE_ACCOUNTING_REQUEST:
			case FR_CODE_COA_REQUEST:
			case FR_CODE_DISCONNECT_REQUEST:
			{
				int ret;
				FILE *log_fp = fr_log_fp;

				fr_log_fp = NULL;
				ret = fr_radius_packet_verify(packet, NULL, conf->radius_secret);
				fr_log_fp = log_fp;
				if (ret != 0) {
					fr_perror("Failed verifying packet ID %d", packet->id);
					fr_radius_packet_free(&packet);
					return;
				}
			}
				break;

			default:
				break;
			}
		}

		/*
		 *	Only decode attributes if we want to print them or filter on them
		 *	fr_radius_packet_ok( does checks to verify the packet is actually valid.
		 */
		if (conf->decode_attrs) {
			int ret;
			FILE *log_fp = fr_log_fp;

			fr_log_fp = NULL;
			ret = fr_radius_packet_decode(packet, NULL,
						      RADIUS_MAX_ATTRIBUTES, false, conf->radius_secret);
			fr_log_fp = log_fp;

			if (ret != 0) {
				fr_radius_packet_free(&packet);
				REDEBUG("Failed decoding");
				return;
			}

			fr_pair_list_sort(&packet->vps, fr_pair_cmp_by_da);
		}

		/*
		 *	Save the request for later matching
		 */
		search.expect = fr_radius_alloc_reply(packet, packet);
		if (!search.expect) {
			REDEBUG("Failed allocating memory to hold expected reply");
			rs_tv_add_ms(&header->ts, conf->stats.timeout, &stats->quiet);
			fr_radius_packet_free(&packet);
			return;
		}
		search.expect->code = packet->code;

		if ((conf->link_da_num > 0) && packet->vps) {
			int ret;
			ret = rs_get_pairs(packet, &search.link_vps, packet->vps, conf->link_da,
					   conf->link_da_num);
			if (ret < 0) {
				ERROR("Failed extracting RTX linking pairs from request");
				fr_radius_packet_free(&packet);
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
			if (original && (memcmp(original->expect->vector, packet->vector,
			    			sizeof(original->expect->vector)) != 0)) {
				/*
				 *	ID reused before the request timed out (which may be an issue)...
				 */
				if (!original->linked) {
					status = RS_REUSED;
					stats->exchange[packet->code].interval.reused_total++;
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
			if (!fr_pair_validate_relaxed(NULL, &conf->filter_request_vps, &packet->vps)) {
				goto drop_request;
			}
		}

		/*
		 *	Is this a retransmission?
		 */
		if (original) {
			status = RS_RTX;
			original->rt_req++;

			fr_radius_packet_free(&original->packet);

			/* We may of seen the response, but it may of been lost upstream */
			fr_radius_packet_free(&original->linked);

			original->packet = talloc_steal(original, packet);

			/* Request may need to be reinserted as the 5 tuple of the response may of changed */
			if (rs_packet_cmp(original, &search) != 0) {
				rbtree_deletebydata(request_tree, original);
			}

			fr_radius_packet_free(&original->expect);
			original->expect = talloc_steal(original, search.expect);

			/* Disarm the timer for the cleanup event for the original request */
			fr_event_timer_delete(&original->event);
		/*
		 *	...nope it's a new request.
		 */
		} else {
			original = talloc_zero(conf, rs_request_t);
			talloc_set_destructor(original, _request_free);
			fr_pair_list_init(&original->link_vps);

			original->id = count;
			original->in = event->in;
			original->stats_req = &stats->exchange[packet->code];

			/* Set the packet pointer to the start of the buffer*/
			original->capture_p = original->capture;

			original->packet = talloc_steal(original, packet);
			original->expect = talloc_steal(original, search.expect);

			if (search.link_vps) {
				bool ret;
				fr_cursor_t cursor;
				fr_pair_t *vp;

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
		original->packet->timestamp = fr_time_from_timeval(&header->ts);
		rs_tv_add_ms(&header->ts, conf->stats.timeout, &original->when);
		if (fr_event_timer_at(NULL, event->list, &original->event,
				      fr_time_from_timeval(&original->when), _rs_event, original) < 0) {
			REDEBUG("Failed inserting new event");

			talloc_free(original);
			return;
		}
		rs_request_to_pcap(event, original, header, data);
		response = false;
		break;
	}

	default:
		REDEBUG("Unsupported code %i", packet->code);
		fr_radius_packet_free(&packet);

		return;
	}

	fr_timeval_subtract(&elapsed, &header->ts, &start_pcap);

	/*
	 *	Increase received count
	 */
	stats->exchange[packet->code].interval.received_total++;

	/*
	 *	It's a linked response
	 */
	if (original && original->linked) {
		latency = fr_time_delta_to_timeval(packet->timestamp - original->packet->timestamp);

		/*
		 *	Update stats for both the request and response types.
		 *
		 *	This isn't useful for things like Access-Requests, but will be useful for
		 *	CoA and Disconnect Messages, as we get the average latency across both
		 *	response types.
		 *
		 *	It also justifies allocating FR_CODE_RADIUS_MAX instances of rs_latency_t.
		 */
		rs_stats_update_latency(&stats->exchange[packet->code], &latency);
		rs_stats_update_latency(&stats->exchange[original->expect->code], &latency);

		/*
		 *	We're filtering on response, now print out the full data from the request
		 */
		if (conf->filter_response && RIDEBUG_ENABLED() && (conf->event_flags & RS_NORMAL)) {
			struct timeval ts_tv;

			ts_tv = fr_time_to_timeval(original->packet->timestamp);

			rs_time_print(timestr, sizeof(timestr), &ts_tv);
			fr_timeval_subtract(&elapsed, &ts_tv, &start_pcap);
			rs_packet_print(original, original->id, RS_NORMAL, original->in,
					original->packet, &elapsed, NULL, false, true);
			fr_timeval_subtract(&elapsed, &header->ts, &start_pcap);
			rs_time_print(timestr, sizeof(timestr), &header->ts);
		}

		if (conf->event_flags & status) {
			rs_packet_print(original, count, status, event->in, packet,
					&elapsed, &latency, response, true);
		}
	/*
	 *	It's the original request
	 *
	 *	If we're filtering on responses we can only indicate we received it on response, or timeout.
	 */
	} else if (!conf->filter_response && (conf->event_flags & status)) {
		rs_packet_print(original, original ? original->id : count, status, event->in,
				packet, &elapsed, NULL, response, true);
	}

	fflush(fr_log_fp);

	/*
	 *	If it's an unlinked response, we need to free it explicitly, as it will
	 *	not be done by the event queue.
	 */
	if (response && !original) {
		fr_radius_packet_free(&packet);
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

static void rs_got_packet(fr_event_list_t *el, int fd, UNUSED int flags, void *ctx)
{
	static uint64_t		count = 0;	/* Packets seen */
	static fr_time_t	last_sync = 0;
	fr_time_t		now_real;
	rs_event_t		*event = talloc_get_type(ctx, rs_event_t);
	pcap_t			*handle = event->in->handle;

	int			i;
	int			ret;
	const			uint8_t *data;
	struct			pcap_pkthdr *header;

	/*
	 *	Because the event loop might be running on synthetic
	 *	pcap file time, we need to implement our own time
	 *	tracking here, and run the monotonic/wallclock sync
	 *	event ourselves.
	 */
	now_real = fr_time();
	if ((now_real - last_sync) > fr_time_delta_from_sec(1)) {
		fr_time_sync();
		last_sync = now_real;
	}

	/*
	 *	Consume entire capture, interleaving not currently possible
	 */
	if ((event->in->type == PCAP_FILE_IN) || (event->in->type == PCAP_STDIO_IN)) {
		bool stats_started = false;

		while (!fr_event_loop_exiting(el)) {
			fr_time_t now;

			ret = pcap_next_ex(handle, &header, &data);
			if (ret == 0) {
				/* No more packets available at this time */
				return;
			}
			if (ret == -2) {
				DEBUG("Done reading packets (%s)", event->in->name);
			done_file:
				fr_event_fd_delete(events, fd, FR_EVENT_FILTER_IO);

				/* Signal pipe takes one slot which is why this is == 1 */
				if (fr_event_list_num_fds(events) == 1) fr_event_loop_exit(events, 1);

				return;
			}
			if (ret < 0) {
				ERROR("Error requesting next packet, got (%i): %s", ret, pcap_geterr(handle));
				goto done_file;
			}

			/*
			 *	Insert the stats processor with the timestamp
			 *	of the first packet in the trace.
			 */
			if (conf->stats.interval && !stats_started) {
				rs_install_stats_processor(event->stats, el, NULL, &header->ts, false);
				stats_started = true;
			}

			do {
				now = fr_time_from_timeval(&header->ts);
			} while (fr_event_timer_run(el, &now) == 1);
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

static int  _rs_event_status(UNUSED void *ctx, fr_time_delta_t wake_t)
{
	struct timeval wake;

	wake = fr_time_delta_to_timeval(wake_t);

	if ((wake.tv_sec != 0) || (wake.tv_usec >= 100000)) {
		DEBUG2("Waking up in %d.%01u seconds", (int) wake.tv_sec, (unsigned int) wake.tv_usec / 100000);

		if (RIDEBUG_ENABLED()) {
			rs_time_print(timestr, sizeof(timestr), &wake);
		}
	}

	return 0;
}

/** Compare requests using packet info and lists of attributes
 *
 */
static int rs_rtx_cmp(rs_request_t const *a, rs_request_t const *b)
{
	int ret;

	RS_ASSERT(a->link_vps);
	RS_ASSERT(b->link_vps);

	ret = (int) a->expect->code - (int) b->expect->code;
	if (ret != 0) return ret;

	ret = a->expect->socket.fd - b->expect->socket.fd;
	if (ret != 0) return ret;

	ret = fr_ipaddr_cmp(&a->expect->socket.inet.src_ipaddr, &b->expect->socket.inet.src_ipaddr);
	if (ret != 0) return ret;

	ret = fr_ipaddr_cmp(&a->expect->socket.inet.dst_ipaddr, &b->expect->socket.inet.dst_ipaddr);
	if (ret != 0) return ret;

	return fr_pair_list_cmp(&a->link_vps, &b->link_vps);
}

static int rs_build_dict_list(fr_dict_attr_t const **out, size_t len, char *list)
{
	size_t i = 0;
	char *p, *tok;

	p = list;
	while ((tok = strsep(&p, "\t ,")) != NULL) {
		fr_dict_attr_t const *da;
		if ((*tok == '\t') || (*tok == ' ') || (*tok == '\0')) {
			continue;
		}

		if (i == len) {
			ERROR("Too many attributes, maximum allowed is %zu", len);
			return -1;
		}

		da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_radius), tok);
		if (!da) da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), tok);
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
	if (i > 1) fr_quick_sort((void const **)out, 0, i, fr_pointer_cmp);

	return i;
}

static int rs_build_filter(fr_pair_t **out, char const *filter)
{
	fr_cursor_t cursor;
	fr_pair_t *vp;
	fr_token_t code;

	code = fr_pair_list_afrom_str(conf, dict_radius, filter, out);
	if (code == T_INVALID) {
		fr_perror("Invalid RADIUS filter \"%s\"", filter);
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
		 *	Xlat expansions are not supported. Convert xlat to value box (if possible).
		 */
		if (vp->type == VT_XLAT) {
			fr_type_t type = vp->da->type;
			if (fr_value_box_from_str(vp, &vp->data, &type, NULL, vp->xlat, -1, '\0', false) < 0) {
				fr_perror("radsniff");
				return -1;
			}
			vp->type = VT_DATA;
		}
	}

	/*
	 *	This allows efficient list comparisons later
	 */
	fr_pair_list_sort(out, fr_pair_cmp_by_da);

	return 0;
}

static int rs_build_event_flags(int *flags, fr_table_num_sorted_t const *map, size_t map_len, char *list)
{
	size_t i = 0;
	char *p, *tok;

	p = list;
	while ((tok = strsep(&p, "\t ,")) != NULL) {
		int flag;

		if ((*tok == '\t') || (*tok == ' ') || (*tok == '\0')) {
			continue;
		}

		*flags |= flag = fr_table_value_by_str(map, tok, -1);
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
static void rs_collectd_reopen(fr_event_list_t *el, fr_time_t now, UNUSED void *ctx)
{
	static fr_event_timer_t const *event;

	if (rs_stats_collectd_open(conf) == 0) {
		DEBUG2("Stats output socket (re)opened");
		return;
	}

	ERROR("Will attempt to re-establish connection in %i ms", RS_SOCKET_REOPEN_DELAY);

	if (fr_event_timer_at(NULL, el, &event,
			      now + fr_time_delta_from_msec(RS_SOCKET_REOPEN_DELAY), rs_collectd_reopen, el) < 0) {
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
		fr_exit_now(EXIT_FAILURE);
	}
}

/** Read the last signal from the signal pipe
 *
 */
static void rs_signal_action(
#ifndef HAVE_COLLECTDC_H
UNUSED
#endif
fr_event_list_t *list, int fd, int UNUSED flags, UNUSED void *ctx)
{
	int sig;
	ssize_t ret;

	ret = read(fd, &sig, sizeof(sig));
	if (ret < 0) {
		ERROR("Failed reading signal from pipe: %s", fr_syserror(errno));
		fr_exit_now(EXIT_FAILURE);
	}

	if (ret != sizeof(sig)) {
		ERROR("Failed reading signal from pipe: "
		      "Expected signal to be %zu bytes but only read %zu byes", sizeof(sig), ret);
		fr_exit_now(EXIT_FAILURE);
	}

	switch (sig) {
#ifdef HAVE_COLLECTDC_H
	case SIGPIPE:
		rs_collectd_reopen(list, fr_time(), list);
		break;
#else
	case SIGPIPE:
#endif

	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
		DEBUG2("Signalling event loop to exit");
		fr_event_loop_exit(events, 1);
		break;

	default:
		ERROR("Unhandled signal %s", strsignal(sig));
		fr_exit_now(EXIT_FAILURE);
	}
}

static void NEVER_RETURNS usage(int status)
{
	FILE *output = status ? stderr : stdout;
	fprintf(output, "Usage: radsniff [options][stats options] -- [pcap files]\n");
	fprintf(output, "options:\n");
	fprintf(output, "  -a                    List all interfaces available for capture.\n");
	fprintf(output, "  -c <count>            Number of packets to capture.\n");
	fprintf(output, "  -C <checksum_type>    Enable checksum validation. (Specify 'udp' or 'radius')\n");
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
	fprintf(output, "  -f <filter>           PCAP filter (default is 'udp port <port> or <port + 1> or %i'\n",
		FR_COA_UDP_PORT);
	fprintf(output, "                                     with extra rules to allow .1Q tagged packets)\n");
	fprintf(output, "  -h                    This help message.\n");
	fprintf(output, "  -i <interface>        Capture packets from interface (defaults to all if supported).\n");
	fprintf(output, "  -I <file>             Read packets from <file>\n");
	fprintf(output, "  -l <attr>[,<attr>]    Output packet sig and a list of attributes.\n");
	fprintf(output, "  -L <attr>[,<attr>]    Detect retransmissions using these attributes to link requests.\n");
	fprintf(output, "  -m                    Don't put interface(s) into promiscuous mode.\n");
	fprintf(output, "  -p <port>             Filter packets by port (default is %i).\n", FR_AUTH_UDP_PORT);
	fprintf(output, "  -P <pidfile>          Daemonize and write out <pidfile>.\n");
	fprintf(output, "  -q                    Print less debugging information.\n");
	fprintf(output, "  -r <filter>           RADIUS attribute request filter.\n");
	fprintf(output, "  -R <filter>           RADIUS attribute response filter.\n");
	fprintf(output, "  -s <secret>           RADIUS secret.\n");
	fprintf(output, "  -S                    Write PCAP data to stdout.\n");
	fprintf(output, "  -v                    Show program version information and exit.\n");
	fprintf(output, "  -w <file>             Write output packets to file.\n");
	fprintf(output, "  -x                    Print more debugging information.\n");
	fprintf(output, "stats options:\n");
	fprintf(output, "  -W <interval>         Periodically write out statistics every <interval> seconds.\n");
	fprintf(output, "  -E                    Print stats in CSV format.\n");
	fprintf(output, "  -T <timeout>          How many milliseconds before the request is counted as lost "
		"(defaults to %i).\n", RS_DEFAULT_TIMEOUT);
#ifdef HAVE_COLLECTDC_H
	fprintf(output, "  -N <prefix>           The instance name passed to the collectd plugin.\n");
	fprintf(output, "  -O <server>           Write statistics to this collectd server.\n");
#endif
	fr_exit_now(status);
}

/**
 *
 * @hidecallgraph
 */
int main(int argc, char *argv[])
{
	fr_pcap_t	*in = NULL, *in_p;
	fr_pcap_t	**in_head = &in;
	fr_pcap_t	*out = NULL;

	int		ret = EXIT_SUCCESS;				/* Exit status */

	char		errbuf[PCAP_ERRBUF_SIZE];			/* Error buffer */
	int		port = FR_AUTH_UDP_PORT;

	int		c;
	char const	*raddb_dir = RADDBDIR;
	char const	*dict_dir = DICTDIR;
	TALLOC_CTX	*autofree;

	rs_stats_t	*stats;

	fr_debug_lvl = 1;
	fr_log_fp = stdout;

	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_thread_local_atexit_setup();

	autofree = talloc_autofree_context();

	/*
	 *	Useful if using radsniff as a long running stats daemon
	 */
#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radsniff");
		fr_exit_now(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	conf = talloc_zero(autofree, rs_t);
	RS_ASSERT(conf);
	fr_pair_list_init(&conf->filter_request_vps);
	fr_pair_list_init(&conf->filter_response_vps);

	stats = talloc_zero(conf, rs_stats_t);

	/*
	 *  We don't really want probes taking down machines
	 */
#ifdef HAVE_TALLOC_SET_MEMLIMIT
	/*
	 *	@fixme causes hang in talloc steal
	 */
	 //talloc_set_memlimit(conf, 52428800);		/* 50 MB */
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
	conf->radius_secret = talloc_strdup(conf, RS_DEFAULT_SECRET);
	conf->logger = NULL;

#ifdef HAVE_COLLECTDC_H
	conf->stats.prefix = RS_DEFAULT_PREFIX;
#endif

	/*
	 *  Get options
	 */
	while ((c = getopt(argc, argv, "ab:c:C:d:D:e:Ef:hi:I:l:L:mp:P:qr:R:s:Svw:xXW:T:P:N:O:")) != -1) {
		switch (c) {
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
			pcap_freealldevs(all_devices);
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

		/* UDP/RADIUS checksum validation */
		case 'C':
			if (strcmp(optarg, "udp") == 0) {
				conf->verify_udp_checksum = true;

			} else if (strcmp(optarg, "radius") == 0) {
				conf->verify_radius_authenticator = true;

			} else {
				ERROR("Must specify 'udp' or 'radius' for -C, not %s", optarg);
				usage(1);
			}
			break;

		case 'd':
			raddb_dir = optarg;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'e':
			if (rs_build_event_flags((int *) &conf->event_flags,
						 rs_events, rs_events_len, optarg) < 0) usage(64);
			break;

		case 'E':
			conf->stats.out = RS_STATS_OUT_STDIO_CSV;
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
			talloc_free(conf->radius_secret);
			conf->radius_secret = talloc_strdup(conf, optarg);
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
			fr_exit_now(EXIT_SUCCESS);

		case 'w':
			out = fr_pcap_init(conf, optarg, PCAP_FILE_OUT);
			if (!out) {
				ERROR("Failed creating pcap file \"%s\"", optarg);
				fr_exit_now(EXIT_FAILURE);
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
		fr_exit_now(EXIT_FAILURE);
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

	/* Can't set stats export mode if we're not writing stats */
	if ((conf->stats.out == RS_STATS_OUT_STDIO_CSV) && !conf->stats.interval) {
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

	/* Set the default stats output */
	if (conf->stats.interval && !conf->stats.out) {
		conf->stats.out = RS_STATS_OUT_STDIO_FANCY;
	}

	if (conf->stats.timeout == 0) {
		conf->stats.timeout = RS_DEFAULT_TIMEOUT;
	}

	/*
	 *	If we're writing pcap data, or CSV to stdout we *really* don't want to send
	 *	logging there as well.
	 */
	if (conf->to_stdout || conf->list_attributes || (conf->stats.out == RS_STATS_OUT_STDIO_CSV)) {
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
		conf->pcap_filter = talloc_asprintf(conf, "udp port %d or %d or %d", port, port + 1, FR_COA_UDP_PORT);

		/*
		 *	Using the VLAN keyword strips off the .1q tag
		 *	allowing the UDP filter to work.  Without this
		 *	tagged packets aren't processed.
		 */
		conf->pcap_filter_vlan = talloc_asprintf(conf, "(%s) or (vlan and (%s))",
							 conf->pcap_filter, conf->pcap_filter);
	}

	if (!fr_dict_global_ctx_init(conf, dict_dir)) {
		fr_perror("radsniff");
		fr_exit_now(EXIT_FAILURE);
	}

	if (fr_dict_autoload(radsniff_dict) < 0) {
		fr_perror("radsniff");
		ret = 64;
		goto finish;
	}

	if (fr_dict_attr_autoload(radsniff_dict_attr) < 0) {
		fr_perror("radsniff");
		ret = 64;
		goto finish;
	}

	if (fr_dict_read(fr_dict_unconst(dict_freeradius), raddb_dir, FR_DICTIONARY_FILE) == -1) {
		fr_perror("radsniff");
		ret = 64;
		goto finish;
	}

	/* Initialise the protocol library */
	if (fr_radius_init() < 0) {
		fr_perror("radclient");
		return 1;
	}

	fr_strerror();	/* Clear out any non-fatal errors */

	if (conf->list_attributes) {
		conf->list_da_num = rs_build_dict_list(conf->list_da, NUM_ELEMENTS(conf->list_da),
						       conf->list_attributes);
		if (conf->list_da_num < 0) {
			usage(64);
		}
		rs_packet_print_csv_header();
	}

	if (conf->link_attributes) {
		conf->link_da_num = rs_build_dict_list(conf->link_da, NUM_ELEMENTS(conf->link_da),
						       conf->link_attributes);
		if (conf->link_da_num < 0) {
			usage(64);
		}

		link_tree = rbtree_talloc_alloc(conf, (rbcmp) rs_rtx_cmp, rs_request_t, _unmark_link, 0);
		if (!link_tree) {
			ERROR("Failed creating RTX tree");
			goto finish;
		}
	}

	if (conf->filter_request) {
		fr_cursor_t cursor;
		fr_pair_t *type;

		if (rs_build_filter(&conf->filter_request_vps, conf->filter_request) < 0) usage(64);

		type = fr_cursor_iter_by_da_init(&cursor, &conf->filter_request_vps, attr_packet_type);
		if (type) {
			fr_cursor_remove(&cursor);
			conf->filter_request_code = type->vp_uint32;
			talloc_free(type);
		}
	}

	if (conf->filter_response) {
		fr_cursor_t cursor;
		fr_pair_t *type;

		if (rs_build_filter(&conf->filter_response_vps, conf->filter_response) < 0) usage(64);

		type = fr_cursor_iter_by_da_init(&cursor, &conf->filter_response_vps, attr_packet_type);
		if (type) {
			fr_cursor_remove(&cursor);
			conf->filter_response_code = type->vp_uint32;
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
	request_tree = rbtree_talloc_alloc(conf, (rbcmp) rs_packet_cmp, rs_request_t, _unmark_request, 0);
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
			pcap_freealldevs(all_devices);
			goto finish;
		}

		for (dev_p = all_devices;
		     dev_p;
		     dev_p = dev_p->next) {
			int link_layer;

			/* Don't use the any device, it's horribly broken */
			if (!strcmp(dev_p->name, "any")) continue;

			/* ...same here.  See https://github.com/FreeRADIUS/freeradius-server/pull/3364 for details */
			if (!strncmp(dev_p->name, "pktap", 5)) continue;

			link_layer = fr_pcap_if_link_layer(dev_p);
			if (link_layer < 0) {
				DEBUG2("Skipping %s: %s", dev_p->name, fr_strerror());
				continue;
			}

			if (!fr_pcap_link_layer_supported(link_layer)) {
				DEBUG2("Skipping %s: datalink type %s not supported",
				       dev_p->name, pcap_datalink_val_to_name(link_layer));
				continue;
			}

			*in_head = fr_pcap_init(conf, dev_p->name, PCAP_INTERFACE_IN);
			in_head = &(*in_head)->next;
		}
		pcap_freealldevs(all_devices);

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
			fr_pair_list_log(&default_log, conf->filter_request_vps);
		}

		if (conf->filter_response_code) {
			DEBUG2("  RADIUS response code    : [%s]", fr_packet_codes[conf->filter_response_code]);
		}

		if (conf->filter_response_vps){
			DEBUG2("  RADIUS response filter  :");
			fr_pair_list_log(&default_log, conf->filter_response_vps);
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
			fr_exit_now(EXIT_FAILURE);
		}

		next = &conf->stats.tmpl;

		for (i = 0; i < (NUM_ELEMENTS(rs_useful_codes)); i++) {
			tmpl = rs_stats_collectd_init_latency(conf, next, conf, "exchanged",
							      &(stats->exchange[rs_useful_codes[i]]),
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
				fr_perror("Failed opening pcap handle (%s)", in_p->name);
				if (conf->from_auto || (in_p->type == PCAP_FILE_IN)) {
					continue;
				}

				goto finish;
			}

			if (!fr_pcap_link_layer_supported(in_p->link_layer)) {
				ERROR("Failed opening pcap handle (%s): Datalink type %s not supported",
				      in_p->name, pcap_datalink_val_to_name(in_p->link_layer));
				goto finish;
			}

			if (conf->pcap_filter) {
				/*
				 *	Not all link layers support VLAN tags
				 *	and this is the easiest way to discover
				 *	which do and which don't.
				 */
				if ((!conf->pcap_filter_vlan ||
				     (fr_pcap_apply_filter(in_p, conf->pcap_filter_vlan) < 0)) &&
				     (fr_pcap_apply_filter(in_p, conf->pcap_filter) < 0)) {
					fr_perror("Failed applying filter");
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
			fr_exit_now(EXIT_FAILURE);
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
			fr_perror("Failed opening pcap output (%s)", out->name);
			goto finish;
		}
	}

	/*
	 *	Get the offset between server time and wallclock time
	 */
	fr_time_start();

	/*
	 *	Setup and enter the main event loop. Who needs libev when you can roll your own...
	 */
	 {
		struct timeval now;

		char *buff;

		events = fr_event_list_alloc(conf, _rs_event_status, NULL);
		if (!events) {
			ERROR();
			goto finish;
		}

		/*
		 *  Initialise the signal handler pipe
		 */
		if (pipe(self_pipe) < 0) {
			ERROR("Couldn't open signal pipe: %s", fr_syserror(errno));
			fr_exit_now(EXIT_FAILURE);
		}

		if (fr_event_fd_insert(NULL, events, self_pipe[0],
				       rs_signal_action,
				       NULL,
				       NULL,
				       events) < 0) {
			fr_perror("Failed inserting signal pipe descriptor");
			goto finish;
		}

		buff = fr_pcap_device_names(conf, in, ' ');
		DEBUG("Sniffing on (%s)", buff);

		/*
		 *  Insert our stats processor
		 */
		if (conf->stats.interval && conf->from_dev) {
			now = fr_time_to_timeval(fr_time());
			rs_install_stats_processor(stats, events, in, &now, false);
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
			event->stats = stats;

			/*
			 *	kevent() doesn't indicate that the
			 *	file is readable if there's not
			 *	sufficient packets in the file.
			 *
			 *	Work around this by processing
			 *	files immediately, and only inserting
			 *	"live" inputs, i.e. stdin and
			 *	actual pcap sockets into the
			 *	event loop.
			 */
			if (event->in->type == PCAP_FILE_IN) {
				rs_got_packet(events, in_p->fd, 0, event);
			} else if (fr_event_fd_insert(NULL, events, in_p->fd,
					       rs_got_packet,
					       NULL,
					       NULL,
					       event) < 0) {
				ERROR("Failed inserting file descriptor");
				goto finish;
			}
		}
	}

	/*
	 *	If we just have the pipe, then exit.
	 */
	if (fr_event_list_num_fds(events) == 1) goto finish;


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
	DEBUG2("Entering event loop");

	fr_event_loop(events);	/* Enter the main event loop */

	DEBUG2("Done sniffing");

finish:
	cleanup = true;

	if (conf->daemonize) unlink(conf->pidfile);

	/*
	 *	Free all the things! This also closes all the sockets and file descriptors
	 */
	talloc_free(conf);

	fr_dict_autofree(radsniff_dict);
	fr_radius_free();

	return ret;
}
