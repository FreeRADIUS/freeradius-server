/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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
#include <assert.h>
#include <signal.h>
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/event.h>

#include <freeradius-devel/conf.h>
#include <freeradius-devel/pcap.h>
#include <freeradius-devel/radsniff.h>

#ifdef HAVE_COLLECTDC_H
#  include <collectd/client.h>
#endif

static VALUE_PAIR *filter_vps = NULL;

FILE *log_dst;

static rs_t *conf;
struct timeval start_pcap = {0, 0};
static rbtree_t *request_tree = NULL;
static fr_event_list_t *events;
static bool cleanup;

typedef int (*rbcmp)(void const *, void const *);

static char const *radsniff_version = "radsniff version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" RADIUSD_VERSION_COMMIT ")"
#endif
", built on " __DATE__ " at " __TIME__;

static int rs_useful_codes[] = {
	PW_CODE_AUTHENTICATION_REQUEST,		//!< RFC2865 - Authentication request
	PW_CODE_AUTHENTICATION_ACK,		//!< RFC2865 - Access-Accept
	PW_CODE_AUTHENTICATION_REJECT,		//!< RFC2865 - Access-Reject
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
		INFO("\tCMA       : %.3lfms", stats->latency_cma);
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

/** Update cumulative moving average and other stats
 *
 */
static void rs_stats_process_latency(rs_latency_t *stats)
{
	if (stats->interval.linked_total && stats->interval.latency_total) {
		stats->interval.latency_average = (stats->interval.latency_total / stats->interval.linked_total);
	}

	if (stats->interval.latency_average > 0) {
		stats->latency_cma_count++;
		stats->latency_cma += ((stats->interval.latency_average - stats->latency_cma) /
					stats->latency_cma_count);
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
		INFO("Stats still muted because of previous error");
		goto clear;
	}

	/*
	 *	Latency stats need a bit more work to calculate the CMA.
	 *
	 *	No further work is required for codes.
	 */
	for (i = 0; i < rs_codes_len; i++) {
		rs_stats_process_latency(&stats->exchange[rs_useful_codes[i]]);
		rs_stats_process_counters(&stats->exchange[rs_useful_codes[i]]);
		if (fr_debug_flag > 0) {
			rs_stats_print(&stats->exchange[rs_useful_codes[i]], rs_useful_codes[i]);
		}
	}

#ifdef HAVE_COLLECTDC_H
	/*
	 *	Update stats in collectd using the complex structures we
	 *	initialised earlier.
	 */
	if (conf->stats.out == RS_STATS_OUT_COLLECTD) {
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
		now.tv_sec += conf->stats.interval;
		now.tv_usec = 0;
		fr_event_insert(this->list, rs_stats_process, ctx, &now, NULL);
	}
}


/** Update latency statistics for request/response and forwarded packets
 *
 */
static void rs_stats_update_latency(rs_latency_t *stats, struct timeval *latency)
{
	double lint;

	stats->interval.linked_total++;
	/* More useful is this is in milliseconds */
	lint = (latency->tv_sec + (latency->tv_usec / 1000000.0)) * 1000;
	if (lint > stats->interval.latency_high) {
		stats->interval.latency_high = lint;
	}
	if (!stats->interval.latency_low || (lint < stats->interval.latency_low)) {
		stats->interval.latency_low = lint;
	}
	stats->interval.latency_total += lint;

}

static void rs_packet_cleanup(void *ctx)
{
	rs_request_t *request = ctx;
	RADIUS_PACKET *packet = request->packet;

	assert(request->stats_req);
	assert(!request->rt_rsp || request->stats_rsp);
	assert(packet);

	/*
	 *	Don't pollute stats or print spurious messages as radsniff closes.
	 */
	if (cleanup) {
		goto skip;
	}

	/*
	 *	Were at packet cleanup time which is when the packet was received + timeout
	 *	and it's not been linked with a forwarded packet or a response.
	 *
	 *	We now count it as lost.
	 */
	if (!request->linked && !request->forced_cleanup) {
		request->stats_req->interval.lost_total++;

		RDEBUG("(%i) ** LOST **", request->id);
		RIDEBUG("(%i) %s Id %i %s:%s:%d -> %s:%d", request->id,
			fr_packet_codes[packet->code], packet->id,
			request->in->name,
			fr_inet_ntop(packet->dst_ipaddr.af, &packet->dst_ipaddr.ipaddr), packet->dst_port,
			fr_inet_ntop(packet->src_ipaddr.af, &packet->src_ipaddr.ipaddr), packet->src_port);
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

	skip:

	/*
	 *	If were attempting to cleanup the request, and it's no longer in the request_tree
	 *	something has gone very badly wrong.
	 */
	assert(rbtree_deletebydata(request_tree, request));

	if (fr_event_list_num_elements(events) == 0) {
		fr_event_loop_exit(events, 1);
	}
}

/*
 *	@fixme: This can be removed once packet destructors are set by rad_alloc
 */
static int _request_free(rs_request_t *request)
{
	if (!cleanup) {
		RDEBUG("(%i) Cleaning up request packet ID %i", request->id, request->packet->id);
	}

	rad_free(&request->packet);
	rad_free(&request->linked);

	return 0;
}

static void rs_packet_process(rs_event_t *event, struct pcap_pkthdr const *header, uint8_t const *data)
{

	static int		count = 0;	/* Packets seen */

	rs_stats_t		*stats = event->stats;
	struct timeval		elapsed;
	struct timeval		latency;

	/*
	 *	Pointers into the packet data we just received
	 */
	size_t len;
	uint8_t const		*p = data;
	struct ip_header const	*ip = NULL;	/* The IP header */
	struct ip_header6 const	*ip6 = NULL;	/* The IPv6 header */
	struct udp_header const	*udp;		/* The UDP header */
	uint8_t			version;	/* IP header version */
	bool			response;	/* Was it a response code */

	decode_fail_t		reason;		/* Why we failed decoding the packet */

	RADIUS_PACKET *current;			/* Current packet were processing */
	rs_request_t *original;

	if (!start_pcap.tv_sec) {
		start_pcap = header->ts;
	}

	if (header->caplen <= 5) {
		INFO("Packet too small, captured %i bytes", header->caplen);
		return;
	}

	/*
	 *	Loopback header
	 */
	if ((p[0] == 2) && (p[1] == 0) && (p[2] == 0) && (p[3] == 0)) {
		p += 4;
	/*
	 *	Ethernet header
	 */
	} else {
		p += sizeof(struct ethernet_header);
	}

	version = (p[0] & 0xf0) >> 4;
	switch (version) {
	case 4:
		ip = (struct ip_header const *)p;
		len = (0x0f & ip->ip_vhl) * 4;	/* ip_hl specifies length in 32bit words */
		p += len;
		break;

	case 6:
		ip6 = (struct ip_header6 const *)p;
		p += sizeof(struct ip_header6);

		break;

	default:
		DEBUG("IP version invalid %i", version);
		return;
	}

	/*
	 *	End of variable length bits, do basic check now to see if packet looks long enough
	 */
	len = (p - data) + sizeof(struct udp_header) + (sizeof(radius_packet_t) - 1);	/* length value */
	if (len > header->caplen) {
		DEBUG("Packet too small, we require at least %zu bytes, captured %i bytes",
		      (size_t) len, header->caplen);
		return;
	}

	udp = (struct udp_header const *)p;
	p += sizeof(struct udp_header);

	/*
	 *	With artificial talloc memory limits there's a good chance we can
	 *	recover once some requests timeout, so make an effort to deal
	 *	with allocation failures gracefully.
	 */
	current = rad_alloc(conf, 0);
	if (!current) {
		ERROR("Failed allocating memory to hold decoded packet");
		rs_tv_add_ms(&header->ts, conf->stats.timeout, &stats->quiet);
		return;
	}
	current->timestamp = header->ts;
	current->data_len = header->caplen - (data - p);
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
		memcpy(&current->src_ipaddr.ipaddr.ip6addr.s6_addr, &ip6->ip_src.s6_addr,
		       sizeof(current->src_ipaddr.ipaddr.ip6addr.s6_addr));

		current->dst_ipaddr.af = AF_INET6;
		memcpy(&current->dst_ipaddr.ipaddr.ip6addr.s6_addr, &ip6->ip_dst.s6_addr,
		       sizeof(current->dst_ipaddr.ipaddr.ip6addr.s6_addr));
	}

	current->src_port = ntohs(udp->udp_sport);
	current->dst_port = ntohs(udp->udp_dport);

	if (!rad_packet_ok(current, 0, &reason)) {
		RIDEBUG("(%i) ** %s **", count, fr_strerror());

		RIDEBUG("(%i) %s Id %i %s:%s:%d -> %s:%d\t+%u.%03u", count,
			fr_packet_codes[current->code], current->id,
			event->in->name,
			fr_inet_ntop(current->src_ipaddr.af, &current->src_ipaddr.ipaddr), current->src_port,
			fr_inet_ntop(current->dst_ipaddr.af, &current->dst_ipaddr.ipaddr), current->dst_port,
			(unsigned int) elapsed.tv_sec, ((unsigned int) elapsed.tv_usec / 1000));

		rad_free(&current);
		return;
	}

	switch (current->code) {
	case PW_CODE_ACCOUNTING_RESPONSE:
	case PW_CODE_AUTHENTICATION_REJECT:
	case PW_CODE_AUTHENTICATION_ACK:
	case PW_CODE_COA_NAK:
	case PW_CODE_COA_ACK:
	case PW_CODE_DISCONNECT_NAK:
	case PW_CODE_DISCONNECT_ACK:
	case PW_CODE_STATUS_CLIENT:
		{
			rs_request_t search;
			struct timeval when;

			rs_tv_add_ms(&header->ts, conf->stats.timeout, &when);

			/* look for a matching request and use it for decoding */
			search.packet = current;
			original = rbtree_finddata(request_tree, &search);

			/*
			 *	Only decode attributes if we want to print them or filter on them
			 *	rad_packet_ok does checks to verify the packet is actually valid.
			 */
			if (filter_vps || conf->print_packet) {
				if (rad_decode(current, original ? original->packet : NULL,
					       conf->radius_secret) != 0) {
					rad_free(&current);
					fr_perror("decode");
					return;
				}
			}

			/*
			 *	Check if we've managed to link it to a request
			 */
			if (original) {
				/*
				 *	Is this a retransmit?
				 */
				if (!original->linked) {
					original->stats_rsp = &stats->exchange[current->code];
				} else {
					RDEBUG("(%i) ** RETRANSMISSION **", count);
					original->rt_rsp++;

					rad_free(&original->linked);
					fr_event_delete(event->list, &original->event);
				}

				original->linked = talloc_steal(original, current);

				/*
				 *	Some RADIUS servers and proxy servers may not cache
				 *	Accounting-Responses (and possibly other code),
				 *	and may immediately re-use a RADIUS packet src
				 *	port/id combination on receipt of a response.
				 */
				if (conf->dequeue[current->code]) {
					fr_event_delete(event->list, &original->event);
					rbtree_deletebydata(request_tree, original);
				} else {
					if (!fr_event_insert(event->list, rs_packet_cleanup, original, &when,
						    	     &original->event)) {
						ERROR("Failed inserting new event");
						rbtree_deletebydata(request_tree, original);

						return;
					}
				}
			/*
			 *	No request seen, or request was dropped by attribute filter
			 */
			} else {
				/*
				 *	If filter_vps are set assume the original request was dropped,
				 *	the alternative is maintaining another 'filter', but that adds
				 *	complexity, reduces max capture rate, and is generally a PITA.
				 */
				if (filter_vps) {
					rad_free(&current);
					RDEBUG2("(%i) Dropped by attribute filter", count);
					return;
				}

				RDEBUG("(%i) ** UNLINKED **", count);
				stats->exchange[current->code].interval.unlinked_total++;
			}

			response = true;
		}
			break;
	case PW_CODE_ACCOUNTING_REQUEST:
	case PW_CODE_AUTHENTICATION_REQUEST:
	case PW_CODE_COA_REQUEST:
	case PW_CODE_DISCONNECT_REQUEST:
	case PW_CODE_STATUS_SERVER:
		{
			rs_request_t search;
			struct timeval when;

			/*
			 *	Only decode attributes if we want to print them or filter on them
			 *	rad_packet_ok does checks to verify the packet is actually valid.
			 */
			if (filter_vps || conf->print_packet) {
				if (rad_decode(current, NULL, conf->radius_secret) != 0) {
					rad_free(&current);
					fr_perror("decode");
					return;
				}
			}

			/*
			 *	Now verify the packet passes the attribute filter
			 */
			if (filter_vps && !pairvalidate_relaxed(filter_vps, current->vps)) {
				rad_free(&current);
				RDEBUG2("(%i) Dropped by attribute filter", count);
				return;
			}

			/*
			 *	save the request for later matching
			 */
			search.packet = rad_alloc_reply(conf, current);
			if (!search.packet) {
				ERROR("Failed allocating memory to hold expected reply");
				rs_tv_add_ms(&header->ts, conf->stats.timeout, &stats->quiet);
				rad_free(&current);
				return;
			}
			search.packet->code = current->code;

			rs_tv_add_ms(&header->ts, conf->stats.timeout, &when);

			original = rbtree_finddata(request_tree, &search);

			/*
			 *	Upstream device re-used src/dst ip/port id without waiting
			 *	for the timeout period to expire, or a response.
			 */
			if (original && memcmp(original->packet->vector, current->vector,
					       sizeof(original->packet->vector) != 0)) {
				RDEBUG2("(%i) ** PREMATURE ID RE-USE **", count);
				stats->exchange[current->code].interval.reused_total++;
				original->forced_cleanup = true;

				fr_event_delete(event->list, &original->event);
				rbtree_deletebydata(request_tree, original);
				original = NULL;
			}

			if (original) {
				RDEBUG("(%i) ** RETRANSMISSION **", count);
				original->rt_req++;

				rad_free(&original->packet);
				original->packet = talloc_steal(original, search.packet);

				/* We may of seen the response, but it may of been lost upstream */
				rad_free(&original->linked);
				fr_event_delete(event->list, &original->event);
			} else {
				original = talloc_zero(conf, rs_request_t);
				talloc_set_destructor(original, _request_free);

				original->id = count;
				original->in = event->in;
				original->stats_req = &stats->exchange[current->code];
				original->packet = talloc_steal(original, search.packet);

				rbtree_insert(request_tree, original);
			}

			/* update the timestamp in either case */
			original->packet->timestamp = header->ts;

			if (!fr_event_insert(event->list, rs_packet_cleanup, original, &when, &original->event)) {
				ERROR("Failed inserting new event");
				rbtree_deletebydata(request_tree, original);

				return;
			}
			response = false;
		}
			break;
		default:
			RDEBUG("** Unsupported code %i **", current->code);
			rad_free(&current);

			return;
	}

	if (event->out) {
		pcap_dump((void *) (event->out->dumper), header, data);
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
		 *	It also justifies allocating 255 instances rs_latency_t.
		 */
		rs_stats_update_latency(&stats->exchange[current->code], &latency);
		rs_stats_update_latency(&stats->exchange[original->packet->code], &latency);


		/*
		 *	Print info about the request/response.
		 */
		RIDEBUG("(%i) %s Id %i %s:%s:%d %s %s:%d\t+%u.%03u\t+%u.%03u", count,
			fr_packet_codes[current->code], current->id,
			event->in->name,
			fr_inet_ntop(current->src_ipaddr.af, &current->src_ipaddr.ipaddr), current->src_port,
			response ? "<-" : "->",
			fr_inet_ntop(current->dst_ipaddr.af, &current->dst_ipaddr.ipaddr), current->dst_port,
			(unsigned int) elapsed.tv_sec, ((unsigned int) elapsed.tv_usec / 1000),
			(unsigned int) latency.tv_sec, ((unsigned int) latency.tv_usec / 1000));
	/*
	 *	It's the original request
	 */
	} else {
		/*
		 *	Print info about the request
		 */
		RIDEBUG("(%i) %s Id %i %s:%s:%d %s %s:%d\t+%u.%03u", count,
			fr_packet_codes[current->code], current->id,
			event->in->name,
			fr_inet_ntop(current->src_ipaddr.af, &current->src_ipaddr.ipaddr), current->src_port,
			response ? "<-" : "->",
			fr_inet_ntop(current->dst_ipaddr.af, &current->dst_ipaddr.ipaddr), current->dst_port,
			(unsigned int) elapsed.tv_sec, ((unsigned int) elapsed.tv_usec / 1000));
	}

	if ((fr_debug_flag > 1) && current->vps) {
		if (conf->do_sort) {
			pairsort(&current->vps, true);
		}
		vp_printlist(log_dst, current->vps);
		pairfree(&current->vps);
	}

	if (!conf->to_stdout && (fr_debug_flag > 4)) {
		rad_print_hex(current);
	}

	fflush(log_dst);

	/*
	 *	If it's a request, a duplicate of the packet will of already been stored.
	 *	If it's a unlinked response, we need to free it explicitly, as it will
	 *	not be done by the event queue.
	 */
	if (!response || !original) {
		rad_free(&current);
	}
}

static void rs_got_packet(UNUSED fr_event_list_t *el, int fd, void *ctx)
{
	rs_event_t *event = ctx;
	pcap_t *handle = event->in->handle;

	int i;
	int ret;
	const uint8_t *data;
	struct pcap_pkthdr *header;

	for (i = 0; (event->in->type == PCAP_FILE_IN) || (i < RS_FORCE_YIELD); i++) {
		ret = pcap_next_ex(handle, &header, &data);
		if (ret == 0) {
			/* No more packets available at this time */
			return;
		}
		if (ret == -2 && (event->in->type == PCAP_FILE_IN)) {
			INFO("Done reading packets (%s)", event->in->name);
			fr_event_fd_delete(events, 0, fd);
			return;
		}
		if (ret < 0) {
			ERROR("Error requesting next packet, got (%i): %s", ret, pcap_geterr(handle));
			return;
		}

		count++;
		rs_packet_process(count, event, header, data);

		/*
		 *	We've hit our capture limit, break out of the event loop
		 */
		if ((conf->limit > 0) && (count >= conf->limit)) {
			INFO("Captured %i packets, exiting...", count);
			fr_event_loop_exit(events, 1);
			return;
		}
	}
}

static void _rs_event_status(struct timeval *wake)
{
	if (wake && ((wake->tv_sec != 0) || (wake->tv_usec >= 100000))) {
		DEBUG2("Waking up in %d.%01u seconds.", (int) wake->tv_sec, (unsigned int) wake->tv_usec / 100000);
	}
}

/** Wrapper function to allow rad_free to be called as an rbtree destructor callback
 *
 * @param request to free.
 */
static void _rb_rad_free(void *request)
{
	talloc_free(request);
}

/** Wrapper around fr_packet_cmp to strip off the outer request struct
 *
 */
static int rs_packet_cmp(rs_request_t const *a, rs_request_t const *b)
{
	return fr_packet_cmp(a->packet, b->packet);
}

static void NEVER_RETURNS usage(int status)
{
	FILE *output = status ? stderr : stdout;
	fprintf(output, "Usage: radsniff [options][stats options]\n");
	fprintf(output, "options:\n");
	fprintf(output, "  -c <count>      Number of packets to capture.\n");
	fprintf(output, "  -d <directory>  Set dictionary directory.\n");
	fprintf(output, "  -F              Filter PCAP file from stdin to stdout.\n");
	fprintf(output, "  -f <filter>     PCAP filter (default is 'udp port <port> or <port + 1> or 3799')\n");
	fprintf(output, "  -h              This help message.\n");
	fprintf(output, "  -i <interface>  Capture packets from interface (defaults to all if supported).\n");
	fprintf(output, "  -I <file>       Read packets from file (overrides input of -F).\n");
	fprintf(output, "  -m              Don't put interface(s) into promiscuous mode.\n");
	fprintf(output, "  -p <port>       Filter packets by port (default is 1812).\n");
	fprintf(output, "  -q              Print less debugging information.\n");
	fprintf(output, "  -r <filter>     RADIUS attribute filter.\n");
	fprintf(output, "  -s <secret>     RADIUS secret.\n");
	fprintf(output, "  -S              Sort attributes in the packet (useful for diffing responses).\n");
	fprintf(output, "  -v              Show program version information.\n");
	fprintf(output, "  -w <file>       Write output packets to file (overrides output of -F).\n");
	fprintf(output, "  -x              Print more debugging information (defaults to -xx).\n");
	fprintf(output, "stats options:\n");
	fprintf(output, "  -W <interval>   Periodically write out statistics every <interval> seconds.\n");
	fprintf(output, "  -T <timeout>    How many milliseconds before the request is counted as lost "
		"(defaults to %i).\n", RS_DEFAULT_TIMEOUT);
#ifdef HAVE_COLLECTDC_H
	fprintf(output, "  -P <prefix>     collectd plugin instance name.\n");
	fprintf(output, "  -O <server>     Write statistics to this collectd server.\n");
#endif
	exit(status);
}

static void rs_cleanup(UNUSED int sig)
{
	DEBUG2("Signalling event loop to exit");
	fr_event_loop_exit(events, 1);
}

int main(int argc, char *argv[])
{
	fr_pcap_t *in = NULL, *in_p;
	fr_pcap_t **in_head = &in;
	fr_pcap_t *out = NULL;

	int ret = 1;					/* Exit status */
	int limit = -1;					/* How many packets to sniff */

	char errbuf[PCAP_ERRBUF_SIZE];			/* Error buffer */
	int port = 1812;

	char buffer[1024];

	int opt;
	FR_TOKEN parsecode;
	char const *radius_dir = RADIUS_DIR;

	rs_stats_t stats;

	fr_debug_flag = 1;
	log_dst = stdout;

	talloc_set_log_stderr();

	conf = talloc_zero(NULL, rs_t);
	if (!fr_assert(conf)) {
		exit (1);
	}

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
	conf->limit = -1;
	conf->promiscuous = true;
	conf->stats.prefix = RS_DEFAULT_PREFIX;
	conf->radius_secret = RS_DEFAULT_SECRET;

	/*
	 *  Get options
	 */
	while ((opt = getopt(argc, argv, "c:d:DFf:hi:I:mp:qr:s:Svw:xXW:P:O:")) != EOF) {
		switch (opt) {
		case 'c':
			limit = atoi(optarg);
			if (limit <= 0) {
				fprintf(stderr, "radsniff: Invalid number of packets \"%s\"", optarg);
				exit(1);
			}
			break;

		case 'd':
			radius_dir = optarg;
			break;

		case 'D':
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

		case 'F':
			conf->from_stdin = true;
			conf->to_stdout = true;
			break;

		case 'f':
			conf->pcap_filter = optarg;
			break;

		case 'h':
			usage(0);
			break;

		case 'i':
			*in_head = fr_pcap_init(conf, optarg, PCAP_INTERFACE_IN);
			if (!*in_head) {
				goto finish;
			}
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
		case 'm':
			conf->promiscuous = false;
			break;

		case 'p':
			port = atoi(optarg);
			break;

		case 'q':
			if (fr_debug_flag > 0) {
				fr_debug_flag--;
			}
			break;

		case 'r':
			conf->radius_filter = optarg;
			break;

		case 's':
			conf->radius_secret = optarg;
			break;

		case 'S':
			conf->do_sort = true;
			break;

		case 'v':
#ifdef HAVE_COLLECTDC_H
			INFO("%s, %s, collectdclient version %s", radsniff_version, pcap_lib_version(),
			     lcc_version_string());
#else
			INFO("%s %s", radsniff_version, pcap_lib_version());
#endif
			exit(0);
			break;

		case 'w':
			out = fr_pcap_init(conf, optarg, PCAP_FILE_OUT);
			conf->to_file = true;
			break;

		case 'x':
		case 'X':
		  	fr_debug_flag++;
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
		case 'P':
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
	 *	If were writing pcap data stdout we *really* don't want to send
	 *	logging there as well.
	 */
 	log_dst = conf->to_stdout ? stderr : stdout;

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

	if (dict_init(radius_dir, RADIUS_DICTIONARY) < 0) {
		fr_perror("radsniff");
		ret = 64;
		goto finish;
	}
	fr_strerror();	/* Clear out any non-fatal errors */

	if (conf->radius_filter) {
		vp_cursor_t cursor;
		VALUE_PAIR *vp;

		parsecode = userparse(NULL, conf->radius_filter, &filter_vps);
		if (parsecode == T_OP_INVALID) {
			ERROR("Invalid RADIUS filter \"%s\" (%s)", conf->radius_filter, fr_strerror());
			ret = 64;
			goto finish;
		}

		if (!filter_vps) {
			ERROR("Empty RADIUS filter \"%s\"", conf->radius_filter);
			ret = 64;
			goto finish;
		}

		for (vp = paircursor(&cursor, &filter_vps);
		     vp;
		     vp = pairnext(&cursor)) {
		     	/*
		     	 *	xlat expansion isn't support hered
		     	 */
		     	if (vp->type == VT_XLAT) {
		     		vp->type = VT_DATA;
		     		vp->vp_strvalue = vp->value.xlat;
		     	}
		}
	}

	/*
	 *	Setup the request tree
	 */
	request_tree = rbtree_create((rbcmp) rs_packet_cmp, _rb_rad_free, 0);
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
		     	/* Don't use the any devices, it's horribly broken */
		     	if (!strcmp(dev_p->name, "any")) continue;
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
	if (fr_debug_flag > 2) {
			DEBUG2("Sniffing with options:");
		if (conf->from_dev)	{
			char *buff = fr_pcap_device_names(conf, in, ' ');
			DEBUG2("  Device(s)                : [%s]", buff);
			talloc_free(buff);
		}
		if (conf->to_file || conf->to_stdout) {
			DEBUG2("  Writing to               : [%s]", out->name);
		}
		if (conf->limit > 0)	{
			DEBUG2("  Capture limit (packets)  : [%d]", conf->limit);
		}
			DEBUG2("  PCAP filter              : [%s]", conf->pcap_filter);
			DEBUG2("  RADIUS secret            : [%s]", conf->radius_secret);
		if (filter_vps){
			DEBUG2("  RADIUS filter            :");
			vp_printlist(log_dst, filter_vps);
		}
	}

	/*
	 *	Open our interface to collectd
	 */
#ifdef HAVE_COLLECTDC_H
	if (conf->stats.out == RS_STATS_OUT_COLLECTD) {
		size_t i;
		rs_stats_tmpl_t *tmpl, **next;

		if (rs_stats_collectd_open(conf) < 0) {
			exit(1);
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
			if (fr_pcap_open(in_p) < 0) {
				if (!conf->from_auto) {
					ERROR("Failed opening pcap handle for %s", in_p->name);
					goto finish;
				}

				DEBUG("Failed opening pcap handle: %s", fr_strerror());
				continue;
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
	}

	/*
	 *	Open our output interface (if we have one);
	 */
	if (out) {
		if (fr_pcap_open(out) < 0) {
			ERROR("Failed opening pcap output");
			goto finish;
		}
	}

	/*
	 *	Setup signal handlers so we always exit gracefully, ensuring output buffers are always
	 *	flushed.
	 */
	{
#ifdef HAVE_SIGACTION
		struct sigaction action;
		memset(&action, 0, sizeof(action));

		action.sa_handler = rs_cleanup;
		sigaction(SIGINT, &action, NULL);
		sigaction(SIGQUIT, &action, NULL);
#else
		signal(SIGINT, rs_cleanup);
#  ifdef SIGQUIT
		signal(SIGQUIT, rs_cleanup);
#  endif
#endif
	}

	/*
	 *	Setup and enter the main event loop. Who needs libev when you can roll your own...
	 */
	 {
	 	struct timeval now;
	 	rs_update_t		update;

	 	char *buff;

		memset(&stats, 0, sizeof(stats));
		memset(&update, 0, sizeof(update));

	 	events = fr_event_list_create(conf, _rs_event_status);
	 	if (!events) {
	 		ERROR();
	 		goto finish;
	 	}

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
		INFO("Sniffing on (%s)", buff);
		talloc_free(buff);

		gettimeofday(&now, NULL);

		/*
		 *	Insert our stats processor
		 */
		if (conf->stats.interval) {
			update.list = events;
			update.stats = &stats;
			update.in = in;

			now.tv_sec += conf->stats.interval;
			now.tv_usec = 0;
			fr_event_insert(events, rs_stats_process, (void *) &update, &now, NULL);
		}

		ret = fr_event_loop(events);	/* Enter the main event loop */
	}

	INFO("Done sniffing");

	finish:

	cleanup = true;
	/*
	 *	Free all the things! This also closes all the sockets and file descriptors
	 */
	talloc_free(conf);

	return ret;
}
