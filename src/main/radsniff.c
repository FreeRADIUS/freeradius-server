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
 * @copyright 2013 Arran Cudbard-Bell <arran.cudbardb@freeradius.org>
 * @copyright 2006 The FreeRADIUS server project
 * @copyright 2006 Nicolas Baradakis <nicolas.baradakis@cegetel.net>
 */

RCSID("$Id$")

#define _LIBRADIUS 1
#include <assert.h>
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/event.h>

#include <freeradius-devel/conf.h>
#include <freeradius-devel/pcap.h>
#include <freeradius-devel/radsniff.h>

#ifdef HAVE_COLLECTDC_H
#  include <collectd/client.h>
#endif

static char const *radius_secret = "testing123";
static VALUE_PAIR *filter_vps = NULL;

FILE *log_dst;

struct timeval start_pcap = {0, 0};
static rbtree_t *filter_tree = NULL;
static rbtree_t *request_tree = NULL;
static RADIUS_PACKET *nullpacket = NULL;

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

/** Update cumulative moving average
 *
 */
static void rs_stats_process_latency(rs_latency_t *stats, PW_CODE code)
{
	stats->intervals++;

	if (stats->interval.linked && stats->interval.latency_total) {
		stats->interval.latency_average = (stats->interval.latency_total / stats->interval.linked);
	}

	if (stats->interval.latency_average > 0) {
		stats->latency_cma_count++;
		stats->latency_cma += ((stats->interval.latency_average - stats->latency_cma) /
					stats->latency_cma_count);

		DEBUG1("Stats interval #%i", stats->intervals);
		DEBUG1("%s counters:", fr_packet_codes[code]);
		DEBUG1("\tLinked    : %" PRIu64, stats->interval.linked);
		DEBUG1("\tCMA DP   : %" PRIu64, stats->latency_cma_count);
		DEBUG1("%s latency:", fr_packet_codes[code]);
		DEBUG1("\tHigh      : %lf", stats->interval.latency_high);
		DEBUG1("\tLow       : %lf", stats->interval.latency_low);
		DEBUG1("\tAverage   : %lf", stats->interval.latency_average);
		DEBUG1("\tCMA       : %lf", stats->latency_cma);
	}
}

/** Process stats for a single interval
 *
 */
static void rs_stats_process(void *ctx)
{
	size_t i;
	size_t rs_codes_len = (sizeof(rs_useful_codes) / sizeof(*rs_useful_codes));
	rs_update_t	*this = ctx;
	rs_stats_t	*stats = this->stats;
	rs_t		*conf = this->conf;

	struct timeval now;

	gettimeofday(&now, NULL);
	/*
	 *	Latency stats need a bit more work to calculate the CMA.
	 *
	 *	No further work is required for codes.
	 */
	for (i = 0; i < rs_codes_len; i++) {
		rs_stats_process_latency(&stats->exchange[rs_useful_codes[i]], rs_useful_codes[i]);
//		rs_stats_process_latency(&stats->forward[rs_useful_codes[i]]);
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

	/*
	 *	Rinse and repeat...
	 */
	for (i = 0; i < rs_codes_len; i++) {
		memset(&stats->exchange[rs_useful_codes[i]].interval, 0,
		       sizeof(stats->exchange[rs_useful_codes[i]].interval));
	}

	memset(&stats->count.type, 0, sizeof(stats->count.type));

	{
		now.tv_sec += conf->stats.interval;
		fr_event_insert(this->list, rs_stats_process, ctx, &now, NULL);
	}
}

/** Update counters
 *
 */
static void rs_stats_update_count(rs_counters_t *counter, RADIUS_PACKET *current)
{
	counter->type[current->code]++;
}


/** Update latency statistics for request/response and forwarded packets
 *
 */
static void rs_stats_update_latency(rs_latency_t *stats, struct timeval *latency)
{
	double lint;

	stats->interval.linked++;
	lint = latency->tv_sec + (latency->tv_usec / 1000000.0);
	if (lint > stats->interval.latency_high) {
		stats->interval.latency_high = lint;
	}
	if (!stats->interval.latency_low || (lint < stats->interval.latency_low)) {
		stats->interval.latency_low = lint;
	}
	stats->interval.latency_total += lint;
}

static int rs_filter_packet(RADIUS_PACKET *packet)
{
	vp_cursor_t cursor, check_cursor;
	VALUE_PAIR *check_item;
	VALUE_PAIR *vp;
	unsigned int pass, fail;
	int compare;

	pass = fail = 0;
	for (vp = paircursor(&cursor, &packet->vps);
	     vp;
	     vp = pairnext(&cursor)) {
		for (check_item = paircursor(&check_cursor, &filter_vps);
		     check_item;
		     check_item = pairnext(&check_cursor))
			if ((check_item->da == vp->da)
			 && (check_item->op != T_OP_SET)) {
				compare = paircmp(check_item, vp);
				if (compare == 1)
					pass++;
				else
					fail++;
			}
	}

	if ((fail == 0) && (pass != 0)) {
		/*
		 *	Cache authentication requests, as the replies
		 *	may not match the RADIUS filter.
		 */
		if ((packet->code == PW_CODE_AUTHENTICATION_REQUEST) ||
		    (packet->code == PW_CODE_ACCOUNTING_REQUEST)) {
			rbtree_deletebydata(filter_tree, packet);

			if (!rbtree_insert(filter_tree, packet)) {
			oom:
				ERROR("Out of memory");
				exit(1);
			}
		}
		return 0;	/* matched */
	}

	/*
	 *	Don't create erroneous matches.
	 */
	if ((packet->code == PW_CODE_AUTHENTICATION_REQUEST) ||
	    (packet->code == PW_CODE_ACCOUNTING_REQUEST)) {
		rbtree_deletebydata(filter_tree, packet);
		return 1;
	}

	/*
	 *	Else see if a previous Access-Request
	 *	matched.  If so, also print out the
	 *	matching accept, reject, or challenge.
	 */
	if ((packet->code == PW_CODE_AUTHENTICATION_ACK) ||
	    (packet->code == PW_CODE_AUTHENTICATION_REJECT) ||
	    (packet->code == PW_CODE_ACCESS_CHALLENGE) ||
	    (packet->code == PW_CODE_ACCOUNTING_RESPONSE)) {
		RADIUS_PACKET *reply;

		/*
		 *	This swaps the various fields.
		 */
		reply = rad_alloc_reply(NULL, packet);
		if (!reply) goto oom;

		compare = 1;
		if (rbtree_finddata(filter_tree, reply)) {
			compare = 0;
		}

		rad_free(&reply);
		return compare;
	}

	return 1;
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

static void rs_process_packet(rs_event_t *event, struct pcap_pkthdr const *header, uint8_t const *data)
{

	static int count = 1;			/* Packets seen */
	rs_stats_t *stats = event->stats;

	/*
	 *	Define pointers for current's attributes
	 */
	const struct ip_header *ip;		/* The IP header */
	const struct udp_header *udp;		/* The UDP header */
	const uint8_t *payload;			/* Packet payload */

	/*
	 *	And define the size of the structures we're using
	 */
	int size_ethernet = sizeof(struct ethernet_header);
	int size_ip = sizeof(struct ip_header);
	int size_udp = sizeof(struct udp_header);

	/*
	 *	For FreeRADIUS
	 */
	RADIUS_PACKET *current, *original;
	struct timeval elapsed;
	struct timeval latency;

	/*
	 *	Define our current's attributes
	 */
	if ((data[0] == 2) && (data[1] == 0) &&
	    (data[2] == 0) && (data[3] == 0)) {
		ip = (struct ip_header const *) (data + 4);

	} else {
		ip = (struct ip_header const *)(data + size_ethernet);
	}

	udp = (struct udp_header const *)(((uint8_t const *) ip) + size_ip);
	payload = (uint8_t const *)(((uint8_t const *) udp) + size_udp);

	current = rad_alloc(event->conf, 0);
	if (!current) {
		ERROR("Out of memory");
		return;
	}

	/*
	 *	Populate various fields from our PCAP data
	 */
	current->src_ipaddr.af = AF_INET;
	current->src_ipaddr.ipaddr.ip4addr.s_addr = ip->ip_src.s_addr;
	current->src_port = ntohs(udp->udp_sport);
	current->dst_ipaddr.af = AF_INET;
	current->dst_ipaddr.ipaddr.ip4addr.s_addr = ip->ip_dst.s_addr;
	current->dst_port = ntohs(udp->udp_dport);
	current->timestamp = header->ts;

	memcpy(&current->data, &payload, sizeof(current->data));
	current->data_len = header->len - (payload - data);

	if (!rad_packet_ok(current, 0)) {
		DEBUG("Packet: %s", fr_strerror());

		DEBUG("  From     %s:%d", inet_ntoa(ip->ip_src), ntohs(udp->udp_sport));
		DEBUG("  To:      %s:%d", inet_ntoa(ip->ip_dst), ntohs(udp->udp_dport));
		DEBUG("  Type:    %s", fr_packet_codes[current->code]);

		rad_free(&current);
		return;
	}

	switch (current->code) {
	case PW_CODE_COA_REQUEST:
		/* we need a 16 x 0 byte vector for decrypting encrypted VSAs */
		original = nullpacket;
		break;
	case PW_CODE_ACCOUNTING_RESPONSE:
	case PW_CODE_AUTHENTICATION_REJECT:
	case PW_CODE_AUTHENTICATION_ACK:
		/* look for a matching request and use it for decoding */
		original = rbtree_finddata(request_tree, current);
		break;
	case PW_CODE_ACCOUNTING_REQUEST:
	case PW_CODE_AUTHENTICATION_REQUEST:
		/* save the request for later matching */
		original = rad_alloc_reply(event->conf, current);
		original->timestamp = header->ts;
		if (original) { /* just ignore allocation failures */
			rbtree_deletebydata(request_tree, original);
			rbtree_insert(request_tree, original);
		}
		/* fallthrough */
	default:
		/* don't attempt to decode any encrypted attributes */
		original = NULL;
	}

	/*
	 *  Decode the data without bothering to check the signatures.
	 */
	if (rad_decode(current, original, event->conf->radius_secret) != 0) {
		rad_free(&current);
		fr_perror("decode");
		return;
	}

	if (filter_vps && rs_filter_packet(current)) {
		rad_free(&current);
		DEBUG("Packet number %d doesn't match", count++);
		return;
	}

	if (event->out) {
		pcap_dump((void *) (event->out->dumper), header, data);
		goto check_filter;
	}

	if (!start_pcap.tv_sec) {
		start_pcap = header->ts;
	}

	rs_tv_sub(&header->ts, &start_pcap, &elapsed);

	rs_stats_update_count(&stats->count, current);
	if (original) {
		rs_tv_sub(&current->timestamp, &original->timestamp, &latency);

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
		rs_stats_update_latency(&stats->exchange[original->code], &latency);

		/*
		 *	Print info about the response.
		 */
		DEBUG("(%i) %s Id %i %s:%s:%d <- %s:%d\t+%u.%03u\t+%u.%03u", count++,
		      fr_packet_codes[current->code], current->id,
		      event->in->name,
		      inet_ntoa(ip->ip_src), ntohs(udp->udp_sport),
		      inet_ntoa(ip->ip_dst), ntohs(udp->udp_dport),
		      (unsigned int) elapsed.tv_sec, ((unsigned int) elapsed.tv_usec / 1000),
		      (unsigned int) latency.tv_sec, ((unsigned int) latency.tv_usec / 1000));

	} else {
		/*
		 *	Print info about the request
		 */
		DEBUG("(%i) %s Id %i %s:%s:%d -> %s:%d\t+%u.%03u", count++,
		      fr_packet_codes[current->code], current->id,
		      event->in->name,
		      inet_ntoa(ip->ip_src), ntohs(udp->udp_sport),
		      inet_ntoa(ip->ip_dst), ntohs(udp->udp_dport),
		      (unsigned int) elapsed.tv_sec, ((unsigned int) elapsed.tv_usec / 1000));
	}

	if (fr_debug_flag > 1) {
		if (current->vps) {
			if (event->conf->do_sort) {
				pairsort(&current->vps, true);
			}
			vp_printlist(log_dst, current->vps);
			pairfree(&current->vps);
		}
	}

	/*
	 *  We've seen a successful reply to this, so delete it now
	 */
	if (original) {
		rbtree_deletebydata(request_tree, original);
	}

	if (!event->conf->to_stdout && (fr_debug_flag > 4)) {
		rad_print_hex(current);
	}

	fflush(log_dst);

check_filter:
	/*
	 *  If we're doing filtering, Access-Requests are cached in the
	 *  filter tree.
	 */
	if (!filter_vps ||
	    ((current->code != PW_CODE_AUTHENTICATION_REQUEST) && (current->code != PW_CODE_ACCOUNTING_REQUEST))) {
		rad_free(&current);
	}
}

static void rs_got_packet(UNUSED fr_event_list_t *events, UNUSED int fd, void *ctx)
{
	rs_event_t *event = ctx;
	pcap_t *handle = event->in->handle;

	int ret;
	const uint8_t *data;
	struct pcap_pkthdr *header;

	ret = pcap_next_ex(handle, &header, &data);
	if (ret < 0) {
		ERROR("Error requesting next packet, got (%i): %s", ret, pcap_geterr(handle));
		return;
	}

	rs_process_packet(event, header, data);
}

static void _rs_event_status(struct timeval *wake)
{
	if (wake && ((wake->tv_sec != 0) || (wake->tv_usec >= 100000))) {
		DEBUG("Waking up in %d.%01u seconds.", (int) wake->tv_sec, (unsigned int) wake->tv_usec / 100000);
	}
}

/** Wrapper function to allow rad_free to be called as an rbtree destructor callback
 *
 * @param packet to free.
 */
static void _rb_rad_free(void *packet)
{
	rad_free((RADIUS_PACKET **) &packet);
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
	fprintf(output, "  -i <interface>  Capture packets from interface (defaults to any if supported).\n");
	fprintf(output, "  -I <file>       Read packets from file (overrides input of -F).\n");
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
#ifdef HAVE_COLLECTDC_H
	fprintf(output, "  -P <prefix>     Prefix counters with this value.\n");
	fprintf(output, "  -O <server>     Write statistics to this collectd server.\n");
#endif
	exit(status);
}

int main(int argc, char *argv[])
{
	rs_t *conf;

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

	fr_debug_flag = 2;
	log_dst = stdout;

	talloc_set_log_stderr();

	conf = talloc_zero(NULL, rs_t);
	if (!fr_assert(conf)) {
		exit (1);
	}

	talloc_set_memlimit(conf, 52428800);		/* 50 MB */

	/*
	 *  Get options
	 */
	while ((opt = getopt(argc, argv, "c:d:DFf:hi:I:p:qr:s:Svw:xXW:P:O:")) != EOF) {
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
			if (conf->stats.interval <= 0) {
				ERROR("Stats interval must be > 0");
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

	if (!conf->radius_secret) {
		conf->radius_secret = radius_secret;
	}

	if (conf->stats.interval && !conf->stats.out) {
		conf->stats.out = RS_STATS_OUT_STDIO;
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

	if (conf->radius_filter) {
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

		filter_tree = rbtree_create((rbcmp) fr_packet_cmp, _rb_rad_free, 0);
		if (!filter_tree) {
			ERROR("Failed creating filter tree");
			ret = 64;
			goto finish;
		}
	}

	/*
	 *	Setup the request tree
	 */
	request_tree = rbtree_create((rbcmp) fr_packet_cmp, _rb_rad_free, 0);
	if (!request_tree) {
		ERROR("Failed creating request tree");
		goto finish;
	}

	/*
	 *	Allocate a null packet for decrypting attributes in CoA requests
	 */
	nullpacket = rad_alloc(conf, 0);
	if (!nullpacket) {
		ERROR("Out of memory");
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
			DEBUG1("Sniffing with options:");
		if (conf->from_dev)	{
			char *buff = fr_pcap_device_names(conf, in, ' ');
			DEBUG1("  Device(s)                : [%s]", buff);
			talloc_free(buff);
		}
		if (conf->to_file || conf->to_stdout) {
			DEBUG1("  Writing to               : [%s]", out->name);
		}
		if (limit > 0)	{
			DEBUG1("  Capture limit (packets)  : [%d]", limit);
		}
			DEBUG1("  PCAP filter              : [%s]", conf->pcap_filter);
			DEBUG1("  RADIUS secret            : [%s]", conf->radius_secret);
		if (filter_vps){
			DEBUG1("  RADIUS filter            :");
			vp_printlist(log_dst, filter_vps);
		}
	}

	/*
	 *	Open our interface to collectd
	 */
#ifdef HAVE_COLLECTDC_H
	if (conf->stats.out == RS_STATS_OUT_COLLECTD) {
		if (rs_stats_collectd_open(conf) < 0) {
			exit(1);
		}

		if (conf->stats.out == RS_STATS_OUT_COLLECTD) {
			size_t i;
			rs_stats_tmpl_t *tmpl, **next;

			next = &conf->stats.tmpl;

			for (i = 0; i < (sizeof(rs_useful_codes) / sizeof(*rs_useful_codes)); i++) {
				tmpl = rs_stats_collectd_init_latency(conf, next, conf, "radius_exchange",
								      &stats.exchange[rs_useful_codes[i]],
								      rs_useful_codes[i]);
				if (!tmpl) {
					goto tmpl_error;
				}
				next = &(tmpl->next);
				tmpl = rs_stats_collectd_init_counter(conf, next, conf, "radius_code",
								      &stats.count.type[rs_useful_codes[i]],
								      rs_useful_codes[i]);
				if (!tmpl) {
					tmpl_error:
					ERROR("Error allocating memory for stats template");
					goto finish;
				}
				next = &(tmpl->next);
			}
		}
	}
#endif

	/*
	 *	This actually opens the capture interfaces/files (we just allocated the memory earlier)
	 */
	{
		fr_pcap_t *prev = NULL;

		for (in_p = in;
		     in_p;
		     in_p = in_p->next) {
			if (fr_pcap_open(in_p) < 0) {
				if (!conf->from_auto) {
					ERROR("Failed opening pcap handle for %s", in_p->name);
					goto finish;
				}

				DEBUG("Failed opening pcap handle: %s", fr_strerror());
				/* Unlink it from the list */
				if (prev) {
					prev->next = in_p->next;
					talloc_free(in_p);
					in_p = prev;
				} else {
					in = in_p->next;
					talloc_free(in_p);
					in_p = in;
				}

				goto next;
			}

			if (conf->pcap_filter) {
				if (fr_pcap_apply_filter(in_p, conf->pcap_filter) < 0) {
					ERROR("Failed applying filter");
					goto finish;
				}
			}

			next:
			prev = in_p;
		}
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

	if (filter_tree) {
		rbtree_free(filter_tree);
	}

	/*
	 *	Setup and enter the main event loop. Who needs libev when you can roll your own...
	 */
	 {
	 	fr_event_list_t		*events;
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

	     	     	event = talloc(events, rs_event_t);
	     	     	event->conf = conf;
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

		/*
		 *	Insert our stats processor
		 */
		if (conf->stats.interval) {
			struct timeval now;
			update.list = events;
			update.conf = conf;
			update.stats = &stats;

			gettimeofday(&now, NULL);
			now.tv_sec += conf->stats.interval;
			fr_event_insert(events, rs_stats_process, (void *) &update, &now, NULL);
		}

		ret = fr_event_loop(events);	/* Enter the main event loop */
	 }

	INFO("Done sniffing");

	finish:

	INFO("Exiting...");
	/*
	 *	Free all the things! This also closes all the sockets and file descriptors
	 */
	talloc_free(conf);

	return ret;
}
