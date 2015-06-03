/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 of the
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
 * @file radsniff.h
 * @brief Structures and prototypes for the RADIUS sniffer.
 *
 * @copyright 2013 Arran Cudbard-Bell <arran.cudbardb@freeradius.org>
 * @copyright 2006 The FreeRADIUS server project
 * @copyright 2006 Nicolas Baradakis <nicolas.baradakis@cegetel.net>
 */

RCSIDH(radsniff_h, "$Id$")

#include <sys/types.h>

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/pcap.h>
#include <freeradius-devel/event.h>

#ifdef HAVE_COLLECTDC_H
#  include <collectd/client.h>
#endif

#define RS_DEFAULT_PREFIX	"radsniff"	//!< Default instance
#define RS_DEFAULT_SECRET	"testing123"	//!< Default secret
#define RS_DEFAULT_TIMEOUT	5200		//!< Standard timeout of 5s + 300ms to cover network latency
#define RS_FORCE_YIELD		1000		//!< Service another descriptor every X number of packets
#define RS_RETRANSMIT_MAX	5		//!< Maximum number of times we expect to see a packet retransmitted
#define RS_MAX_ATTRS		50		//!< Maximum number of attributes we can filter on.
#define RS_SOCKET_REOPEN_DELAY  5000		//!< How long we delay re-opening a collectd socket.

/*
 *	Logging macros
 */
#undef DEBUG2
#define DEBUG2(fmt, ...)	if (fr_debug_lvl > 2) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
#undef DEBUG
#define DEBUG(fmt, ...)		if (fr_debug_lvl > 1) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)
#undef INFO
#define INFO(fmt, ...)		if (fr_debug_lvl > 0) fprintf(fr_log_fp , fmt "\n", ## __VA_ARGS__)

#define ERROR(fmt, ...)		fr_perror("radsniff: " fmt, ## __VA_ARGS__)

#define RIDEBUG_ENABLED()	(conf->print_packet && (fr_debug_lvl > 0))
#define RDEBUG_ENABLED()	(conf->print_packet && (fr_debug_lvl > 1))
#define RDEBUG_ENABLED2()	(conf->print_packet && (fr_debug_lvl > 2))

#define REDEBUG(fmt, ...)	if (conf->print_packet) fr_perror("%s (%" PRIu64 ") " fmt , timestr, count, ## __VA_ARGS__)
#define RIDEBUG(fmt, ...)	if (conf->print_packet && (fr_debug_lvl > 0)) fprintf(fr_log_fp , "%s (%" PRIu64 ") " fmt "\n", timestr, count, ## __VA_ARGS__)
#define RDEBUG(fmt, ...)	if (conf->print_packet && (fr_debug_lvl > 1)) fprintf(fr_log_fp , "%s (%" PRIu64 ") " fmt "\n", timestr, count, ## __VA_ARGS__)
#define RDEBUG2(fmt, ...)	if (conf->print_packet && (fr_debug_lvl > 2)) fprintf(fr_log_fp , "%s (%" PRIu64 ") " fmt "\n", timestr, count, ## __VA_ARGS__)

typedef enum {
	RS_NORMAL	= 0x01,
	RS_UNLINKED	= 0x02,
	RS_RTX		= 0x04,
	RS_REUSED	= 0x08,
	RS_ERROR	= 0x10,
	RS_LOST		= 0x20
} rs_status_t;

typedef void (*rs_packet_logger_t)(uint64_t count, rs_status_t status, fr_pcap_t *handle, RADIUS_PACKET *packet,
				   struct timeval *elapsed, struct timeval *latency, bool response, bool body);
typedef enum {
#ifdef HAVE_COLLECTDC_H
	RS_STATS_OUT_COLLECTD = 1,
#endif
	RS_STATS_OUT_STDIO
} stats_out_t;

typedef struct rs rs_t;

#ifdef HAVE_COLLECTDC_H
typedef struct rs_stats_tmpl rs_stats_tmpl_t;
typedef struct rs_stats_value_tmpl rs_stats_value_tmpl_t;
#endif

typedef struct rs_counters {
	uint64_t type[PW_CODE_MAX];
} rs_counters_t;

/** Stats for a single interval
 *
 * And interval is defined as the time between a call to the stats output function.
 */
typedef struct rs_latency {
	int			intervals;			//!< Number of stats intervals.

	double			latency_smoothed;		//!< Smoothed moving average.
	uint64_t		latency_smoothed_count;		//!< Number of CMA datapoints processed.

	struct {
		uint64_t		received_total;		//!< Total received over interval.
		uint64_t		linked_total;		//!< Total request/response pairs over interval.
		uint64_t		unlinked_total;		//!< Total unlinked over interval.
		uint64_t		reused_total;		//!< Total reused over interval.
		uint64_t		lost_total;		//!< Total packets definitely lost in this interval.
		uint64_t		rt_total[RS_RETRANSMIT_MAX + 1];	//!< Number of RTX until complete
										//!< over interval.


		double			received;		//!< Number of this type of packet we've received.
		double			linked;			//!< Number of request/response pairs
		double			unlinked;		//!< Response with no request.
		double			reused;			//!< ID re-used too quickly.
		double			lost;			//!< Never got a response to a request.
		double			rt[RS_RETRANSMIT_MAX + 1];	//!< Number of times we saw the same
									//!< request packet.

		long double		latency_total;		//!< Total latency between requests/responses in the
								//!< interval.
		double			latency_average;	//!< Average latency (this iteration).

		double			latency_high;		//!< Latency high water mark.
		double			latency_low;		//!< Latency low water mark.
	} interval;
} rs_latency_t;

typedef struct rs_malformed {
	uint64_t		min_length_packet;
	uint64_t		min_length_field;
	uint64_t		min_length_mimatch;
	uint64_t		header_overflow;
	uint64_t		invalid_attribute;
	uint64_t		attribute_too_short;
	uint64_t		attribute_overflow;
	uint64_t		ma_invalid_length;
	uint64_t		attribute_underflow;
	uint64_t		too_many_attributes;
	uint64_t		ma_missing;
} rs_malformed_t;

/** One set of statistics
 *
 */
typedef struct rs_stats {
	int			intervals;		//!< Number of stats intervals.

	rs_latency_t		exchange[PW_CODE_MAX];  //!< We end up allocating ~16K, but memory is cheap so
							//!< what the hell.  This is required because instances of
							//!< FreeRADIUS delay Access-Rejects, which would artificially
							//!< increase latency stats for Access-Requests.

	struct timeval		quiet;			//!< We may need to 'mute' the stats if libpcap starts
							//!< dropping packets, or we run out of memory.
} rs_stats_t;

typedef struct rs_capture {
	struct pcap_pkthdr	*header;		//!< PCAP packet header.
	uint8_t			*data;			//!< PCAP packet data.
} rs_capture_t;

/** Wrapper for RADIUS_PACKET
 *
 * Allows an event to be associated with a request packet.  This is required because we need to disarm
 * the event timer when a response is received, so we don't erroneously log the response as lost.
 */
typedef struct rs_request {
	uint64_t		id;			//!< Monotonically increasing packet counter.
	fr_event_t		*event;			//!< Event created when we received the original request.

	bool			logged;			//!< Whether any messages regarding this request were logged.

	struct timeval		when;			//!< Time when the packet was received, or next time an event
							//!< is scheduled.
	fr_pcap_t		*in;			//!< PCAP handle the original request was received on.
	RADIUS_PACKET		*packet;		//!< The original packet.
	RADIUS_PACKET		*expect;		//!< Request/response.
	RADIUS_PACKET		*linked;		//!< The subsequent response or forwarded request the packet
							//!< was linked against.


	rs_capture_t		capture[RS_RETRANSMIT_MAX];	//!< Buffered request packets (if a response filter
								//!< has been applied).
	rs_capture_t		*capture_p;			//!< Next packet slot.

	uint64_t		rt_req;			//!< Number of times we saw the same request packet.
	uint64_t		rt_rsp;			//!< Number of times we saw a retransmitted response
							//!< packet.
	rs_latency_t		*stats_req;		//!< Latency entry for the request type.
	rs_latency_t		*stats_rsp;		//!< Latency entry for the request type.

	bool			silent_cleanup;		//!< Cleanup was forced before normal expiry period,
							//!< ignore stats about packet loss.

	VALUE_PAIR		*link_vps;		//!< VALUE_PAIRs used to link retransmissions.

	bool			in_request_tree;	//!< Whether the request is currently in the request tree.
	bool			in_link_tree;		//!< Whether the request is currently in the linked tree.
} rs_request_t;

/** Statistic write/print event
 *
 */
typedef struct rs_event {
	fr_event_list_t		*list;			//!< The event list.

	fr_pcap_t		*in;			//!< PCAP handle event occurred on.
	fr_pcap_t		*out;			//!< Where to write output.

	rs_stats_t		*stats;			//!< Where to write stats.
} rs_event_t;

/** FD data which gets passed to callbacks
 *
 */
typedef struct rs_update {
	fr_event_list_t		*list;			//!< List to insert new event into.

	fr_pcap_t		*in;			//!< Linked list of PCAP handles to check for drops.
	rs_stats_t		*stats;			//!< Stats to process.
} rs_update_t;


struct rs {
	bool			from_file;		//!< Were reading pcap data from files.
	bool			from_dev;		//!< Were reading pcap data from devices.
	bool			from_stdin;		//!< Were reading pcap data from stdin.
	bool			to_file;		//!< Were writing pcap data to files.
	bool			to_stdout;		//!< Were writing pcap data to stdout.

	bool			daemonize;		//!< Daemonize and write PID out to file.
	char const		*pidfile;		//!< File to write PID to.

	bool			from_auto;		//!< From list was auto-generated.
	bool			promiscuous;		//!< Capture in promiscuous mode.
	bool			print_packet;		//!< Print packet info, disabled with -W
	bool			decode_attrs;		//!< Whether we should decode attributes in the request
							//!< and response.
	bool			verify_udp_checksum;	//!< Check UDP checksum in packets.

	char const		*radius_secret;		//!< Secret to decode encrypted attributes.

	char			*pcap_filter;		//!< PCAP filter string applied to live capture devices.

	char			*list_attributes;	//!< Raw attribute filter string.
	DICT_ATTR const 	*list_da[RS_MAX_ATTRS]; //!< Output CSV with these attribute values.
	int			list_da_num;

	char			*link_attributes;	//!< Names of DICT_ATTRs to use for rtx.
	DICT_ATTR const		*link_da[RS_MAX_ATTRS];	//!< DICT_ATTRs to link on.
	int			link_da_num;		//!< Number of rtx DICT_ATTRs.

	char const		*filter_request;	//!< Raw request filter string.
	char const		*filter_response;	//!< Raw response filter string.

	VALUE_PAIR 		*filter_request_vps;	//!< Sorted filter vps.
	VALUE_PAIR 		*filter_response_vps;	//!< Sorted filter vps.
	PW_CODE			filter_request_code;	//!< Filter request packets by code.
	PW_CODE			filter_response_code;	//!< Filter response packets by code.

	rs_status_t		event_flags;		//!< Events we log and capture on.
	rs_packet_logger_t	logger;			//!< Packet logger

	int			buffer_pkts;		//!< Size of the ring buffer to setup for live capture.
	uint64_t		limit;			//!< Maximum number of packets to capture

	struct {
		int			interval;		//!< Time between stats updates in seconds.
		stats_out_t		out;			//!< Where to write stats.
		int			timeout;		//!< Maximum length of time we wait for a response.

#ifdef HAVE_COLLECTDC_H
		char const		*collectd;		//!< Collectd server/port/unixsocket
		char const		*prefix;		//!< Prefix collectd stats with this value.
		lcc_connection_t	*handle;		//!< Collectd client handle.
		rs_stats_tmpl_t		*tmpl;			//!< The stats templates we created on startup.
#endif
	} stats;
};

#ifdef HAVE_COLLECTDC_H

/** Callback for processing stats values.
 *
 */
typedef void (*rs_stats_cb_t)(rs_t *conf, rs_stats_value_tmpl_t *tmpl);
struct rs_stats_value_tmpl {
	void			*src;			//!< Pointer to source field in struct. Must be set by
							//!< stats_collectdc_init caller.
	int			type;			//!< Stats type.
	rs_stats_cb_t		cb;			//!< Callback used to process stats
	void			*dst;			//!< Pointer to dst field in value struct. Must be set
							//!< by stats_collectdc_init caller.
};

/** Stats templates
 *
 * This gets processed to turn radsniff stats structures into collectd lcc_value_list_t structures.
 */
struct rs_stats_tmpl
{
	rs_stats_value_tmpl_t	*value_tmpl;		//!< Value template
	void			*stats;			//!< Struct containing the raw stats to process
	lcc_value_list_t	*value;			//!< Collectd stats struct to populate

	rs_stats_tmpl_t		*next;			//!< Next...
};

/*
 *	collectd.c - Registration and processing functions
 */
rs_stats_tmpl_t *rs_stats_collectd_init_latency(TALLOC_CTX *ctx, rs_stats_tmpl_t **out, rs_t *conf,
						char const *type, rs_latency_t *stats, PW_CODE code);
void rs_stats_collectd_do_stats(rs_t *conf, rs_stats_tmpl_t *tmpls, struct timeval *now);
int rs_stats_collectd_open(rs_t *conf);
int rs_stats_collectd_close(rs_t *conf);

#endif
