/*
 *  radsniff.c	Display the RADIUS traffic on the network.
 *
 *  Version:    $Id$
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *  Copyright 2006  The FreeRADIUS server project
 *  Copyright 2006  Nicolas Baradakis <nicolas.baradakis@cegetel.net>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#define _LIBRADIUS 1
#include <freeradius-devel/libradius.h>

#include <pcap.h>

#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/radsniff.h>

static const char *radius_secret = "testing123";
static VALUE_PAIR *filter_vps = NULL;

static int do_sort = 0;
static int to_stdout = 0;
static FILE *log_dst;

#undef DEBUG1
#define DEBUG1 if (fr_debug_flag > 2) fprintf
#undef DEBUG
#define DEBUG if (fr_debug_flag > 1) fprintf
#undef INFO
#define INFO if (fr_debug_flag > 0) fprintf

struct timeval start_pcap = {0, 0};
static rbtree_t *filter_tree = NULL;
static rbtree_t *request_tree = NULL;
static pcap_dumper_t *out = NULL;
static RADIUS_PACKET *nullpacket = NULL;

typedef int (*rbcmp)(const void *, const void *);

static const char *radsniff_version = "radsniff version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" RADIUSD_VERSION_COMMIT ")"
#endif
;

static int filter_packet(RADIUS_PACKET *packet)
{
	VALUE_PAIR *check_item;
	VALUE_PAIR *vp;
	unsigned int pass, fail;
	int compare;

	pass = fail = 0;
	for (vp = packet->vps; vp != NULL; vp = vp->next) {
		for (check_item = filter_vps;
		     check_item != NULL;
		     check_item = check_item->next)
			if ((check_item->attribute == vp->attribute)
			 && (check_item->operator != T_OP_SET)) {
				compare = paircmp(check_item, vp);
				if (compare == 1)
					pass++;
				else
					fail++;
			}
	}

	if (fail == 0 && pass != 0) {
		/*
		 *	Cache authentication requests, as the replies
		 *	may not match the RADIUS filter.
		 */
		if ((packet->code == PW_AUTHENTICATION_REQUEST) ||
		    (packet->code == PW_ACCOUNTING_REQUEST)) {
			rbtree_deletebydata(filter_tree, packet);
			
			if (!rbtree_insert(filter_tree, packet)) {
			oom:
				fprintf(stderr, "radsniff: Out of memory\n");
				exit(1);
			}
		}
		return 0;	/* matched */
	}

	/*
	 *	Don't create erroneous matches.
	 */
	if ((packet->code == PW_AUTHENTICATION_REQUEST) ||
	    (packet->code == PW_ACCOUNTING_REQUEST)) {
		rbtree_deletebydata(filter_tree, packet);
		return 1;
	}
	
	/*
	 *	Else see if a previous Access-Request
	 *	matched.  If so, also print out the
	 *	matching accept, reject, or challenge.
	 */
	if ((packet->code == PW_AUTHENTICATION_ACK) ||
	    (packet->code == PW_AUTHENTICATION_REJECT) ||
	    (packet->code == PW_ACCESS_CHALLENGE) ||
	    (packet->code == PW_ACCOUNTING_RESPONSE)) {
		RADIUS_PACKET *reply;

		/*
		 *	This swaps the various fields.
		 */
		reply = rad_alloc_reply(packet);
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

/*
 *	Bubble goodness
 */
static void sort(RADIUS_PACKET *packet)
{
	int i, j, size;
	VALUE_PAIR *vp, *tmp;
	VALUE_PAIR *array[1024]; /* way more than necessary */

	size = 0;
	for (vp = packet->vps; vp != NULL; vp = vp->next) {
		array[size++] = vp;
	}

	if (size == 0) return;

	for (i = 0; i < size - 1; i++)  {
		for (j = 0; j < size - 1 - i; j++) {
			if (array[j + 1]->attribute < array[j]->attribute)  {
				tmp = array[j];         
				array[j] = array[j + 1];
				array[j + 1] = tmp;
			}
		}
	}

	/*
	 *	And put them back again.
	 */
	vp = packet->vps = array[0];
	for (i = 1; i < size; i++) {
		vp->next = array[i];
		vp = array[i];
	}
	vp->next = NULL;
}

#define USEC 1000000
static void tv_sub(const struct timeval *end, const struct timeval *start,
		   struct timeval *elapsed)
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

static void got_packet(UNUSED uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *data)
{

	static int count = 1;			/* Packets seen */
	
	/*
	 *  Define pointers for packet's attributes
	 */
	const struct ethernet_header *ethernet;	/* The ethernet header */
	const struct ip_header *ip;		/* The IP header */
	const struct udp_header *udp;		/* The UDP header */
	const uint8_t *payload;			/* Packet payload */
	
	/*
	 *  And define the size of the structures we're using
	 */
	int size_ethernet = sizeof(struct ethernet_header);
	int size_ip = sizeof(struct ip_header);
	int size_udp = sizeof(struct udp_header);
	
	/*
	 *  For FreeRADIUS
	 */
	RADIUS_PACKET *packet, *original;
	struct timeval elapsed;

	/*
	 * Define our packet's attributes
	 */

	if ((data[0] == 2) && (data[1] == 0) &&
	    (data[2] == 0) && (data[3] == 0)) {
		ip = (const struct ip_header*) (data + 4);

	} else {
		ethernet = (const struct ethernet_header*)(data);
		ip = (const struct ip_header*)(data + size_ethernet);
	}
	
	udp = (const struct udp_header*)(((const uint8_t *) ip) + size_ip);
	payload = (const uint8_t *)(((const uint8_t *) udp) + size_udp);

	packet = malloc(sizeof(*packet));
	if (!packet) {
		fprintf(stderr, "Out of memory\n");
		return;
	}

	memset(packet, 0, sizeof(*packet));
	packet->src_ipaddr.af = AF_INET;
	packet->src_ipaddr.ipaddr.ip4addr.s_addr = ip->ip_src.s_addr;
	packet->src_port = ntohs(udp->udp_sport);
	packet->dst_ipaddr.af = AF_INET;
	packet->dst_ipaddr.ipaddr.ip4addr.s_addr = ip->ip_dst.s_addr;
	packet->dst_port = ntohs(udp->udp_dport);

	memcpy(&packet->data, &payload, sizeof(packet->data));
	packet->data_len = header->len - (payload - data);

	if (!rad_packet_ok(packet, 0)) {
		DEBUG(log_dst, "Packet: %s\n", fr_strerror());
		
		DEBUG(log_dst, "  From     %s:%d\n", inet_ntoa(ip->ip_src), ntohs(udp->udp_sport));
		DEBUG(log_dst, "  To:      %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(udp->udp_dport));
		DEBUG(log_dst, "  Type:    %s\n", fr_packet_codes[packet->code]);

		free(packet);
		return;
	}
	
	switch (packet->code) {
	case PW_COA_REQUEST:
		/* we need a 16 x 0 byte vector for decrypting encrypted VSAs */
		original = nullpacket;
		break;
	case PW_AUTHENTICATION_ACK:
		/* look for a matching request and use it for decoding */
		original = rbtree_finddata(request_tree, packet);
		break;
	case PW_AUTHENTICATION_REQUEST:
		/* save the request for later matching */
		original = rad_alloc_reply(packet);
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
	if (rad_decode(packet, original, radius_secret) != 0) {
		free(packet);
		fr_perror("decode");
		return;
	}

	/*
	 *  We've seen a successfull reply to this, so delete it now
	 */
	if (original)
		rbtree_deletebydata(request_tree, original);

	if (filter_vps && filter_packet(packet)) {
		free(packet);
		DEBUG(log_dst, "Packet number %d doesn't match\n", count++);
		return;
	}

	if (out) {
		pcap_dump((void *) out, header, data);
		goto check_filter;
	}

	INFO(log_dst, "%s Id %d\t", fr_packet_codes[packet->code], packet->id);

	/*
	 *  Print the RADIUS packet
	 */
	INFO(log_dst, "%s:%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->udp_sport));
	INFO(log_dst, "%s:%d", inet_ntoa(ip->ip_dst), ntohs(udp->udp_dport));
	
	DEBUG1(log_dst, "\t(%d packets)", count++);
	
	if (!start_pcap.tv_sec) {
		start_pcap = header->ts;
	}

	tv_sub(&header->ts, &start_pcap, &elapsed);

	INFO(log_dst, "\t+%u.%03u", (unsigned int) elapsed.tv_sec,
	       (unsigned int) elapsed.tv_usec / 1000);
	       
	if (fr_debug_flag > 1) {
		DEBUG(log_dst, "\n");
		if (packet->vps) {
			if (do_sort) sort(packet);
	
			vp_printlist(log_dst, packet->vps);
			pairfree(&packet->vps);
		}
	}
	
	INFO(log_dst, "\n");
	
	if (!to_stdout && (fr_debug_flag > 4)) {
		rad_print_hex(packet);
	}
	
	fflush(log_dst);

 check_filter:
	/*
	 *  If we're doing filtering, Access-Requests are cached in the
	 *  filter tree.
	 */
	if (!filter_vps ||
	    ((packet->code != PW_AUTHENTICATION_REQUEST) &&
	     (packet->code != PW_ACCOUNTING_REQUEST))) {
		free(packet);
	}
}

static void NEVER_RETURNS usage(int status)
{
	FILE *output = status ? stderr : stdout;
	fprintf(output, "Usage: radsniff [options]\n");
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
	exit(status);
}

int main(int argc, char *argv[])
{
	const char *from_dev = NULL;			/* Capture from device */
	const char *from_file = NULL;			/* Read from pcap file */
	int from_stdin = 0;				/* Read from stdin */
	
	pcap_t *in;					/* PCAP input handle */
	
	int limit = -1;					/* How many packets to sniff */
	
	char errbuf[PCAP_ERRBUF_SIZE];			/* Error buffer */

	char *to_file = NULL;				/* PCAP output file */
	
	char *pcap_filter = NULL;			/* PCAP filter string */
	char *radius_filter = NULL;
	int port = 1812;
	
	struct bpf_program fp;				/* Holds compiled filter */
	bpf_u_int32 ip_mask = PCAP_NETMASK_UNKNOWN;	/* Device Subnet mask */
	bpf_u_int32 ip_addr = 0;			/* Device IP */
	
	char buffer[1024];

	int opt;
	FR_TOKEN parsecode;
	const char *radius_dir = RADIUS_DIR;
	
	fr_debug_flag = 2;
	log_dst = stdout;

	/*
	 *  Get options
	 */
	while ((opt = getopt(argc, argv, "c:d:Ff:hi:I:p:qr:s:Svw:xX")) != EOF) {
		switch (opt)
		{
		case 'c':
			limit = atoi(optarg);
			if (limit <= 0) {
				fprintf(stderr, "radsniff: Invalid number of packets \"%s\"\n", optarg);
				exit(1);
			}
			break;
		case 'd':
			radius_dir = optarg;
			break;
		case 'F':
			from_stdin = 1;
			to_stdout = 1;
			break;
		case 'f':
			pcap_filter = optarg;
			break;
		case 'h':
			usage(0);
			break;
		case 'i':
			from_dev = optarg;
			break;
		case 'I':
			from_file = optarg;
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
			radius_filter = optarg;
			break;
		case 's':
			radius_secret = optarg;
			break;
		case 'S':
			do_sort = 1;
			break;
		case 'v':
			INFO(log_dst, "%s %s\n", radsniff_version, pcap_lib_version());
			exit(0);
			break;
		case 'w':
			to_file = optarg;
			break;
		case 'x':
		case 'X':
		  	fr_debug_flag++;
			break;
		default:
			usage(64);
		}
	}
	
	/* What's the point in specifying -F ?! */
	if (from_stdin && from_file && to_file) {
		usage(64);
	}
	
	/* Can't read from both... */
	if (from_file && from_dev) {
		usage(64);
	}
	
	/* Reading from file overrides stdin */
	if (from_stdin && (from_file || from_dev)) {
		from_stdin = 0;
	}
	
	/* Writing to file overrides stdout */
	if (to_file && to_stdout) {
		to_stdout = 0;
	}
	
	/*
	 *  If were writing pcap data stdout we *really* don't want to send
	 *  logging there as well.
	 */
 	log_dst = to_stdout ? stderr : stdout;

#if !defined(HAVE_PCAP_FOPEN_OFFLINE) || !defined(HAVE_PCAP_DUMP_FOPEN)
	if (from_stdin || to_stdout) {
		fprintf(stderr, "radsniff: PCAP streams not supported.\n");
		exit(64);
	}
#endif

	if (!pcap_filter) {
		pcap_filter = buffer;
		snprintf(buffer, sizeof(buffer), "udp port %d or %d or %d",
			 port, port + 1, 3799);
	}
	
	/*
	 *  There are times when we don't need the dictionaries.
	 */
	if (!to_stdout) {
		if (dict_init(radius_dir, RADIUS_DICTIONARY) < 0) {
			fr_perror("radsniff");
			exit(64);
		}
	}

	if (radius_filter) {
		parsecode = userparse(radius_filter, &filter_vps);
		if (parsecode == T_OP_INVALID) {
			fprintf(stderr, "radsniff: Invalid RADIUS filter \"%s\" (%s)\n", radius_filter, fr_strerror());
			exit(64);
		}
		
		if (!filter_vps) {
			fprintf(stderr, "radsniff: Empty RADIUS filter \"%s\"\n", radius_filter);
			exit(64);
		}

		filter_tree = rbtree_create((rbcmp) fr_packet_cmp, free, 0);
		if (!filter_tree) {
			fprintf(stderr, "radsniff: Failed creating filter tree\n");
			exit(1);
		}
	}

	/*
	 *  Setup the request tree
	 */
	request_tree = rbtree_create((rbcmp) fr_packet_cmp, free, 0);
	if (!request_tree) {
		fprintf(stderr, "radsniff: Failed creating request tree\n");
		exit(1);
	}

	/*
	 *  Allocate a null packet for decrypting attributes in CoA requests
	 */
	nullpacket = rad_alloc(0);
	if (!nullpacket) {
		fprintf(stderr, "radsniff: Out of memory\n");
		exit(1);
	}

	/*
	 *  Get the default capture device
	 */
	if (!from_stdin && !from_file && !from_dev) {
		from_dev = pcap_lookupdev(errbuf);
		if (!from_dev) {
			fprintf(stderr, "radsniff: Failed discovering default interface (%s)\n", errbuf);
			exit(1);
		}

		INFO(log_dst, "Capturing from interface \"%s\"\n", from_dev);
	}
	
	/*
	 *  Print captures values which will be used
	 */
	if (fr_debug_flag > 2) {
				DEBUG1(log_dst, "Sniffing with options:\n");
		if (from_dev)	DEBUG1(log_dst, "  Device                   : [%s]\n", from_dev);
		if (limit > 0)	DEBUG1(log_dst, "  Capture limit (packets)  : [%d]\n", limit);
				DEBUG1(log_dst, "  PCAP filter              : [%s]\n", pcap_filter);
				DEBUG1(log_dst, "  RADIUS secret            : [%s]\n", radius_secret);
		if (filter_vps){DEBUG1(log_dst, "  RADIUS filter            :\n");
			vp_printlist(log_dst, filter_vps);
		}
	}

	/*
	 *  Figure out whether were doing a reading from a file, doing a live
	 *  capture or reading from stdin.
	 */
	if (from_file) {
		in = pcap_open_offline(from_file, errbuf);
#ifdef HAVE_PCAP_FOPEN_OFFLINE
	} else if (from_stdin) {
		in = pcap_fopen_offline(stdin, errbuf);
#endif
	} else if (from_dev) {
		pcap_lookupnet(from_dev, &ip_addr, &ip_mask, errbuf);
		in = pcap_open_live(from_dev, 65536, 1, 1, errbuf);
	} else {
		fprintf(stderr, "radsniff: No capture devices available\n");
	}
	
	if (!in) {
		fprintf(stderr, "radsniff: Failed opening input (%s)\n", errbuf);
		exit(1);
	}

	if (to_file) {
		out = pcap_dump_open(in, to_file);
		if (!out) {
			fprintf(stderr, "radsniff: Failed opening output file (%s)\n", pcap_geterr(in));
			exit(1);
		}
#ifdef HAVE_PCAP_DUMP_FOPEN
	} else if (to_stdout) {
		out = pcap_dump_fopen(in, stdout);
		if (!out) {
			fprintf(stderr, "radsniff: Failed opening stdout (%s)\n", pcap_geterr(in));
			exit(1);
		}
#endif
	}

	/*
	 *  Apply the rules
	 */
	if (pcap_compile(in, &fp, pcap_filter, 0, ip_mask) < 0) {
		fprintf(stderr, "radsniff: Failed compiling PCAP filter (%s)\n", pcap_geterr(in));
		exit(1);
	}
	
	if (pcap_setfilter(in, &fp) < 0) {
		fprintf(stderr, "radsniff: Failed applying PCAP filter (%s)\n", pcap_geterr(in));
		exit(1);
	}

	/*
	 *  Enter the main capture loop...
	 */
	pcap_loop(in, limit, got_packet, NULL);
	
	/*
	 *  ...were done capturing.
	 */
	pcap_close(in);
	if (out) {
		pcap_dump_close(out);
	}
	
	if (filter_tree) {
		rbtree_free(filter_tree);
	}
	
	INFO(log_dst, "Done sniffing\n");
	
	return 0;
}
