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
#undef DEBUG
#define DEBUG if (fr_debug_flag) printf

static int minimal = 0;
static int do_sort = 0;
struct timeval start_pcap = {0, 0};
static rbtree_t *filter_tree = NULL;
typedef int (*rbcmp)(const void *, const void *);

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

static void got_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *data)
{
	/* Just a counter of how many packets we've had */
	static int count = 1;
	/* Define pointers for packet's attributes */
	const struct ethernet_header *ethernet;  /* The ethernet header */
	const struct ip_header *ip;              /* The IP header */
	const struct udp_header *udp;            /* The UDP header */
	const uint8_t *payload;                     /* Packet payload */
	/* And define the size of the structures we're using */
	int size_ethernet = sizeof(struct ethernet_header);
	int size_ip = sizeof(struct ip_header);
	int size_udp = sizeof(struct udp_header);
	/* For FreeRADIUS */
	RADIUS_PACKET *packet;
	struct timeval elapsed;

	args = args;		/* -Wunused */

	/* Define our packet's attributes */
	ethernet = (const struct ethernet_header*)(data);
	ip = (const struct ip_header*)(data + size_ethernet);
	udp = (const struct udp_header*)(data + size_ethernet + size_ip);
	payload = (const uint8_t *)(data + size_ethernet + size_ip + size_udp);

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

	packet->data = payload;
	packet->data_len = header->len - size_ethernet - size_ip - size_udp;

	if (!rad_packet_ok(packet, 0)) {
		fr_perror("Packet");
		
		fprintf(stderr, "\tFrom:    %s:%d\n", inet_ntoa(ip->ip_src), ntohs(udp->udp_sport));
		fprintf(stderr, "\tTo:      %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(udp->udp_dport));
		fprintf(stderr, "\tType:    %s\n", fr_packet_codes[packet->code]);

		free(packet);
		return;
	}

	/*
	 *	Decode the data without bothering to check the signatures.
	 */
	if (rad_decode(packet, NULL, radius_secret) != 0) {
		free(packet);
		fr_perror("decode");
		return;
	}

	if (filter_vps && filter_packet(packet)) {
		free(packet);
		DEBUG("Packet number %d doesn't match\n", count++);
		return;
	}
	printf("%s Id %d\t", fr_packet_codes[packet->code], packet->id);

	/* Print the RADIUS packet */
	printf("%s:%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->udp_sport));
	printf("%s:%d", inet_ntoa(ip->ip_dst), ntohs(udp->udp_dport));
	if (fr_debug_flag) printf("\t(%d packets)", count++);

	if (!start_pcap.tv_sec) {
		start_pcap = header->ts;
	}

	tv_sub(&header->ts, &start_pcap, &elapsed);

	printf("\t+%u.%03u", (unsigned int) elapsed.tv_sec,
	       (unsigned int) elapsed.tv_usec / 1000);
	if (!minimal) printf("\n");
	if (!minimal && packet->vps) {
		if (do_sort) sort(packet);

		vp_printlist(stdout, packet->vps);
		pairfree(&packet->vps);
	}
	printf("\n");
	fflush(stdout);

	/*
	 *	If we're doing filtering, Access-Requests are cached
	 *	in the filter tree.
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
	fprintf(output, "usage: radsniff [options]\n");
	fprintf(output, "options:\n");
	fprintf(output, "\t-c count\tNumber of packets to capture.\n");
	fprintf(output, "\t-d directory\tDirectory where the dictionaries are found\n");
	fprintf(output, "\t-f filter\tPCAP filter. (default is udp port 1812 or 1813 or 1814)\n");
	fprintf(output, "\t-h\t\tPrint this help message.\n");
	fprintf(output, "\t-i interface\tInterface to capture.\n");
	fprintf(output, "\t-I filename\tRead packets from filename.\n");
	fprintf(output, "\t-m\t\tPrint packet headers only, not contents.\n");
	fprintf(output, "\t-p port\tList for packets on port.\n");
	fprintf(output, "\t-r filter\tRADIUS attribute filter.\n");
	fprintf(output, "\t-s secret\tRADIUS secret.\n");
	fprintf(output, "\t-S\t\tSort attributes in the packet.  Used to compare server results.\n");
	fprintf(output, "\t-x\t\tPrint out debugging information.\n");
	exit(status);
}

int main(int argc, char *argv[])
{
	char *dev;                      /* sniffing device */
	char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */
	pcap_t *descr;                  /* sniff handler */
	struct bpf_program fp;          /* hold compiled program */
	bpf_u_int32 maskp;              /* subnet mask */
	bpf_u_int32 netp;               /* ip */
	char buffer[1024];
	char *pcap_filter = NULL;
	char *radius_filter = NULL;
	char *filename = NULL;
	int packet_count = -1;		/* how many packets to sniff */
	int opt;
	FR_TOKEN parsecode;
	const char *radius_dir = RADIUS_DIR;
	int port = 1812;

	/* Default device */
	dev = pcap_lookupdev(errbuf);

	/* Get options */
	while ((opt = getopt(argc, argv, "c:d:f:hi:I:mp:r:s:SxX")) != EOF) {
		switch (opt)
		{
		case 'c':
			packet_count = atoi(optarg);
			if (packet_count <= 0) {
				fprintf(stderr, "radsniff: Invalid number of packets \"%s\"\n", optarg);
				exit(1);
			}
			break;
		case 'd':
			radius_dir = optarg;
			break;
		case 'f':
			pcap_filter = optarg;
			break;
		case 'h':
			usage(0);
			break;
		case 'i':
			dev = optarg;
			break;
		case 'I':
			filename = optarg;
			break;
		case 'm':
			minimal = 1;
			break;
		case 'p':
			port = atoi(optarg);
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
		case 'x':
		case 'X':	/* for backwards compatibility */
		  	fr_debug_flag++;
			break;
		default:
			usage(1);
		}
	}

	if (!pcap_filter) {
		pcap_filter = buffer;
		snprintf(buffer, sizeof(buffer), "udp port %d or %d or %d",
			 port, port + 1, port + 2);
	}

        if (dict_init(radius_dir, RADIUS_DICTIONARY) < 0) {
                fr_perror("radsniff");
                return 1;
        }

	if (radius_filter) {
		parsecode = userparse(radius_filter, &filter_vps);
		if (parsecode == T_OP_INVALID) {
			fprintf(stderr, "radsniff: Invalid RADIUS filter \"%s\": %s\n", radius_filter, fr_strerror());
			exit(1);
		}
		if (!filter_vps) {
			fprintf(stderr, "radsniff: Empty RADIUS filter \"%s\"\n", radius_filter);
			exit(1);
		}

		filter_tree = rbtree_create((rbcmp) fr_packet_cmp,
					    free, 0);
		if (!filter_tree) {
			fprintf(stderr, "radsniff: Failed creating filter tree\n");
			exit(1);
		}
	}

	/* Set our device */
	pcap_lookupnet(dev, &netp, &maskp, errbuf);

	/* Print device to the user */
	if (fr_debug_flag) {
		if (dev) printf("Device: [%s]\n", dev);
		if (packet_count > 0) {
			printf("Num of packets: [%d]\n",
			       packet_count);
		}
		printf("PCAP filter: [%s]\n", pcap_filter);
		if (filter_vps) {
			printf("RADIUS filter:\n");
			vp_printlist(stdout, filter_vps);
		}
		printf("RADIUS secret: [%s]\n", radius_secret);
	}

	/* Open the device so we can spy */
	if (filename) {
		descr = pcap_open_offline(filename, errbuf);
	} else if (!dev) {
		fprintf(stderr, "radsniff: No filename or device was specified.\n");
		exit(1);

	} else {
		descr = pcap_open_live(dev, SNAPLEN, 1, 0, errbuf);
	}
	if (descr == NULL)
	{
		fprintf(stderr, "radsniff: pcap_open_live failed (%s)\n", errbuf);
		exit(1);
	}

	/* Apply the rules */
	if( pcap_compile(descr, &fp, pcap_filter, 0, netp) == -1)
	{
		fprintf(stderr, "radsniff: pcap_compile failed\n");
		exit(1);
	}
	if (pcap_setfilter(descr, &fp) == -1)
	{
		printf("radsniff: pcap_setfilter failed\n");
		exit(1);
	}

	/* Now we can set our callback function */
	pcap_loop(descr, packet_count, got_packet, NULL);
	pcap_close(descr);

	if (filter_tree) rbtree_free(filter_tree);

	DEBUG("Done sniffing\n");
	return 0;
}
