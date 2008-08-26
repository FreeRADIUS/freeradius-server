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
static int debug_flag = 0;
#undef DEBUG
#define DEBUG if (debug_flag) printf

static const char *packet_codes[] = {
  "",
  "Access-Request",
  "Access-Accept",
  "Access-Reject",
  "Accounting-Request",
  "Accounting-Response",
  "Accounting-Status",
  "Password-Request",
  "Password-Accept",
  "Password-Reject",
  "Accounting-Message",
  "Access-Challenge",
  "Status-Server",
  "Status-Client",
  "14",
  "15",
  "16",
  "17",
  "18",
  "19",
  "20",
  "Resource-Free-Request",
  "Resource-Free-Response",
  "Resource-Query-Request",
  "Resource-Query-Response",
  "Alternate-Resource-Reclaim-Request",
  "NAS-Reboot-Request",
  "NAS-Reboot-Response",
  "28",
  "Next-Passcode",
  "New-Pin",
  "Terminate-Session",
  "Password-Expired",
  "Event-Request",
  "Event-Response",
  "35",
  "36",
  "37",
  "38",
  "39",
  "Disconnect-Request",
  "Disconnect-ACK",
  "Disconnect-NAK",
  "CoF-Request",
  "CoF-ACK",
  "CoF-NAK",
  "46",
  "47",
  "48",
  "49",
  "IP-Address-Allocate",
  "IP-Address-Release"
};

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
		return 0;
	}

	return 1;
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

	/* Print the RADIUS packet */
	printf("Packet number %d has just been sniffed\n", count++);
	printf("\tFrom:    %s:%d\n", inet_ntoa(ip->ip_src), ntohs(udp->udp_sport));
	printf("\tTo:      %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(udp->udp_dport));
	printf("\tType:    %s\n", packet_codes[packet->code]);
	if (packet->vps != NULL) {
		vp_printlist(stdout, packet->vps);
		pairfree(&packet->vps);
	}
	fflush(stdout);
	free(packet);
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
	fprintf(output, "\t-p port\tList for packets on port.\n");
	fprintf(output, "\t-r filter\tRADIUS attribute filter.\n");
	fprintf(output, "\t-s secret\tRADIUS secret.\n");
	fprintf(output, "\t-X\t\tPrint out debugging information.\n");
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
	int packet_count = -1;		/* how many packets to sniff */
	int opt;
	FR_TOKEN parsecode;
	const char *radius_dir = RADIUS_DIR;
	int port = 1812;

	/* Default device */
	dev = pcap_lookupdev(errbuf);

	/* Get options */
	while ((opt = getopt(argc, argv, "c:d:f:hi:p:r:s:X")) != EOF) {
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
		case 'p':
			port = atoi(optarg);
			break;
		case 'r':
			radius_filter = optarg;
			break;
		case 's':
			radius_secret = optarg;
			break;
		case 'X':
		  	debug_flag = 1;
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
	}

	/* Set our device */
	pcap_lookupnet(dev, &netp, &maskp, errbuf);

	/* Print device to the user */
	printf("Device: [%s]\n", dev);
	if (packet_count > 0) {
		printf("Num of packets: [%d]\n", packet_count);
	}
	printf("PCAP filter: [%s]\n", pcap_filter);
	if (filter_vps != NULL) {
		printf("RADIUS filter:\n");
		vp_printlist(stdout, filter_vps);
	}
	printf("RADIUS secret: [%s]\n", radius_secret);

	/* Open the device so we can spy */
	descr = pcap_open_live(dev, SNAPLEN, 1, 0, errbuf);
	if (descr == NULL)
	{
		printf("radsniff: pcap_open_live failed (%s)\n", errbuf);
		exit(1);
	}

	/* Apply the rules */
	if( pcap_compile(descr, &fp, pcap_filter, 0, netp) == -1)
	{
		printf("radsniff: pcap_compile failed\n");
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

	printf("Done sniffing\n");
	fflush(stdout);
	return 0;
}
