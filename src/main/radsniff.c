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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 *
 *  Copyright 2006  The FreeRADIUS server project
 *  Copyright 2006  Nicolas Baradakis <nicolas.baradakis@cegetel.net>
 */

#include <freeradius-devel/autoconf.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define _LIBRADIUS 1
#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/radsniff.h>

static const char *radius_secret = "testing123";
static VALUE_PAIR *filter_vps = NULL;

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

/*
 *	Stolen from rad_recv() in ../lib/radius.c
 */
static RADIUS_PACKET *init_packet(const uint8_t *data, size_t data_len)
{
	RADIUS_PACKET		*packet;

	/*
	 *	Allocate the new request data structure
	 */
	if ((packet = malloc(sizeof(*packet))) == NULL) {
		librad_log("out of memory");
		return NULL;
	}
	memset(packet, 0, sizeof(*packet));

	packet->data = data;
	packet->data_len = data_len;

	if (!rad_packet_ok(packet)) {
		rad_free(&packet);
		return NULL;
	}

	/*
	 *	Explicitely set the VP list to empty.
	 */
	packet->vps = NULL;

	return packet;
}

/*
 *	Stolen from rad_decode() in ../lib/radius.c
 */
static int decode_packet(RADIUS_PACKET *packet, const char *secret)
{
	uint32_t		lvalue;
	uint32_t		vendorcode;
	VALUE_PAIR		**tail;
	VALUE_PAIR		*pair;
	uint8_t			*ptr;
	int			packet_length;
	int			attribute;
	int			attrlen;
	int			vendorlen;
	radius_packet_t		*hdr;
	int			vsa_tlen, vsa_llen;
	DICT_VENDOR		*dv = NULL;

/* 	if (rad_verify(packet, original, secret) < 0) return -1; */

	/*
	 *	Extract attribute-value pairs
	 */
	hdr = (radius_packet_t *)packet->data;
	ptr = hdr->data;
	packet_length = packet->data_len - AUTH_HDR_LEN;

	/*
	 *	There may be VP's already in the packet.  Don't
	 *	destroy them.
	 */
	for (tail = &packet->vps; *tail != NULL; tail = &((*tail)->next)) {
		/* nothing */
	}

	vendorcode = 0;
	vendorlen  = 0;
	vsa_tlen = vsa_llen = 1;

	/*
	 *	We have to read at least two bytes.
	 *
	 *	rad_recv() above ensures that this is OK.
	 */
	while (packet_length > 0) {
		attribute = -1;
		attrlen = -1;

		/*
		 *	Normal attribute, handle it like normal.
		 */
		if (vendorcode == 0) {
			/*
			 *	No room to read attr/length,
			 *	or bad attribute, or attribute is
			 *	too short, or attribute is too long,
			 *	stop processing the packet.
			 */
			if ((packet_length < 2) ||
			    (ptr[0] == 0) ||  (ptr[1] < 2) ||
			    (ptr[1] > packet_length)) break;

			attribute = *ptr++;
			attrlen   = *ptr++;

			attrlen -= 2;
			packet_length  -= 2;

			if (attribute != PW_VENDOR_SPECIFIC) goto create_pair;

			/*
			 *	No vendor code, or ONLY vendor code.
			 */
			if (attrlen <= 4) goto create_pair;

			vendorlen = 0;
		}

		/*
		 *	Handle Vendor-Specific
		 */
		if (vendorlen == 0) {
			uint8_t *subptr;
			int sublen;
			int myvendor;

			/*
			 *	attrlen was checked above.
			 */
			memcpy(&lvalue, ptr, 4);
			myvendor = ntohl(lvalue);

			/*
			 *	Zero isn't allowed.
			 */
			if (myvendor == 0) goto create_pair;

			/*
			 *	This is an implementation issue.
			 *	We currently pack vendor into the upper
			 *	16 bits of a 32-bit attribute number,
			 *	so we can't handle vendor numbers larger
			 *	than 16 bits.
			 */
			if (myvendor > 65535) goto create_pair;

			vsa_tlen = vsa_llen = 1;
			dv = dict_vendorbyvalue(myvendor);
			if (dv) {
				vsa_tlen = dv->type;
				vsa_llen = dv->length;
			}

			/*
			 *	Sweep through the list of VSA's,
			 *	seeing if they exactly fill the
			 *	outer Vendor-Specific attribute.
			 *
			 *	If not, create a raw Vendor-Specific.
			 */
			subptr = ptr + 4;
			sublen = attrlen - 4;

			/*
			 *	See if we can parse it.
			 */
			do {
				int myattr = 0;

				/*
				 *	Don't have a type, it's bad.
				 */
				if (sublen < vsa_tlen) goto create_pair;

				/*
				 *	Ensure that the attribute number
				 *	is OK.
				 */
				switch (vsa_tlen) {
				case 1:
					myattr = subptr[0];
					break;

				case 2:
					myattr = (subptr[0] << 8) | subptr[1];
					break;

				case 4:
					if ((subptr[0] != 0) ||
					    (subptr[1] != 0)) goto create_pair;

					myattr = (subptr[2] << 8) | subptr[3];
					break;

					/*
					 *	Our dictionary is broken.
					 */
				default:
					goto create_pair;
				}

				/*
				 *	Not enough room for one more
				 *	attribute.  Die!
				 */
				if (sublen < vsa_tlen + vsa_llen) goto create_pair;
				switch (vsa_llen) {
				case 0:
					attribute = (myvendor << 16) | myattr;
					ptr += 4 + vsa_tlen;
					attrlen -= (4 + vsa_tlen);
					packet_length -= 4 + vsa_tlen;
					goto create_pair;

				case 1:
					if (subptr[vsa_tlen] < (vsa_tlen + vsa_llen))
						goto create_pair;

					if (subptr[vsa_tlen] > sublen)
						goto create_pair;
					sublen -= subptr[vsa_tlen];
					subptr += subptr[vsa_tlen];
					break;

				case 2:
					if (subptr[vsa_tlen] != 0) goto create_pair;
					if (subptr[vsa_tlen + 1] < (vsa_tlen + vsa_llen))
						goto create_pair;
					if (subptr[vsa_tlen + 1] > sublen)
						goto create_pair;
					sublen -= subptr[vsa_tlen + 1];
					subptr += subptr[vsa_tlen + 1];
					break;

					/*
					 *	Our dictionaries are
					 *	broken.
					 */
				default:
					goto create_pair;
				}
			} while (sublen > 0);

			vendorcode = myvendor;
			vendorlen = attrlen - 4;
			packet_length -= 4;

			ptr += 4;
		}

		/*
		 *	attrlen is the length of this attribute.
		 *	total_len is the length of the encompassing
		 *	attribute.
		 */
		switch (vsa_tlen) {
		case 1:
			attribute = ptr[0];
			break;

		case 2:
			attribute = (ptr[0] << 8) | ptr[1];
			break;

		default:	/* can't hit this. */
			return -1;
		}
		attribute |= (vendorcode << 16);
		ptr += vsa_tlen;

		switch (vsa_llen) {
		case 1:
			attrlen = ptr[0] - (vsa_tlen + vsa_llen);
			break;

		case 2:
			attrlen = ptr[1] - (vsa_tlen + vsa_llen);
			break;

		default:	/* can't hit this. */
			return -1;
		}
		ptr += vsa_llen;
		vendorlen -= vsa_tlen + vsa_llen + attrlen;
		if (vendorlen == 0) vendorcode = 0;
		packet_length -= (vsa_tlen + vsa_llen);

		/*
		 *	Create the attribute, setting the default type
		 *	to 'octects'.  If the type in the dictionary
		 *	is different, then the dictionary type will
		 *	over-ride this one.
		 */
	create_pair:
/* 		pair = rad_attr2vp(packet, original, secret, */
/* 				 attribute, attrlen, ptr); */
		pair = rad_attr2vp(packet, NULL, secret,
				 attribute, attrlen, ptr);
		if (!pair) {
			pairfree(&packet->vps);
			librad_log("out of memory");
			return -1;
		}

		debug_pair(pair);
		*tail = pair;
		tail = &pair->next;

		ptr += attrlen;
		packet_length -= attrlen;
	}

	/*
	 *	Merge information from the outside world into our
	 *	random pool.
	 */
	lrad_rand_seed(packet->data, AUTH_HDR_LEN);

	return 0;
}

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

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* Just a counter of how many packets we've had */
	static int count = 1;
	/* Define pointers for packet's attributes */
	const struct ethernet_header *ethernet;  /* The ethernet header */
	const struct ip_header *ip;              /* The IP header */
	const struct udp_header *udp;            /* The UDP header */
	const char *payload;                     /* Packet payload */
	/* And define the size of the structures we're using */
	int size_ethernet = sizeof(struct ethernet_header);
	int size_ip = sizeof(struct ip_header);
	int size_udp = sizeof(struct udp_header);
	/* For FreeRADIUS */
	RADIUS_PACKET *request;

	/* Define our packet's attributes */
	ethernet = (const struct ethernet_header*)(packet);
	ip = (const struct ip_header*)(packet + size_ethernet);
	udp = (const struct udp_header*)(packet + size_ethernet + size_ip);
	payload = (const u_char *)(packet + size_ethernet + size_ip + size_udp);

	/* Read the RADIUS packet structure */
	request = init_packet(payload, header->len - size_ethernet - size_ip - size_udp);
	if (request == NULL) {
		librad_perror("check");
		return;
	}
	request->src_ipaddr.ipaddr.ip4addr.s_addr = ip->ip_src.s_addr;
	request->src_port = ntohs(udp->udp_sport);
	request->dst_ipaddr.ipaddr.ip4addr.s_addr = ip->ip_dst.s_addr;
	request->dst_port = ntohs(udp->udp_dport);
	if (decode_packet(request, radius_secret) != 0) {
		librad_perror("decode");
		return;
	}
	if (filter_vps && filter_packet(request)) {
		/* printf("Packet number %d doesn't match\n", count++); */
		return;
	}

	/* Print the RADIUS packet */
	printf("Packet number %d has just been sniffed\n", count++);
	printf("\tFrom:    %s:%d\n", inet_ntoa(ip->ip_src), ntohs(udp->udp_sport));
	printf("\tTo:      %s:%d\n", inet_ntoa(ip->ip_dst), ntohs(udp->udp_dport));
	printf("\tType:    %s\n", packet_codes[request->code]);
	if (request->vps != NULL) {
		vp_printlist(stdout, request->vps);
		pairfree(&request->vps);
	}
	free(request);
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
	fprintf(output, "\t-r filter\tRADIUS filter.\n");
	fprintf(output, "\t-s secret\tRADIUS secret.\n");
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
	const char *pcap_filter = "udp port 1812 or 1813 or 1814";
	char *radius_filter = NULL;
	int packet_count = -1;		/* how many packets to sniff */
	int opt;
	LRAD_TOKEN parsecode;
	char *radius_dir = RADIUS_DIR;

	/* Default device */
	dev = pcap_lookupdev(errbuf);

	/* Get options */
	while ((opt = getopt(argc, argv, "c:d:f:hi:r:s:")) != EOF) {
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
		case 'r':
			radius_filter = optarg;
			parsecode = userparse(radius_filter, &filter_vps);
			if (parsecode == T_OP_INVALID || filter_vps == NULL) {
				fprintf(stderr, "radsniff: Invalid RADIUS filter \"%s\"\n", optarg);
				exit(1);
			}
			break;
		case 's':
			radius_secret = optarg;
			break;
		default:
			usage(1);
		}
	}

        if (dict_init(radius_dir, RADIUS_DICTIONARY) < 0) {
                librad_perror("radsniff");
                return 1;
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
	return 0;
}
