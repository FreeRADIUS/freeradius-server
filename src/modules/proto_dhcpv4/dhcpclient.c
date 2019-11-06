/*
 * dhcpclient.c	DHCP test client.
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
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Miquel van Smoorenburg (miquels@cistron.nl)
 * @copyright 2010 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>
#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/util/pcap.h>

/*
 *	Logging macros
 */
 #undef DEBUG
#define DEBUG(fmt, ...)		if (fr_debug_lvl > 0) fprintf(stdout, fmt "\n", ## __VA_ARGS__)

#define ERROR(fmt, ...)		fr_perror("dhcpclient: " fmt, ## __VA_ARGS__)

#ifdef WITH_DHCP

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <assert.h>

#include <net/if.h>

static int retries = 3;
static fr_time_delta_t	timeout;

static int sockfd;
#ifdef HAVE_LIBPCAP
static fr_pcap_t	*pcap;
#endif

static char *iface = NULL;
static int iface_ind = -1;

#ifdef HAVE_LINUX_IF_PACKET_H
static struct sockaddr_ll ll;	/* Socket address structure */
#endif

static bool raw_mode = false;
static bool reply_expected = true;

static char const *dhcpclient_version = RADIUSD_VERSION_STRING_BUILD("dhcpclient");

/* structure to keep track of offered IP addresses */
typedef struct {
	uint32_t server_addr;
	uint32_t offered_addr;
} dc_offer_t;

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t dhcpclient_dict[];
fr_dict_autoload_t dhcpclient_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_dst_ip_address;
static fr_dict_attr_t const *attr_packet_dst_ipv6_address;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_packet_src_ip_address;
static fr_dict_attr_t const *attr_packet_src_ipv6_address;
static fr_dict_attr_t const *attr_packet_src_port;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_dhcp_message_type;
static fr_dict_attr_t const *attr_dhcp_dhcp_server_identifier;
static fr_dict_attr_t const *attr_dhcp_your_ip_address;

extern fr_dict_attr_autoload_t dhcpclient_dict_attr[];
fr_dict_attr_autoload_t dhcpclient_dict_attr[] = {
	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_ipv6_address, .name = "Packet-Dst-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ipv6_address, .name = "Packet-Src-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_message_type, .name = "DHCP-Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4},
	{ .out = &attr_dhcp_dhcp_server_identifier, .name = "DHCP-DHCP-Server-Identifier", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_your_ip_address, .name = "DHCP-Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ NULL }
};

static fr_table_num_sorted_t const request_types[] = {
	{ "auto",     		FR_CODE_UNDEFINED	},
	{ "decline",		FR_DHCP_DECLINE		},
	{ "discover",		FR_DHCP_DISCOVER	},
	{ "inform",		FR_DHCP_INFORM		},
	{ "lease_query",	FR_DHCP_LEASE_QUERY	},
	{ "release",		FR_DHCP_RELEASE		},
	{ "request",		FR_DHCP_REQUEST		}
};
static size_t request_types_len = NUM_ELEMENTS(request_types);

static void NEVER_RETURNS usage(void)
{
	DEBUG("Usage: dhcpclient [options] server[:port] [<command>]");
	DEBUG("Send a DHCP request with provided RADIUS attrs and output response.");

	DEBUG("  <command>              One of: discover, request, decline, release, inform; or: auto.");
	DEBUG("  -d <directory>         Set the directory where the dictionaries are stored (defaults to " RADDBDIR ").");
	DEBUG("  -D <dictdir>           Set main dictionary directory (defaults to " DICTDIR ").");
	DEBUG("  -f <file>              Read packets from file, not stdin.");
	DEBUG("  -i <interface>         Use this interface to send/receive at packet level on a raw socket.");
	DEBUG("  -t <timeout>           Wait 'timeout' seconds for a reply (may be a floating point number).");
	DEBUG("  -v                     Show program version information.");
	DEBUG("  -x                     Debugging mode.");

	exit(EXIT_SUCCESS);
}


/*
 *	Initialize the request.
 */
static RADIUS_PACKET *request_init(char const *filename)
{
	FILE *fp;
	fr_cursor_t cursor;
	VALUE_PAIR *vp;
	bool filedone = false;
	RADIUS_PACKET *request;

	/*
	 *	Determine where to read the VP's from.
	 */
	if (filename) {
		fp = fopen(filename, "r");
		if (!fp) {
			ERROR("Error opening %s: %s", filename, fr_syserror(errno));
			return NULL;
		}
	} else {
		fp = stdin;
	}

	request = fr_radius_alloc(NULL, false);

	/*
	 *	Read the VP's.
	 */
	if (fr_pair_list_afrom_file(request, dict_dhcpv4, &request->vps, fp, &filedone) < 0) {
		fr_perror("dhcpclient");
		fr_radius_packet_free(&request);
		if (fp && (fp != stdin)) fclose(fp);
		return NULL;
	}

	/*
	 *	Fix / set various options
	 */
	for (vp = fr_cursor_init(&cursor, &request->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {

		/*
		 *	Xlat expansions are not supported. Convert xlat to value box (if possible).
		 */
		if (vp->type == VT_XLAT) {
			fr_type_t type = vp->da->type;
			if (fr_value_box_from_str(vp, &vp->data, &type, NULL, vp->xlat, -1, '\0', false) < 0) {
				fr_perror("dhcpclient");
				fr_radius_packet_free(&request);
				if (fp && (fp != stdin)) fclose(fp);
				return NULL;
			}
			vp->type = VT_DATA;
		}

		/*
		 *	Allow to set packet type using DHCP-Message-Type
		 */
	     	if (vp->da == attr_dhcp_message_type) {
	     		request->code = vp->vp_uint8;

		/*
		 *	Allow it to set the packet type in
		 *	the attributes read from the file.
		 *	(this takes precedence over the command argument.)
		 */
	     	} else if (vp->da == attr_packet_type) {
	     		request->code = vp->vp_uint32;

		} else if (vp->da == attr_packet_dst_port) {
			request->dst_port = vp->vp_uint16;

		} else if ((vp->da == attr_packet_dst_ip_address) ||
			   (vp->da == attr_packet_dst_ipv6_address)) {
			memcpy(&request->dst_ipaddr, &vp->vp_ip, sizeof(request->src_ipaddr));

		} else if (vp->da == attr_packet_src_port) {
			request->src_port = vp->vp_uint16;

		} else if ((vp->da == attr_packet_src_ip_address) ||
			   (vp->da == attr_packet_src_ipv6_address)) {
			memcpy(&request->src_ipaddr, &vp->vp_ip, sizeof(request->src_ipaddr));
		} /* switch over the attribute */

	} /* loop over the VP's we read in */

	if (fp && (fp != stdin)) fclose(fp);

	/*
	 *	And we're done.
	 */
	return request;
}

static void print_hex(RADIUS_PACKET *packet)
{
	int i, j;
	uint8_t const *p, *a;

	if (!packet->data) return;

	if (packet->data_len < 244) {
		printf("Huh?\n");
		return;
	}

	printf("----------------------------------------------------------------------\n");
	fflush(stdout);

	p = packet->data;
	for (i = 0; i < 14; i++) {
		printf("%s = 0x", (*dhcp_header_attrs[i])->name);
		for (j = 0; j < dhcp_header_sizes[i]; j++) {
			printf("%02x", p[j]);

		}
		printf("\n");
		p += dhcp_header_sizes[i];
	}

	/*
	 *	Magic number
	 */
	printf("%02x %02x %02x %02x\n",
	       p[0], p[1], p[2], p[3]);
	p += 4;

	while (p < (packet->data + packet->data_len)) {

		if (*p == 0) break;
		if (*p == 255) break; /* end of options signifier */
		if ((p + 2) > (packet->data + packet->data_len)) break;

		printf("%02x  %02x  ", p[0], p[1]);
		a = p + 2;

		for (i = 0; i < p[1]; i++) {
			if ((i > 0) && ((i & 0x0f) == 0x00))
				printf("\t\t");
			printf("%02x ", a[i]);
			if ((i & 0x0f) == 0x0f) printf("\n");
		}

		if ((p[1] & 0x0f) != 0x00) printf("\n");

		p += p[1] + 2;
	}
	printf("\n----------------------------------------------------------------------\n");
	fflush(stdout);
}

/*
 *	Loop waiting for DHCP replies until timer expires.
 *	Note that there may be more than one reply: multiple DHCP servers can respond to a broadcast discover.
 *	A real client would pick one of the proposed replies.
 *	We'll just return the first eligible reply, and display the others.
 */
#if defined(HAVE_LINUX_IF_PACKET_H) || defined (HAVE_LIBPCAP)
static RADIUS_PACKET *fr_dhcpv4_recv_raw_loop(int lsockfd,
#ifdef HAVE_LINUX_IF_PACKET_H
					    struct sockaddr_ll *p_ll,
#endif
					    RADIUS_PACKET *request_p)
{
	fr_time_delta_t	our_timeout;
	RADIUS_PACKET	*reply_p = NULL;
	RADIUS_PACKET	*cur_reply_p = NULL;
	int		nb_reply = 0;
	int		nb_offer = 0;
	dc_offer_t	*offer_list = NULL;
	fd_set		read_fd;
	int		retval;

	our_timeout = timeout;

	/* Loop waiting for DHCP replies until timer expires */
	while (our_timeout) {
		if ((!reply_p) || (cur_reply_p)) { // only debug at start and each time we get a valid DHCP reply on raw socket
			DEBUG("Waiting for %s DHCP replies for: %d.%06d",
			      (nb_reply > 0) ? " additional ":" ",
			      (int)(our_timeout / NSEC),
			      (int)(our_timeout % NSEC));
		}

		cur_reply_p = NULL;
		FD_ZERO(&read_fd);
		FD_SET(lsockfd, &read_fd);
		retval = select(lsockfd + 1, &read_fd, NULL, NULL, &fr_time_delta_to_timeval(our_timeout));
		if (retval < 0) {
			fr_strerror_printf("Select on DHCP socket failed: %s", fr_syserror(errno));
			return NULL;
		}

		if (retval > 0 && FD_ISSET(lsockfd, &read_fd)) {
			/* There is something to read on our socket */

#ifdef HAVE_LINUX_IF_PACKET_H
			cur_reply_p = fr_dhcv4_raw_packet_recv(lsockfd, p_ll, request_p);
#else
#  ifdef HAVE_LIBPCAP
			cur_reply_p = fr_dhcpv4_pcap_recv(pcap);
#  else
#    error Need <if/packet.h> or <pcap.h>
#  endif
#endif
		} else {
			our_timeout = 0;
		}

		if (cur_reply_p) {
			nb_reply ++;

			if (fr_debug_lvl) print_hex(cur_reply_p);

			if (fr_dhcpv4_packet_decode(cur_reply_p) < 0) {
				ERROR("Failed decoding reply");
				return NULL;
			}

			if (!reply_p) reply_p = cur_reply_p;

			if (cur_reply_p->code == FR_DHCP_OFFER) {
				VALUE_PAIR *vp1 = fr_pair_find_by_da(cur_reply_p->vps,
								     attr_dhcp_dhcp_server_identifier,
								     TAG_ANY);
				VALUE_PAIR *vp2 = fr_pair_find_by_da(cur_reply_p->vps,
								     attr_dhcp_your_ip_address,
								     TAG_ANY);

				if (vp1 && vp2) {
					nb_offer++;
					offer_list = talloc_realloc(request_p, offer_list, dc_offer_t, nb_offer);
					offer_list[nb_offer - 1].server_addr = vp1->vp_ipv4addr;
					offer_list[nb_offer - 1].offered_addr = vp2->vp_ipv4addr;
				}
			}
		}
	}

	if (0 == nb_reply) {
		DEBUG("No valid DHCP reply received");
		return NULL;
	}

	/* display offer(s) received */
	if (nb_offer > 0 ) {
		DEBUG("Received %d DHCP Offer(s):", nb_offer);
		int i;
		for (i = 0; i < nb_reply; i++) {
			char server_addr_buf[INET6_ADDRSTRLEN];
			char offered_addr_buf[INET6_ADDRSTRLEN];

			DEBUG("IP address: %s offered by DHCP server: %s",
			      inet_ntop(AF_INET, &offer_list[i].offered_addr,
			      		offered_addr_buf, sizeof(offered_addr_buf)),
			      inet_ntop(AF_INET, &offer_list[i].server_addr,
			      		server_addr_buf, sizeof(server_addr_buf))
			);
		}
	}

	return reply_p;
}
#endif	/* <if/packet.h> or <pcap.h> */

static int send_with_socket(RADIUS_PACKET **reply, RADIUS_PACKET *request)
{
	int on = 1;

#ifdef HAVE_LINUX_IF_PACKET_H
	if (raw_mode) {
		sockfd = fr_dhcpv4_raw_socket_open(&ll, iface_ind);
		if (sockfd < 0) {
			ERROR("Error opening socket");
			return -1;
		}
	} else
#endif
	{
		sockfd = fr_socket_server_udp(&request->src_ipaddr, &request->src_port, NULL, false);
		if (sockfd < 0) {
			ERROR("Error opening socket: %s", fr_strerror());
			return -1;
		}

		if (fr_socket_bind(sockfd, &request->src_ipaddr, &request->src_port, NULL) < 0) {
			ERROR("Error binding socket: %s", fr_strerror());
			return -1;
		}
	}


	/*
	 *	Set option 'receive timeout' on socket.
	 *	Note: in case of a timeout, the error will be "Resource temporarily unavailable".
	 */
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
		       &fr_time_delta_to_timeval(timeout), sizeof(struct timeval)) == -1) {
		ERROR("Failed setting socket timeout: %s", fr_syserror(errno));
		return -1;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
		ERROR("Can't set broadcast option: %s", fr_syserror(errno));
		return -1;
	}
	request->sockfd = sockfd;

#ifdef HAVE_LINUX_IF_PACKET_H
	if (raw_mode) {
		if (fr_dhcpv4_raw_packet_send(sockfd, &ll, request) < 0) {
			ERROR("Failed sending (fr_dhcpv4_raw_packet_send): %s", fr_syserror(errno));
			return -1;
		}
		if (!reply_expected) return 0;

		*reply = fr_dhcpv4_recv_raw_loop(sockfd, &ll, request);
		if (!*reply) {
			ERROR("Error receiving reply (fr_dhcpv4_recv_raw_loop)");
			return -1;
		}
	} else
#endif
	{
		if (fr_dhcpv4_udp_packet_send(request) < 0) {
			ERROR("Failed sending: %s", fr_syserror(errno));
			return -1;
		}
		if (!reply_expected) return 0;

		*reply = fr_dhcpv4_udp_packet_recv(sockfd);
		if (!*reply) {
			if (errno == EAGAIN) {
				fr_strerror(); /* clear error */
				ERROR("Timed out waiting for reply");
			} else {
				ERROR("Error receiving reply");
			}
			return -1;
		}
	}

	return 0;
}

#ifdef HAVE_LIBPCAP
static int send_with_pcap(RADIUS_PACKET **reply, RADIUS_PACKET *request)
{
	char ip[16];
	char pcap_filter[255];

	pcap = fr_pcap_init(NULL, iface, PCAP_INTERFACE_IN_OUT);
	if (!pcap) {
		ERROR("Failed creating pcap");
		return -1;
	}

	if (fr_pcap_open(pcap) < 0) {
		ERROR("Failed opening interface");
		talloc_free(pcap);
		return -1;
	}

	fr_inet_ntoh(&request->src_ipaddr, ip, sizeof(ip));
	sprintf(pcap_filter, "udp and dst port %d", request->src_port);

	if (fr_pcap_apply_filter(pcap, pcap_filter) < 0) {
		ERROR("Failing setting filter");
		talloc_free(pcap);
		return -1;
	}

	if (fr_dhcpv4_pcap_send(pcap, eth_bcast, request) < 0) {
		ERROR("Failed sending packet");
		talloc_free(pcap);
		return -1;
	}

	if (!reply_expected) return 0;

	*reply = fr_dhcpv4_recv_raw_loop(pcap->fd,
#ifdef HAVE_LINUX_IF_PACKET_H
				      &ll,
#endif
				      request);

	if (!*reply) {
		ERROR("Error receiving reply");
		talloc_free(pcap);
		return -1;
	}

	talloc_free(pcap);
	return 0;
}
#endif	/* HAVE_LIBPCAP */

static void dhcp_packet_debug(RADIUS_PACKET *packet, bool received)
{
	fr_cursor_t	cursor;
	char		buffer[256];

	char		src_ipaddr[INET6_ADDRSTRLEN];
	char		dst_ipaddr[INET6_ADDRSTRLEN];
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
	char		if_name[IFNAMSIZ];
#endif
	VALUE_PAIR	*vp;

	if (!packet) return;

	/*
	 *	Client-specific debugging re-prints the input
	 *	packet into the client log.
	 *
	 *	This really belongs in a utility library
	 */
	printf("%s %s Id %08x from %s%s%s:%i to %s%s%s:%i "
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
	       "%s%s%s"
#endif
	       "length %zu\n",
	       received ? "Received" : "Sending",
	       dhcp_message_types[packet->code],
	       packet->id,
	       packet->src_ipaddr.af == AF_INET6 ? "[" : "",
	       inet_ntop(packet->src_ipaddr.af,
			 &packet->src_ipaddr.addr,
			 src_ipaddr, sizeof(src_ipaddr)),
	       packet->src_ipaddr.af == AF_INET6 ? "]" : "",
	       packet->src_port,
	       packet->dst_ipaddr.af == AF_INET6 ? "[" : "",
	       inet_ntop(packet->dst_ipaddr.af,
			 &packet->dst_ipaddr.addr,
			 dst_ipaddr, sizeof(dst_ipaddr)),
	       packet->dst_ipaddr.af == AF_INET6 ? "]" : "",
	       packet->dst_port,
#if defined(WITH_UDPFROMTO) && defined(WITH_IFINDEX_NAME_RESOLUTION)
	       packet->if_index ? "via " : "",
	       packet->if_index ? fr_ifname_from_ifindex(if_name, packet->if_index) : "",
	       packet->if_index ? " " : "",
#endif
	       packet->data_len);

	for (vp = fr_cursor_init(&cursor, &packet->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VP_VERIFY(vp);

		fr_pair_snprint(buffer, sizeof(buffer), vp);
		printf("\t%s\n", buffer);
	}
}

int main(int argc, char **argv)
{

	static uint16_t		server_port = 0;
	static int		packet_code = 0;
	static fr_ipaddr_t	server_ipaddr;
	static fr_ipaddr_t	client_ipaddr;

	int			c;
	char const		*raddb_dir = RADDBDIR;
	char const		*dict_dir = DICTDIR;
	char const		*filename = NULL;

	RADIUS_PACKET		*request = NULL;
	RADIUS_PACKET		*reply = NULL;

	TALLOC_CTX		*autofree = talloc_autofree_context();

	int			ret;

	fr_debug_lvl = 1;

	while ((c = getopt(argc, argv, "d:D:f:hr:t:vxi:")) != -1) switch(c) {
		case 'D':
			dict_dir = optarg;
			break;

		case 'd':
			raddb_dir = optarg;
			break;

		case 'f':
			filename = optarg;
			break;

		case 'i':
			iface = optarg;
			break;

		case 'r':
			if (!isdigit((int) *optarg)) usage();
			retries = atoi(optarg);
			if ((retries == 0) || (retries > 1000)) usage();
			break;

		case 't':
			if (fr_time_delta_from_str(&timeout, optarg, FR_TIME_RES_SEC) < 0) usage();
			break;

		case 'v':
			DEBUG("%s", dhcpclient_version);
			exit(0);

		case 'x':
			fr_debug_lvl++;
			break;

		case 'h':
		default:
			usage();
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if (argc < 2) usage();

	if (!fr_dict_global_ctx_init(autofree, dict_dir)) {
		fr_perror("dhcpclient");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_autoload(dhcpclient_dict) < 0) {
		fr_perror("dhcpclient");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_attr_autoload(dhcpclient_dict_attr) < 0) {
		fr_perror("dhcpclient");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_read(fr_dict_unconst(dict_freeradius), raddb_dir, FR_DICTIONARY_FILE) == -1) {
		fr_perror("dhcpclient");
		exit(EXIT_FAILURE);
	}
	fr_strerror();	/* Clear the error buffer */

	/*
	 *	Initialise the DHCPv4 library
	 */
	if (fr_dhcpv4_global_init() < 0) {
		fr_perror("dhcpclient");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Resolve hostname.
	 */
	server_ipaddr.af = AF_INET;
	if (strcmp(argv[1], "-") != 0) {
		if (fr_inet_pton_port(&server_ipaddr, &server_port, argv[1],
				      strlen(argv[1]), AF_UNSPEC, true, true) < 0) {
			fr_perror("dhcpclient");
			fr_exit_now(1);
		}
		client_ipaddr.af = server_ipaddr.af;
	}

	/*
	 *	See what kind of request we want to send.
	 */
	if (argc >= 3) {
		if (!isdigit((int) argv[2][0])) {
			packet_code = fr_table_value_by_str(request_types, argv[2], -2);
			if (packet_code == -2) {
				ERROR("Unknown packet type: %s", argv[2]);
				usage();
			}
		} else {
			packet_code = atoi(argv[2]);
		}
	}
	if (!server_port) server_port = 67;

	/*
	 *	set "raw mode" if an interface is specified and if destination
	 *	IP address is the broadcast address.
	 */
	if (iface) {
		iface_ind = if_nametoindex(iface);
		if (iface_ind <= 0) {
			ERROR("Unknown interface: %s", iface);
			exit(EXIT_FAILURE);
		}

		if (server_ipaddr.addr.v4.s_addr == 0xFFFFFFFF) {
			ERROR("Using interface: %s (index: %d) in raw packet mode", iface, iface_ind);
			raw_mode = true;
		}
	}

	request = request_init(filename);
	if (!request || !request->vps) {
		ERROR("Nothing to send");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Set defaults if they weren't specified via pairs
	 */
	if (request->src_port == 0) request->src_port = server_port + 1;
	if (request->dst_port == 0) request->dst_port = server_port;
	if (request->src_ipaddr.af == AF_UNSPEC) request->src_ipaddr = client_ipaddr;
	if (request->dst_ipaddr.af == AF_UNSPEC) request->dst_ipaddr = server_ipaddr;
	if (!request->code) request->code = packet_code;

	/*
	 *	Sanity check.
	 */
	if (!request->code) {
		ERROR("Command was %s, and request did not contain DHCP-Message-Type nor Packet-Type",
		      (argc >= 3) ? "'auto'" : "unspecified");
		exit(EXIT_FAILURE);
	}

	/*
	 *	These kind of packets do not get a reply, so don't wait for one.
	 */
	if ((request->code == FR_DHCP_RELEASE) || (request->code == FR_DHCP_DECLINE)) {
		reply_expected = false;
	}

	/*
	 *	Encode the packet
	 */
	if (fr_dhcpv4_packet_encode(request) < 0) {
		ERROR("Failed encoding packet");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Decode to produce VALUE_PAIRs from the default field
	 */
	if (fr_debug_lvl) {
		fr_dhcpv4_packet_decode(request);
		dhcp_packet_debug(request, false);
	}

#ifdef HAVE_LIBPCAP
	if (raw_mode) {
		ret = send_with_pcap(&reply, request);
	} else
#endif
	{
		ret = send_with_socket(&reply, request);
	}

	if (reply) {
		if (fr_dhcpv4_packet_decode(reply) < 0) {
			ERROR("Failed decoding packet");
			ret = -1;
		}
		dhcp_packet_debug(reply, true);
	}

	fr_dhcpv4_global_free();
	fr_dict_autofree(dhcpclient_dict);

	return ret < 0 ? 1 : 0;
}

#endif	/* WITH_DHCP */
