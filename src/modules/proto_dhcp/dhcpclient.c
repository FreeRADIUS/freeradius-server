/*
 * dhcpclient.c	General radius packet debug tool.
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2010  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/dhcp.h>

#ifdef WITH_DHCP

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#include <assert.h>

#include <net/if.h>

static int success = 0;
static int retries = 3;
static float timeout = 5.0;
static struct timeval tv_timeout;

static int sockfd;

static char *iface = NULL;
static int iface_ind = -1;

static RADIUS_PACKET *reply = NULL;

static bool reply_expected = true;

#define DHCP_CHADDR_LEN	(16)
#define DHCP_SNAME_LEN	(64)
#define DHCP_FILE_LEN	(128)

static char const *dhcpclient_version = "dhcpclient version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
", built on " __DATE__ " at " __TIME__;

/* structure to keep track of offered IP addresses */
typedef struct dc_offer {
	uint32_t server_addr;
	uint32_t offered_addr;
} dc_offer_t;

static const FR_NAME_NUMBER request_types[] = {
	{ "discover", PW_DHCP_DISCOVER },
	{ "request",  PW_DHCP_REQUEST },
	{ "decline",  PW_DHCP_DECLINE },
	{ "release",  PW_DHCP_RELEASE },
	{ "inform",   PW_DHCP_INFORM },
	{ "lease_query",  PW_DHCP_LEASE_QUERY },
	{ "auto",     PW_CODE_UNDEFINED },
	{ NULL, 0}
};

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "Usage: dhcpclient [options] server[:port] [<command>]\n");
	fprintf(stderr, "Send a DHCP request with provided RADIUS attrs and output response.\n");

	fprintf(stderr, "  <command>              One of: discover, request, decline, release, inform; or: auto.\n");
	fprintf(stderr, "  -d <directory>         Set the directory where the dictionaries are stored (defaults to " RADDBDIR ").\n");
	fprintf(stderr, "  -D <dictdir>           Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -f <file>              Read packets from file, not stdin.\n");
	fprintf(stderr, "  -i <interface>         Use this interface to send/receive at packet level on a raw socket.\n");
	fprintf(stderr, "  -t <timeout>           Wait 'timeout' seconds for a reply (may be a floating point number).\n");
	fprintf(stderr, "  -v                     Show program version information.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	exit(1);
}


/*
 *	Initialize the request.
 */
static RADIUS_PACKET *request_init(char const *filename)
{
	FILE *fp;
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	bool filedone = false;
	RADIUS_PACKET *request;

	/*
	 *	Determine where to read the VP's from.
	 */
	if (filename) {
		fp = fopen(filename, "r");
		if (!fp) {
			fprintf(stderr, "dhcpclient: Error opening %s: %s\n", filename, fr_syserror(errno));
			return NULL;
		}
	} else {
		fp = stdin;
	}

	request = rad_alloc(NULL, false);
	/*
	 *	Read the VP's.
	 */
	if (fr_pair_list_afrom_file(NULL, &request->vps, fp, &filedone) < 0) {
		fr_perror("dhcpclient");
		rad_free(&request);
		if (fp != stdin) fclose(fp);
		return NULL;
	}

	/*
	 *	Fix / set various options
	 */
	for (vp = fr_cursor_init(&cursor, &request->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	Allow to set packet type using DHCP-Message-Type
		 */
		if (vp->da->vendor == DHCP_MAGIC_VENDOR && vp->da->attr == PW_DHCP_MESSAGE_TYPE) {
			request->code = vp->vp_integer + PW_DHCP_OFFSET;
		} else if (!vp->da->vendor) switch (vp->da->attr) {
		/*
		 *	Allow it to set the packet type in
		 *	the attributes read from the file.
		 *	(this takes precedence over the command argument.)
		 */
		case PW_PACKET_TYPE:
			request->code = vp->vp_integer;
			break;

		case PW_PACKET_DST_PORT:
			request->dst_port = (vp->vp_integer & 0xffff);
			break;

		case PW_PACKET_DST_IP_ADDRESS:
			request->dst_ipaddr.af = AF_INET;
			request->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
			request->dst_ipaddr.prefix = 32;
			break;

		case PW_PACKET_DST_IPV6_ADDRESS:
			request->dst_ipaddr.af = AF_INET6;
			request->dst_ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
			request->dst_ipaddr.prefix = 128;
			break;

		case PW_PACKET_SRC_PORT:
			request->src_port = (vp->vp_integer & 0xffff);
			break;

		case PW_PACKET_SRC_IP_ADDRESS:
			request->src_ipaddr.af = AF_INET;
			request->src_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
			request->src_ipaddr.prefix = 32;
			break;

		case PW_PACKET_SRC_IPV6_ADDRESS:
			request->src_ipaddr.af = AF_INET6;
			request->src_ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
			request->src_ipaddr.prefix = 128;
			break;

		default:
			break;
		} /* switch over the attribute */

	} /* loop over the VP's we read in */

	if (fp != stdin) fclose(fp);

	/*
	 *	And we're done.
	 */
	return request;
}

static char const *dhcp_header_names[] = {
	"DHCP-Opcode",
	"DHCP-Hardware-Type",
	"DHCP-Hardware-Address-Length",
	"DHCP-Hop-Count",
	"DHCP-Transaction-Id",
	"DHCP-Number-of-Seconds",
	"DHCP-Flags",
	"DHCP-Client-IP-Address",
	"DHCP-Your-IP-Address",
	"DHCP-Server-IP-Address",
	"DHCP-Gateway-IP-Address",
	"DHCP-Client-Hardware-Address",
	"DHCP-Server-Host-Name",
	"DHCP-Boot-Filename",

	NULL
};

static int dhcp_header_sizes[] = {
	1, 1, 1, 1,
	4, 2, 2, 4,
	4, 4, 4,
	DHCP_CHADDR_LEN,
	DHCP_SNAME_LEN,
	DHCP_FILE_LEN
};


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
		printf("%s = 0x", dhcp_header_names[i]);
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

static void send_with_socket(RADIUS_PACKET *request)
{
	sockfd = fr_socket(&request->src_ipaddr, request->src_port);
	if (sockfd < 0) {
		fprintf(stderr, "dhcpclient: socket: %s\n", fr_strerror());
		fr_exit_now(1);
	}

	/*
	 *	Set option 'receive timeout' on socket.
	 *	Note: in case of a timeout, the error will be "Resource temporarily unavailable".
	 */
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv_timeout,sizeof(struct timeval)) == -1) {
		fprintf(stderr, "dhcpclient: failed setting socket timeout: %s\n",
			fr_syserror(errno));
		fr_exit_now(1);
	}

	request->sockfd = sockfd;

	if (fr_dhcp_send(request) < 0) {
		fprintf(stderr, "dhcpclient: failed sending: %s\n",
			fr_syserror(errno));
		fr_exit_now(1);
	}

	if (!reply_expected) return;

	reply = fr_dhcp_recv(sockfd);
	if (!reply) {
		fprintf(stderr, "dhcpclient: Error receiving reply: %s\n", fr_strerror());
		fr_exit_now(1);
	}
}

int main(int argc, char **argv)
{

	static uint16_t		server_port = 0;
	static int		packet_code = 0;
	static fr_ipaddr_t	server_ipaddr;
	static fr_ipaddr_t	client_ipaddr;

	int			c;
	char const		*radius_dir = RADDBDIR;
	char const		*dict_dir = DICTDIR;
	char const		*filename = NULL;
	DICT_ATTR const		*da;
	RADIUS_PACKET		*request = NULL;

	fr_debug_lvl = 0;

	while ((c = getopt(argc, argv, "d:D:f:hr:t:vxi:")) != EOF) switch(c) {
		case 'D':
			dict_dir = optarg;
			break;

		case 'd':
			radius_dir = optarg;
			break;
		case 'f':
			filename = optarg;
			break;
		case 'i':
			iface = optarg;
			break;
		case 'r':
			if (!isdigit((int) *optarg))
				usage();
			retries = atoi(optarg);
			if ((retries == 0) || (retries > 1000)) usage();
			break;
		case 't':
			if (!isdigit((int) *optarg))
				usage();
			timeout = atof(optarg);
			break;
		case 'v':
			printf("%s\n", dhcpclient_version);
			exit(0);

		case 'x':
			fr_debug_lvl++;
			fr_log_fp = stdout;
			break;
		case 'h':
		default:
			usage();
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if (argc < 2) usage();

	/*	convert timeout to a struct timeval */
#define USEC 1000000
	tv_timeout.tv_sec = timeout;
	tv_timeout.tv_usec = ((timeout - (float) tv_timeout.tv_sec) * USEC);

	if (dict_init(dict_dir, RADIUS_DICTIONARY) < 0) {
		fr_perror("radclient");
		return 1;
	}

	if (dict_read(radius_dir, RADIUS_DICTIONARY) == -1) {
		fr_perror("radclient");
		return 1;
	}
	fr_strerror();	/* Clear the error buffer */

	/*
	 *	Ensure that dictionary.dhcp is loaded.
	 */
	da = dict_attrbyname("DHCP-Message-Type");
	if (!da) {
		if (dict_read(dict_dir, "dictionary.dhcp") < 0) {
			fprintf(stderr, "Failed reading dictionary.dhcp: %s\n", fr_strerror());
			return -1;
		}
	}

	/*
	 *	Resolve hostname.
	 */
	server_ipaddr.af = AF_INET;
	if (strcmp(argv[1], "-") != 0) {
		if (ip_hton(&server_ipaddr, AF_INET, argv[1], false) < 0) {
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
			packet_code = fr_str2int(request_types, argv[2], -2);
			if (packet_code == -2) {
				fprintf(stderr, "Unknown packet type: %s\n", argv[2]);
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
			fprintf(stderr, "dhcpclient: unknown interface: %s\n", iface);
			fr_exit_now(1);
		}

		if (server_ipaddr.ipaddr.ip4addr.s_addr == 0xFFFFFFFF) {
			fprintf(stderr, "dhcpclient: Sending broadcast packets is not supported\n");
			exit(1);
		}
	}

	request = request_init(filename);
	if (!request || !request->vps) {
		fprintf(stderr, "dhcpclient: Nothing to send.\n");
		fr_exit_now(1);
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
		fprintf(stderr, "dhcpclient: Command was %s, and request did not contain DHCP-Message-Type nor Packet-Type.\n",
			(argc >= 3) ? "'auto'" : "unspecified");
		exit(1);
	}

	if ((request->code == PW_DHCP_RELEASE) || (request->code == PW_DHCP_DECLINE)) {
		/*	These kind of packets do not get a reply, so don't wait for one. */
		reply_expected = false;
	}
	/*
	 *	Encode the packet
	 */
	if (fr_dhcp_encode(request) < 0) {
		fprintf(stderr, "dhcpclient: failed encoding: %s\n", fr_strerror());
		fr_exit_now(1);
	}
	if (fr_debug_lvl) print_hex(request);

	send_with_socket(request);

	if (reply && fr_debug_lvl) print_hex(reply);

	if (reply && fr_dhcp_decode(reply) < 0) {
		fprintf(stderr, "dhcpclient: failed decoding\n");
		return 1;
	}

	dict_free();

	if (success) return 0;

	return 1;
}

#endif	/* WITH_DHCP */
