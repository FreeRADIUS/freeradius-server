/*
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
 */

/**
 * $Id$
 *
 * @file src/bin/radclient.c
 * @brief General radius client and debug tool.
 *
 * @copyright 2000,2006,2014 The FreeRADIUS server project
 * @copyright 2000 Miquel van Smoorenburg (miquels@cistron.nl)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/radius/list.h>
#include <freeradius-devel/radius/radius.h>
#include <ctype.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <assert.h>

typedef struct request_s request_t;	/* to shut up warnings about mschap.h */

#include "smbdes.h"
#include "mschap.h"

#include "radclient.h"

#define pair_update_request(_attr, _da) fr_pair_update_by_da(request->packet, _attr, &request->request_pairs, _da)

static int retries = 3;
static fr_time_delta_t timeout = ((fr_time_delta_t) 5) * NSEC;
static fr_time_delta_t sleep_time = -1;
static char *secret = NULL;
static bool do_output = true;

static rc_stats_t stats;

static uint16_t server_port = 0;
static int packet_code = FR_CODE_UNDEFINED;
static fr_ipaddr_t server_ipaddr;
static int resend_count = 1;
static bool done = true;
static bool print_filename = false;

static fr_ipaddr_t client_ipaddr;
static uint16_t client_port = 0;

static int sockfd;
static int last_used_id = -1;

static int ipproto = IPPROTO_UDP;

static rbtree_t *filename_tree = NULL;
static fr_packet_list_t *packet_list = NULL;

static rc_request_t *request_head = NULL;
static rc_request_t *rc_request_tail = NULL;

static char const *radclient_version = RADIUSD_VERSION_STRING_BUILD("radclient");

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t radclient_dict[];
fr_dict_autoload_t radclient_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_cleartext_password;

static fr_dict_attr_t const *attr_ms_chap_challenge;
static fr_dict_attr_t const *attr_ms_chap_password;
static fr_dict_attr_t const *attr_ms_chap_response;

static fr_dict_attr_t const *attr_packet_dst_ip_address;
static fr_dict_attr_t const *attr_packet_dst_ipv6_address;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_packet_src_ip_address;
static fr_dict_attr_t const *attr_packet_src_ipv6_address;
static fr_dict_attr_t const *attr_packet_src_port;

static fr_dict_attr_t const *attr_radclient_test_name;
static fr_dict_attr_t const *attr_request_authenticator;

static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_chap_challenge;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t radclient_dict_attr[];
fr_dict_attr_autoload_t radclient_dict_attr[] = {
	{ .out = &attr_cleartext_password, .name = "Password.Cleartext", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_challenge, .name = "Vendor-Specific.Microsoft.CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap_password, .name = "MS-CHAP-Password", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_response, .name = "MS-CHAP-Response", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_ipv6_address, .name = "Packet-Dst-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ipv6_address, .name = "Packet-Src-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_radclient_test_name, .name = "Radclient-Test-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_request_authenticator, .name = "Request-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_chap_password, .name = "CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ NULL }
};

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "Usage: radclient [options] server[:port] <command> [<secret>]\n");

	fprintf(stderr, "  <command>              One of auth, acct, status, coa, disconnect or auto.\n");
	fprintf(stderr, "  -4                     Use IPv4 address of server\n");
	fprintf(stderr, "  -6                     Use IPv6 address of server.\n");
	fprintf(stderr, "  -C <client_port>       Assigning port number to client socket. Values may be 1..65535\n");
	fprintf(stderr, "  -c <count>             Send each packet 'count' times.\n");
	fprintf(stderr, "  -d <raddb>             Set user dictionary directory (defaults to " RADDBDIR ").\n");
	fprintf(stderr, "  -D <dictdir>           Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -f <file>[:<file>]     Read packets from file, not stdin.\n");
	fprintf(stderr, "                         If a second file is provided, it will be used to verify responses\n");
	fprintf(stderr, "  -F                     Print the file name, packet number and reply code.\n");
	fprintf(stderr, "  -h                     Print usage help information.\n");
	fprintf(stderr, "  -i <id>                Set request id to 'id'.  Values may be 0..255\n");
	fprintf(stderr, "  -n <num>               Send N requests/s\n");
	fprintf(stderr, "  -p <num>               Send 'num' packets from a file in parallel.\n");
	fprintf(stderr, "  -P <proto>             Use proto (tcp or udp) for transport.\n");
	fprintf(stderr, "  -r <retries>           If timeout, retry sending the packet 'retries' times.\n");
	fprintf(stderr, "  -s                     Print out summary information of auth results.\n");
	fprintf(stderr, "  -S <file>              read secret from file, not command line.\n");
	fprintf(stderr, "  -t <timeout>           Wait 'timeout' seconds before retrying (may be a floating point number).\n");
	fprintf(stderr, "  -v                     Show program version information.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	fr_exit_now(EXIT_SUCCESS);
}

/*
 *	Free a radclient struct, which may (or may not)
 *	already be in the list.
 */
static int _rc_request_free(rc_request_t *request)
{
	rc_request_t *prev, *next;

	prev = request->prev;
	next = request->next;

	if (prev) {
		assert(request_head != request);
		prev->next = next;
	} else if (request_head) {
		assert(request_head == request);
		request_head = next;
	}

	if (next) {
		assert(rc_request_tail != request);
		next->prev = prev;
	} else if (rc_request_tail) {
		assert(rc_request_tail == request);
		rc_request_tail = prev;
	}

	return 0;
}

static int mschapv1_encode(fr_radius_packet_t *packet, fr_pair_t **request,
			   char const *password)
{
	unsigned int		i;
	uint8_t			*p;
	fr_pair_t		*challenge, *reply;
	uint8_t			nthash[16];

	fr_pair_delete_by_da(&packet->vps, attr_ms_chap_challenge);
	fr_pair_delete_by_da(&packet->vps, attr_ms_chap_response);

	MEM(challenge = fr_pair_afrom_da(packet, attr_ms_chap_challenge));

	fr_pair_add(request, challenge);
	challenge->vp_length = 8;
	challenge->vp_octets = p = talloc_array(challenge, uint8_t, challenge->vp_length);
	for (i = 0; i < challenge->vp_length; i++) {
		p[i] = fr_rand();
	}

	MEM(reply = fr_pair_afrom_da(packet, attr_ms_chap_response));
	fr_pair_add(request, reply);
	reply->vp_length = 50;
	reply->vp_octets = p = talloc_array(reply, uint8_t, reply->vp_length);
	memset(p, 0, reply->vp_length);

	p[1] = 0x01; /* NT hash */

	if (mschap_nt_password_hash(nthash, password) < 0) return 0;

	smbdes_mschap(nthash, challenge->vp_octets, p + 26);
	return 1;
}


static int getport(char const *name)
{
	struct servent *svp;

	svp = getservbyname(name, "udp");
	if (!svp) return 0;

	return ntohs(svp->s_port);
}

/*
 *	Set a port from the request type if we don't already have one
 */
static void radclient_get_port(FR_CODE type, uint16_t *port)
{
	switch (type) {
	default:
	case FR_CODE_ACCESS_REQUEST:
	case FR_CODE_ACCESS_CHALLENGE:
	case FR_CODE_STATUS_SERVER:
		if (*port == 0) *port = getport("radius");
		if (*port == 0) *port = FR_AUTH_UDP_PORT;
		return;

	case FR_CODE_ACCOUNTING_REQUEST:
		if (*port == 0) *port = getport("radacct");
		if (*port == 0) *port = FR_ACCT_UDP_PORT;
		return;

	case FR_CODE_DISCONNECT_REQUEST:
		if (*port == 0) *port = FR_POD_UDP_PORT;
		return;

	case FR_CODE_COA_REQUEST:
		if (*port == 0) *port = FR_COA_UDP_PORT;
		return;

	case FR_CODE_UNDEFINED:
		if (*port == 0) *port = 0;
		return;
	}
}

/*
 *	Resolve a port to a request type
 */
static FR_CODE radclient_get_code(uint16_t port)
{
	/*
	 *	getport returns 0 if the service doesn't exist
	 *	so we need to return early, to avoid incorrect
	 *	codes.
	 */
	if (port == 0) return FR_CODE_UNDEFINED;

	if ((port == getport("radius")) || (port == FR_AUTH_UDP_PORT) || (port == FR_AUTH_UDP_PORT_ALT)) {
		return FR_CODE_ACCESS_REQUEST;
	}
	if ((port == getport("radacct")) || (port == FR_ACCT_UDP_PORT) || (port == FR_ACCT_UDP_PORT_ALT)) {
		return FR_CODE_ACCOUNTING_REQUEST;
	}
	if (port == FR_COA_UDP_PORT) return FR_CODE_COA_REQUEST;

	return FR_CODE_UNDEFINED;
}


static bool already_hex(fr_pair_t *vp)
{
	size_t i;

	if (!vp || (vp->vp_type != FR_TYPE_OCTETS)) return true;

	/*
	 *	If it's 17 octets, it *might* be already encoded.
	 *	Or, it might just be a 17-character password (maybe UTF-8)
	 *	Check it for non-printable characters.  The odds of ALL
	 *	of the characters being 32..255 is (1-7/8)^17, or (1/8)^17,
	 *	or 1/(2^51), which is pretty much zero.
	 */
	for (i = 0; i < vp->vp_length; i++) {
		if (vp->vp_octets[i] < 32) {
			return true;
		}
	}

	return false;
}

/*
 *	Initialize a radclient data structure and add it to
 *	the global linked list.
 */
static int radclient_init(TALLOC_CTX *ctx, rc_file_pair_t *files)
{
	FILE		*packets, *filters = NULL;

	fr_cursor_t	cursor;
	fr_pair_t	*vp;
	rc_request_t	*request;
	bool		packets_done = false;
	uint64_t	num = 0;

	assert(files->packets != NULL);

	/*
	 *	Determine where to read the VP's from.
	 */
	if (strcmp(files->packets, "-") != 0) {
		packets = fopen(files->packets, "r");
		if (!packets) {
			ERROR("Error opening %s: %s", files->packets, fr_syserror(errno));
			return -1;
		}

		/*
		 *	Read in the pairs representing the expected response.
		 */
		if (files->filters) {
			filters = fopen(files->filters, "r");
			if (!filters) {
				ERROR("Error opening %s: %s", files->filters, fr_syserror(errno));
				fclose(packets);
				return -1;
			}
		}
	} else {
		packets = stdin;
	}

	/*
	 *	Loop until the file is done.
	 */
	do {
		/*
		 *	Allocate it.
		 */
		request = talloc_zero(ctx, rc_request_t);
		if (!request) {
			ERROR("Out of memory");
			goto error;
		}

		request->packet = fr_radius_alloc(request, true);
		if (!request->packet) {
			ERROR("Out of memory");
			goto error;
		}

		request->packet->socket.inet.src_ipaddr = client_ipaddr;
		request->packet->socket.inet.src_port = client_port;
		request->packet->socket.inet.dst_ipaddr = server_ipaddr;
		request->packet->socket.inet.dst_port = server_port;
		request->packet->socket.proto = ipproto;

		request->files = files;
		request->packet->id = last_used_id;
		request->num = num++;

		fr_pair_list_init(&request->filter);

		/*
		 *	Read the request VP's.
		 */
		if (fr_pair_list_afrom_file(request->packet, dict_radius,
					    &request->request_pairs, packets, &packets_done) < 0) {
			char const *input;

			if ((files->packets[0] == '-') && (files->packets[1] == '\0')) {
				input = "stdin";
			} else {
				input = files->packets;
			}

			REDEBUG("Error parsing \"%s\"", input);
			goto error;
		}

		/*
		 *	Skip empty entries
		 */
		if (!request->request_pairs) {
			WARN("Skipping \"%s\": No Attributes", files->packets);
			talloc_free(request);
			continue;
		}

		/*
		 *	Read in filter VP's.
		 */
		if (filters) {
			bool filters_done;

			if (fr_pair_list_afrom_file(request, dict_radius,
						    &request->filter, filters, &filters_done) < 0) {
				REDEBUG("Error parsing \"%s\"", files->filters);
				goto error;
			}

			if (filters_done && !packets_done) {
				REDEBUG("Differing number of packets/filters in %s:%s "
				        "(too many requests))", files->packets, files->filters);
				goto error;
			}

			if (!filters_done && packets_done) {
				REDEBUG("Differing number of packets/filters in %s:%s "
				        "(too many filters))", files->packets, files->filters);
				goto error;
			}

			/*
			 *	xlat expansions aren't supported here
			 */
			for (vp = fr_cursor_init(&cursor, &request->filter);
			     vp;
			     vp = fr_cursor_next(&cursor)) {
			     again:
				/*
				 *	Xlat expansions are not supported. Convert xlat to value box (if possible).
				 */
				if (vp->type == VT_XLAT) {
					fr_type_t type = vp->da->type;
					if (fr_value_box_from_str(vp, &vp->data, &type, NULL, vp->xlat, -1, '\0', false) < 0) {
						fr_perror("radclient");
						goto error;
					}
					vp->type = VT_DATA;
				}

				if (vp->da == attr_packet_type) {
					vp = fr_cursor_remove(&cursor);	/* so we don't break the filter */
					request->filter_code = vp->vp_uint32;
					talloc_free(vp);
					vp = fr_cursor_current(&cursor);
					if (!vp) break;
					goto again;
				}
			}

			/*
			 *	This allows efficient list comparisons later
			 */
			fr_pair_list_sort(&request->filter, fr_pair_cmp_by_da);
		}

		/*
		 *	Process special attributes
		 */
		for (vp = fr_cursor_init(&cursor, &request->request_pairs);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			/*
			 *	Xlat expansions are not supported. Convert xlat to value box (if possible).
			 */
			if (vp->type == VT_XLAT) {
				fr_type_t type = vp->da->type;
				if (fr_value_box_from_str(vp, &vp->data, &type, NULL, vp->xlat, -1, '\0', false) < 0) {
					fr_perror("radclient");
					goto error;
				}
				vp->type = VT_DATA;
			}

			/*
			 *	Allow it to set the packet type in
			 *	the attributes read from the file.
			 */
			if (vp->da == attr_packet_type) {
				request->packet->code = vp->vp_uint32;
			} else if (vp->da == attr_packet_dst_port) {
				request->packet->socket.inet.dst_port = vp->vp_uint16;
			} else if ((vp->da == attr_packet_dst_ip_address) ||
				   (vp->da == attr_packet_dst_ipv6_address)) {
				memcpy(&request->packet->socket.inet.dst_ipaddr, &vp->vp_ip, sizeof(request->packet->socket.inet.dst_ipaddr));
			} else if (vp->da == attr_packet_src_port) {
				if (vp->vp_uint16 < 1024) {
					ERROR("Invalid value '%u' for Packet-Src-Port", vp->vp_uint16);
					goto error;
				}
				request->packet->socket.inet.src_port = vp->vp_uint16;
			} else if ((vp->da == attr_packet_src_ip_address) ||
				   (vp->da == attr_packet_src_ipv6_address)) {
				memcpy(&request->packet->socket.inet.src_ipaddr, &vp->vp_ip, sizeof(request->packet->socket.inet.src_ipaddr));
			} else if (vp->da == attr_request_authenticator) {
				if (vp->vp_length > sizeof(request->packet->vector)) {
					memcpy(request->packet->vector, vp->vp_octets, sizeof(request->packet->vector));
				} else {
					memset(request->packet->vector, 0, sizeof(request->packet->vector));
					memcpy(request->packet->vector, vp->vp_octets, vp->vp_length);
				}
			} else if (vp->da == attr_cleartext_password) {
				request->password = vp;
			/*
			 *	Keep a copy of the the password attribute.
			 */
			} else if (vp->da == attr_chap_password) {
				/*
				 *	If it's already hex, do nothing.
				 */
				if ((vp->vp_length == 17) && (already_hex(vp))) continue;

				/*
				 *	CHAP-Password is octets, so it may not be zero terminated.
				 */
				MEM(pair_update_request(&request->password, attr_cleartext_password) >= 0);
				fr_pair_value_bstrndup(request->password, vp->vp_strvalue, vp->vp_length, true);
			} else if ((vp->da == attr_user_password) ||
				   (vp->da == attr_ms_chap_password)) {
				MEM(pair_update_request(&request->password, attr_cleartext_password) >= 0);
				fr_pair_value_bstrndup(request->password, vp->vp_strvalue, vp->vp_length, true);
			} else if (vp->da == attr_radclient_test_name) {
				request->name = vp->vp_strvalue;
			}
		} /* loop over the VP's we read in */

		/*
		 *	Use the default set on the command line
		 */
		if (request->packet->code == FR_CODE_UNDEFINED) request->packet->code = packet_code;

		/*
		 *	Default to the filename
		 */
		if (!request->name) request->name = request->files->packets;

		/*
		 *	Automatically set the response code from the request code
		 *	(if one wasn't already set).
		 */
		if (request->filter_code == FR_CODE_UNDEFINED) {
			switch (request->packet->code) {
			case FR_CODE_ACCESS_REQUEST:
				request->filter_code = FR_CODE_ACCESS_ACCEPT;
				break;

			case FR_CODE_ACCOUNTING_REQUEST:
				request->filter_code = FR_CODE_ACCOUNTING_RESPONSE;
				break;

			case FR_CODE_COA_REQUEST:
				request->filter_code = FR_CODE_COA_ACK;
				break;

			case FR_CODE_DISCONNECT_REQUEST:
				request->filter_code = FR_CODE_DISCONNECT_ACK;
				break;

			case FR_CODE_STATUS_SERVER:
				switch (radclient_get_code(request->packet->socket.inet.dst_port)) {
				case FR_CODE_ACCESS_REQUEST:
					request->filter_code = FR_CODE_ACCESS_ACCEPT;
					break;

				case FR_CODE_ACCOUNTING_REQUEST:
					request->filter_code = FR_CODE_ACCOUNTING_RESPONSE;
					break;

				default:
					request->filter_code = FR_CODE_UNDEFINED;
					break;
				}
				break;

			case FR_CODE_UNDEFINED:
				REDEBUG("Packet-Type must be defined,"
					"or a well known RADIUS port");
				goto error;

			default:
				REDEBUG("Can't determine expected &reply.Packet-Type for Packet-Type %i",
					request->packet->code);
				goto error;
			}
		/*
		 *	Automatically set the request code from the response code
		 *	(if one wasn't already set).
		 */
		} else if (request->packet->code == FR_CODE_UNDEFINED) {
			switch (request->filter_code) {
			case FR_CODE_ACCESS_ACCEPT:
			case FR_CODE_ACCESS_REJECT:
				request->packet->code = FR_CODE_ACCESS_REQUEST;
				break;

			case FR_CODE_ACCOUNTING_RESPONSE:
				request->packet->code = FR_CODE_ACCOUNTING_REQUEST;
				break;

			case FR_CODE_DISCONNECT_ACK:
			case FR_CODE_DISCONNECT_NAK:
				request->packet->code = FR_CODE_DISCONNECT_REQUEST;
				break;

			case FR_CODE_COA_ACK:
			case FR_CODE_COA_NAK:
				request->packet->code = FR_CODE_COA_REQUEST;
				break;

			default:
				REDEBUG("Can't determine expected Packet-Type for &reply.Packet-Type %i",
					request->filter_code);
				goto error;
			}
		}

		/*
		 *	Automatically set the dst port (if one wasn't already set).
		 */
		if (request->packet->socket.inet.dst_port == 0) {
			radclient_get_port(request->packet->code, &request->packet->socket.inet.dst_port);
			if (request->packet->socket.inet.dst_port == 0) {
				REDEBUG("Can't determine destination port");
				goto error;
			}
		}

		/*
		 *	Add it to the tail of the list.
		 */
		if (!request_head) {
			assert(rc_request_tail == NULL);
			request_head = request;
			request->prev = NULL;
		} else {
			assert(rc_request_tail->next == NULL);
			rc_request_tail->next = request;
			request->prev = rc_request_tail;
		}
		rc_request_tail = request;
		request->next = NULL;

		/*
		 *	Set the destructor so it removes itself from the
		 *	request list when freed. We don't set this until
		 *	the packet is actually in the list, else we trigger
		 *	the asserts in the free callback.
		 */
		talloc_set_destructor(request, _rc_request_free);
	} while (!packets_done); /* loop until the file is done. */

	if (packets != stdin) fclose(packets);
	if (filters) fclose(filters);

	/*
	 *	And we're done.
	 */
	return 0;

error:
	talloc_free(request);

	if (packets != stdin) fclose(packets);
	if (filters) fclose(filters);

	return -1;
}


/*
 *	Sanity check each argument.
 */
static int radclient_sane(rc_request_t *request)
{
	if (request->packet->socket.inet.dst_port == 0) {
		request->packet->socket.inet.dst_port = server_port;
	}
	if (request->packet->socket.inet.dst_ipaddr.af == AF_UNSPEC) {
		if (server_ipaddr.af == AF_UNSPEC) {
			ERROR("No server was given, and request %" PRIu64 " in file %s did not contain "
			      "Packet-Dst-IP-Address", request->num, request->files->packets);
			return -1;
		}
		request->packet->socket.inet.dst_ipaddr = server_ipaddr;
	}
	if (request->packet->code == 0) {
		if (packet_code == -1) {
			ERROR("Request was \"auto\", and request %" PRIu64 " in file %s did not contain Packet-Type",
			      request->num, request->files->packets);
			return -1;
		}
		request->packet->code = packet_code;
	}
	request->packet->socket.fd = -1;

	return 0;
}


/*
 *	For request handling.
 */
static int filename_cmp(void const *one, void const *two)
{
	rc_file_pair_t const *a = one, *b = two;
	int cmp;

	cmp = strcmp(a->packets, b->packets);
	if (cmp != 0) return cmp;

	return strcmp(a->filters, b->filters);
}

static int filename_walk(void *data, UNUSED void *uctx)
{
	rc_file_pair_t *files = data;

	/*
	 *	Read request(s) from the file.
	 */
	return radclient_init(files, files);
}

/*
 *	Deallocate packet ID, etc.
 */
static void deallocate_id(rc_request_t *request)
{
	if (!request || !request->packet ||
	    (request->packet->id < 0)) {
		return;
	}

	/*
	 *	One more unused RADIUS ID.
	 */
	fr_packet_list_id_free(packet_list, request->packet, true);

	/*
	 *	If we've already sent a packet, free up the old one,
	 *	and ensure that the next packet has a unique
	 *	authentication vector.
	 */
	if (request->packet->data) TALLOC_FREE(request->packet->data);
	if (request->reply) fr_radius_packet_free(&request->reply);
}

/*
 *	Send one packet.
 */
static int send_one_packet(rc_request_t *request)
{
	assert(request->done == false);

	/*
	 *	Remember when we have to wake up, to re-send the
	 *	request, of we didn't receive a reply.
	 */
	if ((sleep_time == -1) || (sleep_time > timeout)) sleep_time = timeout;

	/*
	 *	Haven't sent the packet yet.  Initialize it.
	 */
	if (!request->tries || request->packet->id == -1) {
		bool rcode;

		assert(request->reply == NULL);

		/*
		 *	Didn't find a free packet ID, we're not done,
		 *	we don't sleep, and we stop trying to process
		 *	this packet.
		 */
	retry:
		request->packet->socket.inet.src_ipaddr.af = server_ipaddr.af;
		rcode = fr_packet_list_id_alloc(packet_list, ipproto, &request->packet, NULL);
		if (!rcode) {
			int mysockfd;

			if (ipproto == IPPROTO_TCP) {
				mysockfd = fr_socket_client_tcp(NULL,
								&request->packet->socket.inet.dst_ipaddr,
								request->packet->socket.inet.dst_port, false);
				if (mysockfd < 0) {
					fr_perror("Error opening socket");
					return -1;
				}
			} else {
				uint16_t port = 0;

				mysockfd = fr_socket_server_udp(&client_ipaddr, &port, NULL, true);
				if (mysockfd < 0) {
					fr_perror("Error opening socket");
					return -1;
				}

				if (fr_socket_bind(mysockfd, &client_ipaddr, &port, NULL) < 0) {
					fr_perror("Error binding socket");
					return -1;
				}
			}

			if (!fr_packet_list_socket_add(packet_list, mysockfd, ipproto,
						       &request->packet->socket.inet.dst_ipaddr,
						       request->packet->socket.inet.dst_port, NULL)) {
				ERROR("Can't add new socket");
				fr_exit_now(1);
			}
			goto retry;
		}

		assert(request->packet->id != -1);
		assert(request->packet->data == NULL);

		/*
		 *	Update the password, so it can be encrypted with the
		 *	new authentication vector.
		 */
		if (request->password) {
			fr_pair_t *vp;

			if ((vp = fr_pair_find_by_da(&request->request_pairs, attr_user_password)) != NULL) {
				fr_pair_value_strdup(vp, request->password->vp_strvalue);

			} else if ((vp = fr_pair_find_by_da(&request->request_pairs,
							    attr_chap_password)) != NULL) {
				uint8_t		buffer[17];
				fr_pair_t	*challenge;
				uint8_t	const	*vector;

				/*
				 *	Use Chap-Challenge pair if present,
				 *	Request Authenticator otherwise.
				 */
				challenge = fr_pair_find_by_da(&request->request_pairs, attr_chap_challenge);
				if (challenge && (challenge->vp_length == RADIUS_AUTH_VECTOR_LENGTH)) {
					vector = challenge->vp_octets;
				} else {
					vector = request->packet->vector;
				}

				fr_radius_encode_chap_password(buffer,
							       fr_rand() & 0xff, vector,
							       request->password->vp_strvalue,
							       request->password->vp_length);
				fr_pair_value_memdup(vp, buffer, sizeof(buffer), false);

			} else if (fr_pair_find_by_da(&request->request_pairs, attr_ms_chap_password) != NULL) {
				mschapv1_encode(request->packet, &request->request_pairs, request->password->vp_strvalue);

			} else {
				DEBUG("WARNING: No password in the request");
			}
		}

		request->timestamp = fr_time();
		request->tries = 1;
		request->resend++;

	} else {		/* request->packet->id >= 0 */
		fr_time_delta_t now = fr_time();

		/*
		 *	FIXME: Accounting packets are never retried!
		 *	The Acct-Delay-Time attribute is updated to
		 *	reflect the delay, and the packet is re-sent
		 *	from scratch!
		 */

		/*
		 *	Not time for a retry, do so.
		 */
		if ((now - request->timestamp) < timeout) {
			/*
			 *	When we walk over the tree sending
			 *	packets, we update the minimum time
			 *	required to sleep.
			 */
			if ((sleep_time == -1) ||
			    (sleep_time > (now - request->timestamp))) {
				sleep_time = now - request->timestamp;
			}
			return 0;
		}

		/*
		 *	We're not trying later, maybe the packet is done.
		 */
		if (request->tries == retries) {
			assert(request->packet->id >= 0);

			/*
			 *	Delete the request from the tree of
			 *	outstanding requests.
			 */
			fr_packet_list_yank(packet_list, request->packet);

			REDEBUG("No reply from server for ID %d socket %d",
				request->packet->id, request->packet->socket.fd);
			deallocate_id(request);

			/*
			 *	Normally we mark it "done" when we've received
			 *	the reply, but this is a special case.
			 */
			if (request->resend == resend_count) {
				request->done = true;
			}
			stats.lost++;
			return -1;
		}

		/*
		 *	We are trying later.
		 */
		request->timestamp = now;
		request->tries++;
	}

	/*
	 *	Send the packet.
	 */
	if (fr_radius_packet_send(request->packet, NULL, secret) < 0) {
		REDEBUG("Failed to send packet for ID %d", request->packet->id);
		deallocate_id(request);
		request->done = true;
		return -1;
	}

	fr_packet_log(&default_log, request->packet, false);

	return 0;
}

/*
 *	Receive one packet, maybe.
 */
static int recv_one_packet(fr_time_t wait_time)
{
	fd_set		set;
	fr_time_delta_t our_wait_time;
	rc_request_t	*request;
	fr_radius_packet_t	*reply, **packet_p;
	volatile int	max_fd;

	/* And wait for reply, timing out as necessary */
	FD_ZERO(&set);

	max_fd = fr_packet_list_fd_set(packet_list, &set);
	if (max_fd < 0) fr_exit_now(1); /* no sockets to listen on! */

	our_wait_time = (wait_time <= 0) ? 0 : wait_time;

	/*
	 *	No packet was received.
	 */
	if (select(max_fd, &set, NULL, NULL, &fr_time_delta_to_timeval(our_wait_time)) <= 0) return 0;

	/*
	 *	Look for the packet.
	 */
	reply = fr_packet_list_recv(packet_list, &set, RADIUS_MAX_ATTRIBUTES, false);
	if (!reply) {
		ERROR("Received bad packet");
		/*
		 *	If the packet is bad, we close the socket.
		 *	I'm not sure how to do that now, so we just
		 *	die...
		 */
		if (ipproto == IPPROTO_TCP) fr_exit_now(1);
		return -1;	/* bad packet */
	}

	/*
	 *	We don't use udpfromto.  So if we bind to "*", we want
	 *	to find replies sent to 192.0.2.4.  Therefore, we
	 *	force all replies to have the one address we know
	 *	about, no matter what real address they were sent to.
	 *
	 *	This only works if were not using any of the
	 *	Packet-* attributes, or running with 'auto'.
	 */
	reply->socket.inet.dst_ipaddr = client_ipaddr;
	reply->socket.inet.dst_port = client_port;

	/*
	 *	TCP sockets don't use recvmsg(), and thus don't get
	 *	the source IP/port.  However, since they're TCP, we
	 *	know what the source IP/port is, because that's where
	 *	we connected to.
	 */
	if (ipproto == IPPROTO_TCP) {
		reply->socket.inet.src_ipaddr = server_ipaddr;
		reply->socket.inet.src_port = server_port;
	}

	packet_p = fr_packet_list_find_byreply(packet_list, reply);
	if (!packet_p) {
		ERROR("Received reply to request we did not send. (id=%d socket %d)",
		      reply->id, reply->socket.fd);
		fr_radius_packet_free(&reply);
		return -1;	/* got reply to packet we didn't send */
	}
	request = fr_packet2myptr(rc_request_t, packet, packet_p);

	/*
	 *	Fails the signature validation: not a real reply.
	 *	FIXME: Silently drop it and listen for another packet.
	 */
	if (fr_radius_packet_verify(reply, request->packet, secret) < 0) {
		REDEBUG("Reply verification failed");
		stats.lost++;
		goto packet_done; /* shared secret is incorrect */
	}

	if (print_filename) {
		RDEBUG("%s response code %d", request->files->packets, reply->code);
	}

	deallocate_id(request);
	request->reply = reply;
	reply = NULL;

	/*
	 *	If this fails, we're out of memory.
	 */
	if (fr_radius_packet_decode(request->reply, request->packet, RADIUS_MAX_ATTRIBUTES, false, secret) != 0) {
		REDEBUG("Reply decode failed");
		stats.lost++;
		goto packet_done;
	}

	fr_packet_log(&default_log, request->reply, true);

	/*
	 *	Increment counters...
	 */
	switch (request->reply->code) {
	case FR_CODE_ACCESS_ACCEPT:
	case FR_CODE_ACCOUNTING_RESPONSE:
	case FR_CODE_COA_ACK:
	case FR_CODE_DISCONNECT_ACK:
		stats.accepted++;
		break;

	case FR_CODE_ACCESS_CHALLENGE:
		break;

	default:
		stats.rejected++;
	}

	fr_strerror();	/* Clear strerror buffer */

	/*
	 *	If we had an expected response code, check to see if the
	 *	packet matched that.
	 */
	if ((request->filter_code != FR_CODE_UNDEFINED) && (request->reply->code != request->filter_code)) {
		if (is_radius_code(request->reply->code)) {
			REDEBUG("%s: Expected %s got %s", request->name, fr_packet_codes[request->filter_code],
				fr_packet_codes[request->reply->code]);
		} else {
			REDEBUG("%s: Expected %u got %i", request->name, request->filter_code,
				request->reply->code);
		}
		stats.failed++;
	/*
	 *	Check if the contents of the packet matched the filter
	 */
	} else if (!request->filter) {
		stats.passed++;
	} else {
		fr_pair_t const *failed[2];

		fr_pair_list_sort(&request->reply_pairs, fr_pair_cmp_by_da);
		if (fr_pair_validate(failed, &request->filter, &request->reply_pairs)) {
			RDEBUG("%s: Response passed filter", request->name);
			stats.passed++;
		} else {
			fr_pair_validate_debug(request, failed);
			REDEBUG("%s: Response for failed filter", request->name);
			stats.failed++;
		}
	}

	if (request->resend == resend_count) {
		request->done = true;
	}

packet_done:
	fr_radius_packet_free(&request->reply);
	fr_radius_packet_free(&reply);	/* may be NULL */

	return 0;
}

/**
 *
 * @hidecallgraph
 */
int main(int argc, char **argv)
{
	int		c;
	char		const *raddb_dir = RADDBDIR;
	char		const *dict_dir = DICTDIR;
	char		filesecret[256];
	FILE		*fp;
	int		do_summary = false;
	int		persec = 0;
	int		parallel = 1;
	rc_request_t	*this;
	int		force_af = AF_UNSPEC;
	TALLOC_CTX	*autofree;

	/*
	 *	It's easier having two sets of flags to set the
	 *	verbosity of library calls and the verbosity of
	 *	radclient.
	 */
	fr_debug_lvl = 0;
	fr_log_fp = stdout;

	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_thread_local_atexit_setup();

	autofree = talloc_autofree_context();

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radclient");
		fr_exit_now(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	filename_tree = rbtree_talloc_alloc(NULL, filename_cmp, rc_file_pair_t, NULL, 0);
	if (!filename_tree) {
	oom:
		ERROR("Out of memory");
		fr_exit_now(1);
	}

	/*
	 *	Always log to stdout
	 */
	default_log.dst = L_DST_STDOUT;
	default_log.fd = STDOUT_FILENO;
	default_log.print_level = false;

	while ((c = getopt(argc, argv, "46c:C:d:D:f:Fhi:n:p:P:r:sS:t:vx")) != -1) switch (c) {
		case '4':
			force_af = AF_INET;
			break;

		case '6':
			force_af = AF_INET6;
			break;

		case 'c':
			if (!isdigit((int) *optarg)) usage();

			resend_count = atoi(optarg);

			if (resend_count < 1) usage();
			break;

		case 'C':
		{
			int tmp;

			tmp = atoi(optarg);
			if (tmp < 1 || tmp > 65535) usage();

			client_port = (uint16_t)tmp;
		}
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'd':
			raddb_dir = optarg;
			break;

		case 'f':
		{
			char const *p;
			rc_file_pair_t *files;

			files = talloc(talloc_autofree_context(), rc_file_pair_t);
			if (!files) goto oom;

			p = strchr(optarg, ':');
			if (p) {
				files->packets = talloc_strndup(files, optarg, p - optarg);
				if (!files->packets) goto oom;
				files->filters = p + 1;
			} else {
				files->packets = optarg;
				files->filters = NULL;
			}
			rbtree_insert(filename_tree, (void *) files);
		}
			break;

		case 'F':
			print_filename = true;
			break;

		case 'i':
			if (!isdigit((int) *optarg))
				usage();
			last_used_id = atoi(optarg);
			if ((last_used_id < 0) || (last_used_id > 255)) {
				usage();
			}
			break;

		case 'n':
			persec = atoi(optarg);
			if (persec <= 0) usage();
			break;

			/*
			 *	Note that sending MANY requests in
			 *	parallel can over-run the kernel
			 *	queues, and Linux will happily discard
			 *	packets.  So even if the server responds,
			 *	the client may not see the reply.
			 */
		case 'p':
			parallel = atoi(optarg);
			if (parallel <= 0) usage();
			break;

		case 'P':
			if (!strcmp(optarg, "tcp")) {
				ipproto = IPPROTO_TCP;
			} else if (!strcmp(optarg, "udp")) {
				ipproto = IPPROTO_UDP;
			} else {
				usage();
			}
			break;

		case 'r':
			if (!isdigit((int) *optarg)) usage();
			retries = atoi(optarg);
			if ((retries == 0) || (retries > 1000)) usage();
			break;

		case 's':
			do_summary = true;
			break;

		case 'S':
		{
			char *p;
			fp = fopen(optarg, "r");
			if (!fp) {
			       ERROR("Error opening %s: %s", optarg, fr_syserror(errno));
			       fr_exit_now(1);
			}
			if (fgets(filesecret, sizeof(filesecret), fp) == NULL) {
			       ERROR("Error reading %s: %s", optarg, fr_syserror(errno));
			       fr_exit_now(1);
			}
			fclose(fp);

			/* truncate newline */
			p = filesecret + strlen(filesecret) - 1;
			while ((p >= filesecret) &&
			      (*p < ' ')) {
			       *p = '\0';
			       --p;
			}

			if (strlen(filesecret) < 2) {
			       ERROR("Secret in %s is too short", optarg);
			       fr_exit_now(1);
			}
			secret = talloc_strdup(NULL, filesecret);
		}
		       break;

		case 't':
			if (fr_time_delta_from_str(&timeout, optarg, FR_TIME_RES_SEC) < 0) {
				fr_perror("Failed parsing timeout value");
				fr_exit_now(EXIT_FAILURE);
			}
			break;

		case 'v':
			fr_debug_lvl = 1;
			DEBUG("%s", radclient_version);
			fr_exit_now(0);

		case 'x':
			fr_debug_lvl++;
			if (fr_debug_lvl > 1) default_log.print_level = true;
			break;

		case 'h':
		default:
			usage();
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if ((argc < 3) || ((secret == NULL) && (argc < 4))) {
		ERROR("Insufficient arguments");
		usage();
	}
	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radclient");
		return 1;
	}

	if (!fr_dict_global_ctx_init(autofree, dict_dir)) {
		fr_perror("radclient");
		return 1;
	}

	if (fr_radius_init() < 0) {
		fr_perror("radclient");
		return 1;
	}

	if (fr_dict_autoload(radclient_dict) < 0) {
		fr_perror("radclient");
		return 1;
	}

	if (fr_dict_attr_autoload(radclient_dict_attr) < 0) {
		fr_perror("radclient");
		return 1;
	}

	if (fr_dict_read(fr_dict_unconst(dict_freeradius), raddb_dir, FR_DICTIONARY_FILE) == -1) {
		fr_log_perror(&default_log, L_ERR, __FILE__, __LINE__, NULL,
			      "Failed to initialize the dictionaries");
		return 1;
	}
	fr_strerror();	/* Clear the error buffer */

	/*
	 *	Get the request type
	 */
	if (!isdigit((int) argv[2][0])) {
		packet_code = fr_table_value_by_str(fr_request_types, argv[2], -2);
		if (packet_code == -2) {
			ERROR("Unrecognised request type \"%s\"", argv[2]);
			usage();
		}
	} else {
		packet_code = atoi(argv[2]);
	}

	/*
	 *	Resolve hostname.
	 */
	if (strcmp(argv[1], "-") != 0) {
		if (fr_inet_pton_port(&server_ipaddr, &server_port, argv[1], -1, force_af, true, true) < 0) {
			fr_perror("radclient");
			fr_exit_now(1);
		}

		/*
		 *	Work backwards from the port to determine the packet type
		 */
		if (packet_code == FR_CODE_UNDEFINED) packet_code = radclient_get_code(server_port);
	}
	radclient_get_port(packet_code, &server_port);

	/*
	 *	Add the secret.
	 */
	if (argv[3]) secret = talloc_strdup(NULL, argv[3]);

	/*
	 *	If no '-f' is specified, we're reading from stdin.
	 */
	if (rbtree_num_elements(filename_tree) == 0) {
		rc_file_pair_t *files;

		files = talloc_zero(talloc_autofree_context(), rc_file_pair_t);
		files->packets = "-";
		if (radclient_init(files, files) < 0) fr_exit_now(1);
	}

	/*
	 *	Walk over the list of filenames, creating the requests.
	 */
	if (rbtree_walk(filename_tree, RBTREE_IN_ORDER, filename_walk, NULL) != 0) {
		ERROR("Failed parsing input files");
		fr_exit_now(1);
	}

	/*
	 *	No packets read.  Die.
	 */
	if (!request_head) {
		ERROR("Nothing to send");
		fr_exit_now(1);
	}

	/*
	 *	Bind to the first specified IP address and port.
	 *	This means we ignore later ones.
	 */
	if (request_head->packet->socket.inet.src_ipaddr.af == AF_UNSPEC) {
		memset(&client_ipaddr, 0, sizeof(client_ipaddr));
		client_ipaddr.af = server_ipaddr.af;
	} else {
		client_ipaddr = request_head->packet->socket.inet.src_ipaddr;
	}

	if (client_port == 0) client_port = request_head->packet->socket.inet.src_port;

	if (ipproto == IPPROTO_TCP) {
		sockfd = fr_socket_client_tcp(NULL, &server_ipaddr, server_port, false);
		if (sockfd < 0) {
			ERROR("Failed opening socket");
			return -1;
		}

	} else {
		sockfd = fr_socket_server_udp(&client_ipaddr, &client_port, NULL, false);
		if (sockfd < 0) {
			fr_perror("Error opening socket");
			return -1;
		}

		if (fr_socket_bind(sockfd, &client_ipaddr, &client_port, NULL) < 0) {
			fr_perror("Error binding socket");
			return -1;
		}
	}

	packet_list = fr_packet_list_create(1);
	if (!packet_list) {
		ERROR("Out of memory");
		fr_exit_now(1);
	}

	if (!fr_packet_list_socket_add(packet_list, sockfd, ipproto, &server_ipaddr,
				       server_port, NULL)) {
		ERROR("Failed adding socket");
		fr_exit_now(1);
	}

	/*
	 *	Walk over the list of packets, sanity checking
	 *	everything.
	 */
	for (this = request_head; this != NULL; this = this->next) {
		this->packet->socket.inet.src_ipaddr = client_ipaddr;
		this->packet->socket.inet.src_port = client_port;
		if (radclient_sane(this) != 0) {
			fr_exit_now(1);
		}
	}

	/*
	 *	Walk over the packets to send, until
	 *	we're all done.
	 *
	 *	FIXME: This currently busy-loops until it receives
	 *	all of the packets.  It should really have some sort of
	 *	send packet, get time to wait, select for time, etc.
	 *	loop.
	 */
	do {
		int n = parallel;
		rc_request_t *next;
		char const *filename = NULL;

		done = true;
		sleep_time = -1;

		/*
		 *	Walk over the packets, sending them.
		 */

		for (this = request_head; this != NULL; this = next) {
			next = this->next;

			/*
			 *	If there's a packet to receive,
			 *	receive it, but don't wait for a
			 *	packet.
			 */
			recv_one_packet(0);

			/*
			 *	This packet is done.  Delete it.
			 */
			if (this->done) {
				talloc_free(this);
				continue;
			}

			/*
			 *	Packets from multiple '-f' are sent
			 *	in parallel.
			 *
			 *	Packets from one file are sent in
			 *	series, unless '-p' is specified, in
			 *	which case N packets from each file
			 *	are sent in parallel.
			 */
			if (this->files->packets != filename) {
				filename = this->files->packets;
				n = parallel;
			}

			if (n > 0) {
				n--;

				/*
				 *	Send the current packet.
				 */
				if (send_one_packet(this) < 0) {
					talloc_free(this);
					break;
				}

				/*
				 *	Wait a little before sending
				 *	the next packet, if told to.
				 */
				if (persec) {
					fr_time_delta_t psec;

					psec = (persec == 1) ? fr_time_delta_from_sec(1) : (1000000 / persec);

					/*
					 *	Don't sleep elsewhere.
					 */
					sleep_time = 0;


					/*
					 *	Sleep for milliseconds,
					 *	portably.
					 *
					 *	If we get an error or
					 *	a signal, treat it like
					 *	a normal timeout.
					 */
					select(0, NULL, NULL, NULL, &fr_time_delta_to_timeval(psec));
				}

				/*
				 *	If we haven't sent this packet
				 *	often enough, we're not done,
				 *	and we shouldn't sleep.
				 */
				if (this->resend < resend_count) {
					int i;

					done = false;
					sleep_time = 0;

					for (i = 0; i < 4; i++) {
						((uint32_t *) this->packet->vector)[i] = fr_rand();
					}
				}
			} else { /* haven't sent this packet, we're not done */
				assert(this->done == false);
				assert(this->reply == NULL);
				done = false;
			}
		}

		/*
		 *	Still have outstanding requests.
		 */
		if (fr_packet_list_num_elements(packet_list) > 0) {
			done = false;
		} else {
			sleep_time = 0;
		}

		/*
		 *	Nothing to do until we receive a request, so
		 *	sleep until then.  Once we receive one packet,
		 *	we go back, and walk through the whole list again,
		 *	sending more packets (if necessary), and updating
		 *	the sleep time.
		 */
		if (!done && (sleep_time > 0)) {
			recv_one_packet(sleep_time);
		}
	} while (!done);

	talloc_free(filename_tree);

	fr_packet_list_free(packet_list);

	while (request_head) TALLOC_FREE(request_head);

	talloc_free(secret);

	fr_radius_free();

	fr_dict_autofree(radclient_dict);

	if (do_summary) {
		fr_perror("Packet summary:\n"
		      "\tAccepted      : %" PRIu64 "\n"
		      "\tRejected      : %" PRIu64 "\n"
		      "\tLost          : %" PRIu64 "\n"
		      "\tPassed filter : %" PRIu64 "\n"
		      "\tFailed filter : %" PRIu64,
		      stats.accepted,
		      stats.rejected,
		      stats.lost,
		      stats.passed,
		      stats.failed
		);
	}

	if ((stats.lost > 0) || (stats.failed > 0)) {
		fr_exit_now(EXIT_FAILURE);
	}

	fr_exit_now(EXIT_SUCCESS);
}
