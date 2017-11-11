/*
 * radclient.c	General radius packet debug tool.
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
 * Copyright 2000,2006,2014  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radclient.h>
#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/conf.h>
#include <ctype.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <assert.h>

typedef struct REQUEST REQUEST;	/* to shut up warnings about mschap.h */

#include "smbdes.h"
#include "mschap.h"

static int retries = 3;
static float timeout = 5;
static char const *secret = NULL;
static bool do_output = true;

static rc_stats_t stats;

static uint16_t server_port = 0;
static int packet_code = PW_CODE_UNDEFINED;
static fr_ipaddr_t server_ipaddr;
static int resend_count = 1;
static bool done = true;
static bool print_filename = false;

static fr_ipaddr_t client_ipaddr;
static uint16_t client_port = 0;

static int sockfd;
static int last_used_id = -1;

#ifdef WITH_TCP
static char const *proto = NULL;
#endif
static int ipproto = IPPROTO_UDP;

static rbtree_t *filename_tree = NULL;
static fr_packet_list_t *pl = NULL;

static int sleep_time = -1;

static rc_request_t *request_head = NULL;
static rc_request_t *rc_request_tail = NULL;

static char const *radclient_version = "radclient version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
#ifndef ENABLE_REPRODUCIBLE_BUILDS
", built on " __DATE__ " at " __TIME__
#endif
;

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "Usage: radclient [options] server[:port] <command> [<secret>]\n");

	fprintf(stderr, "  <command>              One of auth, acct, status, coa, disconnect or auto.\n");
	fprintf(stderr, "  -4                     Use IPv4 address of server\n");
	fprintf(stderr, "  -6                     Use IPv6 address of server.\n");
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
	fprintf(stderr, "  -q                     Do not print anything out.\n");
	fprintf(stderr, "  -r <retries>           If timeout, retry sending the packet 'retries' times.\n");
	fprintf(stderr, "  -s                     Print out summary information of auth results.\n");
	fprintf(stderr, "  -S <file>              read secret from file, not command line.\n");
	fprintf(stderr, "  -t <timeout>           Wait 'timeout' seconds before retrying (may be a floating point number).\n");
	fprintf(stderr, "  -v                     Show program version information.\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

#ifdef WITH_TCP
	fprintf(stderr, "  -P <proto>             Use proto (tcp or udp) for transport.\n");
#endif

	exit(1);
}

static const FR_NAME_NUMBER request_types[] = {
	{ "auth",	PW_CODE_ACCESS_REQUEST },
	{ "challenge",	PW_CODE_ACCESS_CHALLENGE },
	{ "acct",	PW_CODE_ACCOUNTING_REQUEST },
	{ "status",	PW_CODE_STATUS_SERVER },
	{ "disconnect",	PW_CODE_DISCONNECT_REQUEST },
	{ "coa",	PW_CODE_COA_REQUEST },
	{ "auto",	PW_CODE_UNDEFINED },

	{ NULL, 0}
};

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

static int mschapv1_encode(RADIUS_PACKET *packet, VALUE_PAIR **request,
			   char const *password)
{
	unsigned int i;
	uint8_t *p;
	VALUE_PAIR *challenge, *reply;
	uint8_t nthash[16];

	fr_pair_delete_by_num(&packet->vps, PW_MSCHAP_CHALLENGE, VENDORPEC_MICROSOFT, TAG_ANY);
	fr_pair_delete_by_num(&packet->vps, PW_MSCHAP_RESPONSE, VENDORPEC_MICROSOFT, TAG_ANY);

	challenge = fr_pair_afrom_num(packet, PW_MSCHAP_CHALLENGE, VENDORPEC_MICROSOFT);
	if (!challenge) {
		return 0;
	}

	fr_pair_add(request, challenge);
	challenge->vp_length = 8;
	challenge->vp_octets = p = talloc_array(challenge, uint8_t, challenge->vp_length);
	for (i = 0; i < challenge->vp_length; i++) {
		p[i] = fr_rand();
	}

	reply = fr_pair_afrom_num(packet, PW_MSCHAP_RESPONSE, VENDORPEC_MICROSOFT);
	if (!reply) {
		return 0;
	}

	fr_pair_add(request, reply);
	reply->vp_length = 50;
	reply->vp_octets = p = talloc_array(reply, uint8_t, reply->vp_length);
	memset(p, 0, reply->vp_length);

	p[1] = 0x01; /* NT hash */

	if (mschap_ntpwdhash(nthash, password) < 0) {
		return 0;
	}

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
static void radclient_get_port(PW_CODE type, uint16_t *port)
{
	switch (type) {
	default:
	case PW_CODE_ACCESS_REQUEST:
	case PW_CODE_ACCESS_CHALLENGE:
	case PW_CODE_STATUS_SERVER:
		if (*port == 0) *port = getport("radius");
		if (*port == 0) *port = PW_AUTH_UDP_PORT;
		return;

	case PW_CODE_ACCOUNTING_REQUEST:
		if (*port == 0) *port = getport("radacct");
		if (*port == 0) *port = PW_ACCT_UDP_PORT;
		return;

	case PW_CODE_DISCONNECT_REQUEST:
		if (*port == 0) *port = PW_POD_UDP_PORT;
		return;

	case PW_CODE_COA_REQUEST:
		if (*port == 0) *port = PW_COA_UDP_PORT;
		return;

	case PW_CODE_UNDEFINED:
		if (*port == 0) *port = 0;
		return;
	}
}

/*
 *	Resolve a port to a request type
 */
static PW_CODE radclient_get_code(uint16_t port)
{
	/*
	 *	getport returns 0 if the service doesn't exist
	 *	so we need to return early, to avoid incorrect
	 *	codes.
	 */
	if (port == 0) return PW_CODE_UNDEFINED;

	if ((port == getport("radius")) || (port == PW_AUTH_UDP_PORT) || (port == PW_AUTH_UDP_PORT_ALT)) {
		return PW_CODE_ACCESS_REQUEST;
	}
	if ((port == getport("radacct")) || (port == PW_ACCT_UDP_PORT) || (port == PW_ACCT_UDP_PORT_ALT)) {
		return PW_CODE_ACCOUNTING_REQUEST;
	}
	if (port == PW_COA_UDP_PORT) return PW_CODE_COA_REQUEST;
	if (port == PW_POD_UDP_PORT) return PW_CODE_DISCONNECT_REQUEST;

	return PW_CODE_UNDEFINED;
}


static bool already_hex(VALUE_PAIR *vp)
{
	size_t i;

	if (!vp || (vp->da->type != PW_TYPE_OCTETS)) return true;

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
	FILE *packets, *filters = NULL;

	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	rc_request_t *request;
	bool packets_done = false;
	uint64_t num = 0;

	assert(files->packets != NULL);

	/*
	 *	Determine where to read the VP's from.
	 */
	if (strcmp(files->packets, "-") != 0) {
		packets = fopen(files->packets, "r");
		if (!packets) {
			ERROR("Error opening %s: %s", files->packets, strerror(errno));
			return 0;
		}

		/*
		 *	Read in the pairs representing the expected response.
		 */
		if (files->filters) {
			filters = fopen(files->filters, "r");
			if (!filters) {
				ERROR("Error opening %s: %s", files->filters, strerror(errno));
				fclose(packets);
				return 0;
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

		request->packet = rad_alloc(request, true);
		if (!request->packet) {
			ERROR("Out of memory");
			goto error;
		}

#ifdef WITH_TCP
		request->packet->src_ipaddr = client_ipaddr;
		request->packet->src_port = client_port;
		request->packet->dst_ipaddr = server_ipaddr;
		request->packet->dst_port = server_port;
		request->packet->proto = ipproto;
#endif

		request->files = files;
		request->packet->id = -1; /* allocate when sending */
		request->num = num++;

		/*
		 *	Read the request VP's.
		 */
		if (fr_pair_list_afrom_file(request->packet, &request->packet->vps, packets, &packets_done) < 0) {
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
		if (!request->packet->vps) {
			talloc_free(request);
			continue;
		}

		/*
		 *	Read in filter VP's.
		 */
		if (filters) {
			bool filters_done;

			if (fr_pair_list_afrom_file(request, &request->filter, filters, &filters_done) < 0) {
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
				if (vp->type == VT_XLAT) {
					vp->type = VT_DATA;
					vp->vp_strvalue = vp->value.xlat;
					vp->vp_length = talloc_array_length(vp->vp_strvalue) - 1;
				}

				if (vp->da->vendor == 0 ) switch (vp->da->attr) {
				case PW_RESPONSE_PACKET_TYPE:
				case PW_PACKET_TYPE:
					fr_cursor_remove(&cursor);	/* so we don't break the filter */
					request->filter_code = vp->vp_integer;
					talloc_free(vp);

				default:
					break;
				}
			}

			/*
			 *	This allows efficient list comparisons later
			 */
			fr_pair_list_sort(&request->filter, fr_pair_cmp_by_da_tag);
		}

		/*
		 *	Process special attributes
		 */
		for (vp = fr_cursor_init(&cursor, &request->packet->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			/*
			 *	Double quoted strings get marked up as xlat expansions,
			 *	but we don't support that in request.
			 */
			if (vp->type == VT_XLAT) {
				vp->type = VT_DATA;
				vp->vp_strvalue = vp->value.xlat;
				vp->vp_length = talloc_array_length(vp->vp_strvalue) - 1;
			}

			if (!vp->da->vendor) switch (vp->da->attr) {
			default:
				break;

			/*
			 *	Allow it to set the packet type in
			 *	the attributes read from the file.
			 */
			case PW_PACKET_TYPE:
				request->packet->code = vp->vp_integer;
				break;

			case PW_RESPONSE_PACKET_TYPE:
				request->filter_code = vp->vp_integer;
				break;

			case PW_PACKET_DST_PORT:
				request->packet->dst_port = (vp->vp_integer & 0xffff);
				break;

			case PW_PACKET_DST_IP_ADDRESS:
				request->packet->dst_ipaddr.af = AF_INET;
				request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
				request->packet->dst_ipaddr.prefix = 32;
				break;

			case PW_PACKET_DST_IPV6_ADDRESS:
				request->packet->dst_ipaddr.af = AF_INET6;
				request->packet->dst_ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
				request->packet->dst_ipaddr.prefix = 128;
				break;

			case PW_PACKET_SRC_PORT:
				if ((vp->vp_integer < 1024) ||
				    (vp->vp_integer > 65535)) {
					ERROR("Invalid value '%u' for Packet-Src-Port", vp->vp_integer);
					goto error;
				}
				request->packet->src_port = (vp->vp_integer & 0xffff);
				break;

			case PW_PACKET_SRC_IP_ADDRESS:
				request->packet->src_ipaddr.af = AF_INET;
				request->packet->src_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
				request->packet->src_ipaddr.prefix = 32;
				break;

			case PW_PACKET_SRC_IPV6_ADDRESS:
				request->packet->src_ipaddr.af = AF_INET6;
				request->packet->src_ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
				request->packet->src_ipaddr.prefix = 128;
				break;

			case PW_DIGEST_REALM:
			case PW_DIGEST_NONCE:
			case PW_DIGEST_METHOD:
			case PW_DIGEST_URI:
			case PW_DIGEST_QOP:
			case PW_DIGEST_ALGORITHM:
			case PW_DIGEST_BODY_DIGEST:
			case PW_DIGEST_CNONCE:
			case PW_DIGEST_NONCE_COUNT:
			case PW_DIGEST_USER_NAME:
			/* overlapping! */
			{
				DICT_ATTR const *da;
				uint8_t *p, *q;

				p = talloc_array(vp, uint8_t, vp->vp_length + 2);

				memcpy(p + 2, vp->vp_octets, vp->vp_length);
				p[0] = vp->da->attr - PW_DIGEST_REALM + 1;
				vp->vp_length += 2;
				p[1] = vp->vp_length;

				da = dict_attrbyvalue(PW_DIGEST_ATTRIBUTES, 0);
				if (!da) {
					ERROR("Out of memory");
					goto error;
				}
				vp->da = da;

				/*
				 *	Re-do fr_pair_value_memsteal ourselves,
				 *	because we play games with
				 *	vp->da, and fr_pair_value_memsteal goes
				 *	to GREAT lengths to sanitize
				 *	and fix and change and
				 *	double-check the various
				 *	fields.
				 */
				memcpy(&q, &vp->vp_octets, sizeof(q));
				talloc_free(q);

				vp->vp_octets = talloc_steal(vp, p);
				vp->type = VT_DATA;

				VERIFY_VP(vp);
			}
				break;

				/*
				 *	Cache this for later.
				 */
			case PW_CLEARTEXT_PASSWORD:
				request->password = vp;
				break;

			/*
			 *	Keep a copy of the the password attribute.
			 */
			case PW_CHAP_PASSWORD:
				/*
				 *	If it's already hex, do nothing.
				 */
				if ((vp->vp_length == 17) &&
				    (already_hex(vp))) break;

				/*
				 *	CHAP-Password is octets, so it may not be zero terminated.
				 */
				request->password = fr_pair_make(request->packet, &request->packet->vps, "Cleartext-Password",
							     "", T_OP_EQ);
				fr_pair_value_bstrncpy(request->password, vp->vp_strvalue, vp->vp_length);
				break;

			case PW_USER_PASSWORD:
			case PW_MS_CHAP_PASSWORD:
				request->password = fr_pair_make(request->packet, &request->packet->vps, "Cleartext-Password",
							     vp->vp_strvalue, T_OP_EQ);
				break;

			case PW_RADCLIENT_TEST_NAME:
				request->name = vp->vp_strvalue;
				break;
			}
		} /* loop over the VP's we read in */

		/*
		 *	Use the default set on the command line
		 */
		if (request->packet->code == PW_CODE_UNDEFINED) request->packet->code = packet_code;

		/*
		 *	Default to the filename
		 */
		if (!request->name) request->name = request->files->packets;

		/*
		 *	Automatically set the response code from the request code
		 *	(if one wasn't already set).
		 */
		if (request->filter_code == PW_CODE_UNDEFINED) {
			switch (request->packet->code) {
			case PW_CODE_ACCESS_REQUEST:
				request->filter_code = PW_CODE_ACCESS_ACCEPT;
				break;

			case PW_CODE_ACCOUNTING_REQUEST:
				request->filter_code = PW_CODE_ACCOUNTING_RESPONSE;
				break;

			case PW_CODE_COA_REQUEST:
				request->filter_code = PW_CODE_COA_ACK;
				break;

			case PW_CODE_DISCONNECT_REQUEST:
				request->filter_code = PW_CODE_DISCONNECT_ACK;
				break;

			case PW_CODE_STATUS_SERVER:
				switch (radclient_get_code(request->packet->dst_port)) {
				case PW_CODE_ACCESS_REQUEST:
					request->filter_code = PW_CODE_ACCESS_ACCEPT;
					break;

				case PW_CODE_ACCOUNTING_REQUEST:
					request->filter_code = PW_CODE_ACCOUNTING_RESPONSE;
					break;

				default:
					request->filter_code = PW_CODE_UNDEFINED;
					break;
				}
				break;

			case PW_CODE_UNDEFINED:
				REDEBUG("Both Packet-Type and Response-Packet-Type undefined, specify at least one, "
					"or a well known RADIUS port");
				goto error;

			default:
				REDEBUG("Can't determine expected Response-Packet-Type for Packet-Type %i",
					request->packet->code);
				goto error;
			}
		/*
		 *	Automatically set the request code from the response code
		 *	(if one wasn't already set).
		 */
		} else if (request->packet->code == PW_CODE_UNDEFINED) {
			switch (request->filter_code) {
			case PW_CODE_ACCESS_ACCEPT:
			case PW_CODE_ACCESS_REJECT:
				request->packet->code = PW_CODE_ACCESS_REQUEST;
				break;

			case PW_CODE_ACCOUNTING_RESPONSE:
				request->packet->code = PW_CODE_ACCOUNTING_REQUEST;
				break;

			case PW_CODE_DISCONNECT_ACK:
			case PW_CODE_DISCONNECT_NAK:
				request->packet->code = PW_CODE_DISCONNECT_REQUEST;
				break;

			case PW_CODE_COA_ACK:
			case PW_CODE_COA_NAK:
				request->packet->code = PW_CODE_COA_REQUEST;
				break;

			default:
				REDEBUG("Can't determine expected Packet-Type for Response-Packet-Type %i",
					request->filter_code);
				goto error;
			}
		}

		/*
		 *	Automatically set the dst port (if one wasn't already set).
		 */
		if (request->packet->dst_port == 0) {
			radclient_get_port(request->packet->code, &request->packet->dst_port);
			if (request->packet->dst_port == 0) {
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
	return 1;

error:
	talloc_free(request);

	if (packets != stdin) fclose(packets);
	if (filters) fclose(filters);

	return 0;
}


/*
 *	Sanity check each argument.
 */
static int radclient_sane(rc_request_t *request)
{
	if (request->packet->dst_port == 0) {
		request->packet->dst_port = server_port;
	}
	if (request->packet->dst_ipaddr.af == AF_UNSPEC) {
		if (server_ipaddr.af == AF_UNSPEC) {
			ERROR("No server was given, and request %" PRIu64 " in file %s did not contain "
			      "Packet-Dst-IP-Address", request->num, request->files->packets);
			return -1;
		}
		request->packet->dst_ipaddr = server_ipaddr;
	}
	if (request->packet->code == 0) {
		if (packet_code == -1) {
			ERROR("Request was \"auto\", and request %" PRIu64 " in file %s did not contain Packet-Type",
			      request->num, request->files->packets);
			return -1;
		}
		request->packet->code = packet_code;
	}
	request->packet->sockfd = -1;

	return 0;
}


/*
 *	For request handling.
 */
static int filename_cmp(void const *one, void const *two)
{
	int cmp;

	rc_file_pair_t const *a = one;
	rc_file_pair_t const *b = two;

	cmp = strcmp(a->packets, b->packets);
	if (cmp != 0) return cmp;

	return strcmp(a->filters, b->filters);
}

static int filename_walk(UNUSED void *context, void *data)
{
	rc_file_pair_t *files = data;

	/*
	 *	Read request(s) from the file.
	 */
	if (!radclient_init(files, files)) return -1;	/* stop walking */

	return 0;
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
	fr_packet_list_id_free(pl, request->packet, true);

	/*
	 *	If we've already sent a packet, free up the old one,
	 *	and ensure that the next packet has a unique
	 *	authentication vector.
	 */
	if (request->packet->data) TALLOC_FREE(request->packet->data);
	if (request->reply) rad_free(&request->reply);
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
	if ((sleep_time == -1) || (sleep_time > (int) timeout)) sleep_time = (int) timeout;

	/*
	 *	Haven't sent the packet yet.  Initialize it.
	 */
	if (request->packet->id == -1) {
		int i;
		bool rcode;

		assert(request->reply == NULL);

		/*
		 *	Didn't find a free packet ID, we're not done,
		 *	we don't sleep, and we stop trying to process
		 *	this packet.
		 */
	retry:
		request->packet->src_ipaddr.af = server_ipaddr.af;
		rcode = fr_packet_list_id_alloc(pl, ipproto, &request->packet, NULL);
		if (!rcode) {
			int mysockfd;

#ifdef WITH_TCP
			if (proto) {
				mysockfd = fr_socket_client_tcp(NULL,
								&request->packet->dst_ipaddr,
								request->packet->dst_port, false);
			} else
#endif
			mysockfd = fr_socket(&client_ipaddr, 0);
			if (mysockfd < 0) {
				ERROR("Failed opening socket");
				exit(1);
			}
			if (!fr_packet_list_socket_add(pl, mysockfd, ipproto,
						       &request->packet->dst_ipaddr,
						       request->packet->dst_port, NULL)) {
				ERROR("Can't add new socket");
				exit(1);
			}
			goto retry;
		}

		assert(request->packet->id != -1);
		assert(request->packet->data == NULL);

		for (i = 0; i < 4; i++) {
			((uint32_t *) request->packet->vector)[i] = fr_rand();
		}

		/*
		 *	Update the password, so it can be encrypted with the
		 *	new authentication vector.
		 */
		if (request->password) {
			VALUE_PAIR *vp;

			if ((vp = fr_pair_find_by_num(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY)) != NULL) {
				fr_pair_value_strcpy(vp, request->password->vp_strvalue);

			} else if ((vp = fr_pair_find_by_num(request->packet->vps, PW_CHAP_PASSWORD, 0, TAG_ANY)) != NULL) {
				uint8_t buffer[17];

				rad_chap_encode(request->packet, buffer, fr_rand() & 0xff, request->password);
				fr_pair_value_memcpy(vp, buffer, 17);

			} else if (fr_pair_find_by_num(request->packet->vps, PW_MS_CHAP_PASSWORD, 0, TAG_ANY) != NULL) {
				mschapv1_encode(request->packet, &request->packet->vps, request->password->vp_strvalue);

			} else {
				DEBUG("WARNING: No password in the request");
			}
		}

		request->timestamp = time(NULL);
		request->tries = 1;
		request->resend++;

	} else {		/* request->packet->id >= 0 */
		time_t now = time(NULL);

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
			fr_packet_list_yank(pl, request->packet);

			REDEBUG("No reply from server for ID %d socket %d",
				request->packet->id, request->packet->sockfd);
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
	if (rad_send(request->packet, NULL, secret) < 0) {
		REDEBUG("Failed to send packet for ID %d", request->packet->id);
		deallocate_id(request);
		request->done = true;
		return -1;
	}

	if (fr_log_fp) {
		fr_packet_header_print(fr_log_fp, request->packet, false);
		if (fr_debug_lvl > 0) vp_printlist(fr_log_fp, request->packet->vps);
	}

	return 0;
}

/*
 *	Receive one packet, maybe.
 */
static int recv_one_packet(int wait_time)
{
	fd_set		set;
	struct timeval  tv;
	rc_request_t	*request;
	RADIUS_PACKET	*reply, **packet_p;
	volatile int max_fd;

	/* And wait for reply, timing out as necessary */
	FD_ZERO(&set);

	max_fd = fr_packet_list_fd_set(pl, &set);
	if (max_fd < 0) exit(1); /* no sockets to listen on! */

	tv.tv_sec = (wait_time <= 0) ? 0 : wait_time;
	tv.tv_usec = 0;

	/*
	 *	No packet was received.
	 */
	if (select(max_fd, &set, NULL, NULL, &tv) <= 0) return 0;

	/*
	 *	Look for the packet.
	 */
	reply = fr_packet_list_recv(pl, &set);
	if (!reply) {
		ERROR("Received bad packet");
#ifdef WITH_TCP
		/*
		 *	If the packet is bad, we close the socket.
		 *	I'm not sure how to do that now, so we just
		 *	die...
		 */
		if (proto) exit(1);
#endif
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
	reply->dst_ipaddr = client_ipaddr;
	reply->dst_port = client_port;

#ifdef WITH_TCP

	/*
	 *	TCP sockets don't use recvmsg(), and thus don't get
	 *	the source IP/port.  However, since they're TCP, we
	 *	know what the source IP/port is, because that's where
	 *	we connected to.
	 */
	if (ipproto == IPPROTO_TCP) {
		reply->src_ipaddr = server_ipaddr;
		reply->src_port = server_port;
	}
#endif

	packet_p = fr_packet_list_find_byreply(pl, reply);
	if (!packet_p) {
		ERROR("Received reply to request we did not send. (id=%d socket %d)",
		      reply->id, reply->sockfd);
		rad_free(&reply);
		return -1;	/* got reply to packet we didn't send */
	}
	request = fr_packet2myptr(rc_request_t, packet, packet_p);

	/*
	 *	Fails the signature validation: not a real reply.
	 *	FIXME: Silently drop it and listen for another packet.
	 */
	if (rad_verify(reply, request->packet, secret) < 0) {
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
	if (rad_decode(request->reply, request->packet, secret) != 0) {
		REDEBUG("Reply decode failed");
		stats.lost++;
		goto packet_done;
	}

	if (fr_log_fp) {
		fr_packet_header_print(fr_log_fp, request->reply, true);
		if (fr_debug_lvl > 0) vp_printlist(fr_log_fp, request->reply->vps);
	}

	/*
	 *	Increment counters...
	 */
	switch (request->reply->code) {
	case PW_CODE_ACCESS_ACCEPT:
	case PW_CODE_ACCOUNTING_RESPONSE:
	case PW_CODE_COA_ACK:
	case PW_CODE_DISCONNECT_ACK:
		stats.accepted++;
		break;

	case PW_CODE_ACCESS_CHALLENGE:
		break;

	default:
		stats.rejected++;
	}

	/*
	 *	If we had an expected response code, check to see if the
	 *	packet matched that.
	 */
	if ((request->filter_code != PW_CODE_UNDEFINED) && (request->reply->code != request->filter_code)) {
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
		VALUE_PAIR const *failed[2];

		fr_pair_list_sort(&request->reply->vps, fr_pair_cmp_by_da_tag);
		if (fr_pair_validate(failed, request->filter, request->reply->vps)) {
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
	rad_free(&request->reply);
	rad_free(&reply);	/* may be NULL */

	return 0;
}

int main(int argc, char **argv)
{
	int		c;
	char		const *radius_dir = RADDBDIR;
	char		const *dict_dir = DICTDIR;
	char		filesecret[256];
	FILE		*fp;
	int		do_summary = false;
	int		persec = 0;
	int		parallel = 1;
	rc_request_t	*this;
	int		force_af = AF_UNSPEC;

	/*
	 *	It's easier having two sets of flags to set the
	 *	verbosity of library calls and the verbosity of
	 *	radclient.
	 */
	fr_debug_lvl = 0;
	fr_log_fp = stdout;

#ifndef NDEBUG
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radclient");
		exit(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	filename_tree = rbtree_create(NULL, filename_cmp, NULL, 0);
	if (!filename_tree) {
	oom:
		ERROR("Out of memory");
		exit(1);
	}

	while ((c = getopt(argc, argv, "46c:d:D:f:Fhi:n:p:qr:sS:t:vx"
#ifdef WITH_TCP
		"P:"
#endif
			   )) != EOF) switch (c) {
		case '4':
			force_af = AF_INET;
			break;

		case '6':
			force_af = AF_INET6;
			break;

		case 'c':
			if (!isdigit((int) *optarg))
				usage();
			resend_count = atoi(optarg);
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'd':
			radius_dir = optarg;
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

		case 'i':	/* currently broken */
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

#ifdef WITH_TCP
		case 'P':
			proto = optarg;
			if (strcmp(proto, "tcp") != 0) {
				if (strcmp(proto, "udp") == 0) {
					proto = NULL;
				} else {
					usage();
				}
			} else {
				ipproto = IPPROTO_TCP;
			}
			break;

#endif

		case 'q':
			do_output = false;
			fr_log_fp = NULL; /* no output from you, either! */
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
			       exit(1);
			}
			if (fgets(filesecret, sizeof(filesecret), fp) == NULL) {
			       ERROR("Error reading %s: %s", optarg, fr_syserror(errno));
			       exit(1);
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
			       exit(1);
			}
			secret = filesecret;
		}
		       break;

		case 't':
			if (!isdigit((int) *optarg))
				usage();
			timeout = atof(optarg);
			break;

		case 'v':
			fr_debug_lvl = 1;
			DEBUG("%s", radclient_version);
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

	if ((argc < 3)  || ((secret == NULL) && (argc < 4))) {
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
	 *	Get the request type
	 */
	if (!isdigit((int) argv[2][0])) {
		packet_code = fr_str2int(request_types, argv[2], -2);
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
		if (fr_pton_port(&server_ipaddr, &server_port, argv[1], -1, force_af, true) < 0) {
			ERROR("%s", fr_strerror());
			exit(1);
		}

		/*
		 *	Work backwards from the port to determine the packet type
		 */
		if (packet_code == PW_CODE_UNDEFINED) packet_code = radclient_get_code(server_port);
	}
	radclient_get_port(packet_code, &server_port);

	/*
	 *	Add the secret.
	 */
	if (argv[3]) secret = argv[3];

	/*
	 *	If no '-f' is specified, we're reading from stdin.
	 */
	if (rbtree_num_elements(filename_tree) == 0) {
		rc_file_pair_t *files;

		files = talloc_zero(talloc_autofree_context(), rc_file_pair_t);
		files->packets = "-";
		if (!radclient_init(files, files)) {
			exit(1);
		}
	}

	/*
	 *	Walk over the list of filenames, creating the requests.
	 */
	if (rbtree_walk(filename_tree, RBTREE_IN_ORDER, filename_walk, NULL) != 0) {
		ERROR("Failed parsing input files");
		exit(1);
	}

	/*
	 *	No packets read.  Die.
	 */
	if (!request_head) {
		ERROR("Nothing to send");
		exit(1);
	}

	/*
	 *	Bind to the first specified IP address and port.
	 *	This means we ignore later ones.
	 */
	if (request_head->packet->src_ipaddr.af == AF_UNSPEC) {
		memset(&client_ipaddr, 0, sizeof(client_ipaddr));
		client_ipaddr.af = server_ipaddr.af;
	} else {
		client_ipaddr = request_head->packet->src_ipaddr;
	}

	client_port = request_head->packet->src_port;

#ifdef WITH_TCP
	if (proto) {
		sockfd = fr_socket_client_tcp(NULL, &server_ipaddr, server_port, false);
	} else
#endif
	sockfd = fr_socket(&client_ipaddr, client_port);
	if (sockfd < 0) {
		ERROR("Error opening socket");
		exit(1);
	}

	pl = fr_packet_list_create(1);
	if (!pl) {
		ERROR("Out of memory");
		exit(1);
	}

	if (!fr_packet_list_socket_add(pl, sockfd, ipproto, &server_ipaddr,
				       server_port, NULL)) {
		ERROR("Out of memory");
		exit(1);
	}

	/*
	 *	Walk over the list of packets, sanity checking
	 *	everything.
	 */
	for (this = request_head; this != NULL; this = this->next) {
		this->packet->src_ipaddr = client_ipaddr;
		this->packet->src_port = client_port;
		if (radclient_sane(this) != 0) {
			exit(1);
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
					struct timeval tv;

					/*
					 *	Don't sleep elsewhere.
					 */
					sleep_time = 0;

					if (persec == 1) {
						tv.tv_sec = 1;
						tv.tv_usec = 0;
					} else {
						tv.tv_sec = 0;
						tv.tv_usec = 1000000/persec;
					}

					/*
					 *	Sleep for milliseconds,
					 *	portably.
					 *
					 *	If we get an error or
					 *	a signal, treat it like
					 *	a normal timeout.
					 */
					select(0, NULL, NULL, NULL, &tv);
				}

				/*
				 *	If we haven't sent this packet
				 *	often enough, we're not done,
				 *	and we shouldn't sleep.
				 */
				if (this->resend < resend_count) {
					done = false;
					sleep_time = 0;
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
		if (fr_packet_list_num_elements(pl) > 0) {
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

	rbtree_free(filename_tree);
	fr_packet_list_free(pl);
	while (request_head) TALLOC_FREE(request_head);
	dict_free();

	if (do_summary) {
		printf("Packet summary:\n"
		       "\tAccepted      : %" PRIu64 "\n"
		       "\tRejected      : %" PRIu64 "\n"
		       "\tLost          : %" PRIu64 "\n"
		       "\tPassed filter : %" PRIu64 "\n"
		       "\tFailed filter : %" PRIu64 "\n",
		       stats.accepted,
		       stats.rejected,
		       stats.lost,
		       stats.passed,
		       stats.failed
		);
	}

	if ((stats.lost > 0) || (stats.failed > 0)) {
		exit(1);
	}
	exit(0);
}
