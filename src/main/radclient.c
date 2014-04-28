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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/radpaths.h>
#include <freeradius-devel/conf.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#include <assert.h>

typedef struct REQUEST REQUEST;	/* to shut up warnings about mschap.h */

#include "smbdes.h"
#include "mschap.h"

static int retries = 3;
static float timeout = 5;
static char const *secret = NULL;
static bool do_output = true;

typedef struct rc_stats {
	uint64_t accepted;		//!< Requests to which we received a accept
	uint64_t rejected;		//!< Requests to which we received a reject
	uint64_t lost;			//!< Requests to which we received no response
	uint64_t passed;		//!< Requests which passed a filter
	uint64_t failed;		//!< Requests which failed a fitler
} rc_stats_t;

static rc_stats_t stats;

static int server_port = 0;
static int packet_code = 0;
static fr_ipaddr_t server_ipaddr;
static int resend_count = 1;
static bool done = true;
static bool print_filename = false;

static fr_ipaddr_t client_ipaddr;
static int client_port = 0;

static int sockfd;
static int last_used_id = -1;

#ifdef WITH_TCP
char const *proto = NULL;
#endif
static int ipproto = IPPROTO_UDP;

static rbtree_t *filename_tree = NULL;
static fr_packet_list_t *pl = NULL;

static int sleep_time = -1;

typedef struct rc_request rc_request_t;

typedef struct rc_file_pair {
	char const *packets;		//!< The file containing the request packet
	char const *filters;		//!< The file containing the definition of the
					//!< packet we want to match.
} rc_file_pair_t;

struct rc_request {
	rc_request_t	*prev;
	rc_request_t	*next;

	rc_file_pair_t	*files;		//!< Request and response file names.

	int		request_number; //!< The number (within the file) of the request were reading.

	char		password[256];
	time_t		timestamp;

	RADIUS_PACKET	*packet;	//!< The outgoing request.
	PW_CODE		packet_code;	//!< The code in the outgoing request.
	RADIUS_PACKET	*reply;		//!< The incoming response.
	VALUE_PAIR	*filter;	//!< If the reply passes the filter, then the request passes.
	PW_CODE		filter_code;	//!< Expected code of the response packet.

	int		resend;
	int		tries;
	bool		done;		//!< Whether the request is complete.
};

static rc_request_t *request_head = NULL;
static rc_request_t *rc_request_tail = NULL;

char const *radclient_version = "radclient version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
", built on " __DATE__ " at " __TIME__;

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "Usage: radclient [options] server[:port] <command> [<secret>]\n");

	fprintf(stderr, "  <command>              One of auth, acct, status, coa, or disconnect.\n");
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

	challenge = paircreate(packet, PW_MSCHAP_CHALLENGE, VENDORPEC_MICROSOFT);
	if (!challenge) {
		return 0;
	}

	pairadd(request, challenge);
	challenge->length = 8;
	challenge->vp_octets = p = talloc_array(challenge, uint8_t, challenge->length);
	for (i = 0; i < challenge->length; i++) {
		p[i] = fr_rand();
	}

	reply = paircreate(packet, PW_MSCHAP_RESPONSE, VENDORPEC_MICROSOFT);
	if (!reply) {
		return 0;
	}

	pairadd(request, reply);
	reply->length = 50;
	reply->vp_octets = p = talloc_array(reply, uint8_t, reply->length);
	memset(p, 0, reply->length);

	p[1] = 0x01; /* NT hash */

	if (mschap_ntpwdhash(nthash, password) < 0) {
		return 0;
	}

	smbdes_mschap(nthash, challenge->vp_octets, p + 26);
	return 1;
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
	int request_number = 1;

	assert(files->packets != NULL);

	/*
	 *	Determine where to read the VP's from.
	 */
	if (strcmp(files->packets, "-") != 0) {
		packets = fopen(files->packets, "r");
		if (!packets) {
			fr_perror("radclient: Error opening %s: %s",
				  files->packets, strerror(errno));
			return 0;
		}

		/*
		 *	Read in the pairs representing the expected response.
		 */
		if (files->filters) {
			filters = fopen(files->filters, "r");
			if (!filters) {
				fr_perror("radclient: Error opening %s: %s",
					  files->filters, strerror(errno));
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
			fr_perror("radclient: Out of memory");
			goto error;
		}
		talloc_set_destructor(request, _rc_request_free);

		request->packet = rad_alloc(request, 1);
		if (!request->packet) {
			fr_perror("radclient: Out of memory");
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
		request->request_number = request_number++;

		/*
		 *	Read the request VP's.
		 */
		if (readvp2(&request->packet->vps, request->packet, packets, &packets_done) < 0) {
			goto error;
		}

		fr_cursor_init(&cursor, &request->filter);
		vp = fr_cursor_next_by_num(&cursor, PW_PACKET_TYPE, 0, TAG_ANY);
		if (vp) {
			fr_cursor_remove(&cursor);
			request->packet_code = vp->vp_integer;
			talloc_free(vp);
		} else {
			request->packet_code = packet_code; /* Use the default set on the command line */
		}

		/*
		 *	Read in filter VP's.
		 */
		if (filters) {
			bool filters_done;

			if (readvp2(&request->filter, request, filters, &filters_done) < 0) {
				goto error;
			}

			if (!request->filter) {
				goto error;
			}

			if (filters_done && !packets_done) {
				fr_perror("radclient: Differing number of packets/filters in %s:%s "
					  "(too many requests))", files->packets, files->filters);
				goto error;
			}

			if (!filters_done && packets_done) {
				fr_perror("radclient: Differing number of packets/filters in %s:%s "
					  "(too many filters))", files->packets, files->filters);
				goto error;
			}

			fr_cursor_init(&cursor, &request->filter);
			vp = fr_cursor_next_by_num(&cursor, PW_PACKET_TYPE, 0, TAG_ANY);
			if (vp) {
				fr_cursor_remove(&cursor);
				request->filter_code = vp->vp_integer;
				talloc_free(vp);
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
				}
			}

			/*
			 *	This allows efficient list comparisons later
			 */
			pairsort(&request->filter, attrtagcmp);
		}

		/*
		 *	Determine the response code from the request (if not already set)
		 */
		if (!request->filter_code) {
			switch (request->packet_code) {
			case PW_CODE_AUTHENTICATION_REQUEST:
				request->filter_code = PW_CODE_AUTHENTICATION_ACK;
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

			default:
				break;
			}
		}

		/*
		 *	Keep a copy of the the User-Password attribute.
		 */
		if ((vp = pairfind(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY)) != NULL) {
			strlcpy(request->password, vp->vp_strvalue,
				sizeof(request->password));
		/*
		 *	Otherwise keep a copy of the CHAP-Password attribute.
		 */
		} else if ((vp = pairfind(request->packet->vps, PW_CHAP_PASSWORD, 0, TAG_ANY)) != NULL) {
			strlcpy(request->password, vp->vp_strvalue,
				sizeof(request->password));

		} else if ((vp = pairfind(request->packet->vps, PW_MSCHAP_PASSWORD, 0, TAG_ANY)) != NULL) {
			strlcpy(request->password, vp->vp_strvalue,
				sizeof(request->password));
		} else {
			request->password[0] = '\0';
		}

		/*
		 *	Fix up Digest-Attributes issues
		 */
		for (vp = fr_cursor_init(&cursor, &request->packet->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			/*
			 *	Double quoted strings get marked up as xlat expansions,
			 *	but we don't support that in request.
			 */
			if (vp->type == VT_XLAT) {
				vp->vp_strvalue = vp->value.xlat;
				vp->value.xlat = NULL;
				vp->type = VT_DATA;
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

			case PW_PACKET_DST_PORT:
				request->packet->dst_port = (vp->vp_integer & 0xffff);
				break;

			case PW_PACKET_DST_IP_ADDRESS:
				request->packet->dst_ipaddr.af = AF_INET;
				request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
				break;

			case PW_PACKET_DST_IPV6_ADDRESS:
				request->packet->dst_ipaddr.af = AF_INET6;
				request->packet->dst_ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
				break;

			case PW_PACKET_SRC_PORT:
				request->packet->src_port = (vp->vp_integer & 0xffff);
				break;

			case PW_PACKET_SRC_IP_ADDRESS:
				request->packet->src_ipaddr.af = AF_INET;
				request->packet->src_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
				break;

			case PW_PACKET_SRC_IPV6_ADDRESS:
				request->packet->src_ipaddr.af = AF_INET6;
				request->packet->src_ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
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

					p = talloc_array(vp, uint8_t, vp->length + 2);

					memcpy(p + 2, vp->vp_octets, vp->length);
					p[0] = vp->da->attr - PW_DIGEST_REALM + 1;
					vp->length += 2;
					p[1] = vp->length;

					da = dict_attrbyvalue(PW_DIGEST_ATTRIBUTES, 0);
					if (!da) {
						fr_perror("radclient: Out of memory");
						goto error;
					}
					vp->da = da;

					/*
					 *	Re-do pairmemsteal ourselves,
					 *	because we play games with
					 *	vp->da, and pairmemsteal goes
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
			}
		} /* loop over the VP's we read in */

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
			fr_perror("radclient: No server was given, but request %d in file %s "
				  "did not contain Packet-Dst-IP-Address",
				  request->request_number, request->files->packets);
			return -1;
		}
		request->packet->dst_ipaddr = server_ipaddr;
	}
	if (request->packet->code == 0) {
		if (packet_code == -1) {
			fr_perror("radclient: Request was \"auto\", but request %d in file %s "
				  "did not contain Packet-Type",
				  request->request_number, request->files->packets);
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
	if (!radclient_init(files, files)) {
		return -1;	/* stop walking */
	}

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
	if (request->packet->data) {
		talloc_free(request->packet->data);
		request->packet->data = NULL;
	}

	if (request->reply) rad_free(&request->reply);
}


static void print_hex(RADIUS_PACKET *packet)
{
	int i;

	if (!packet->data) return;

	printf("  Code:\t\t%u\n", packet->data[0]);
	printf("  Id:\t\t%u\n", packet->data[1]);
	printf("  Length:\t%u\n", ((packet->data[2] << 8) |
				   (packet->data[3])));
	printf("  Vector:\t");
	for (i = 4; i < 20; i++) {
		printf("%02x", packet->data[i]);
	}
	printf("\n");

	if (packet->data_len > 20) {
		int total;
		uint8_t const *ptr;
		printf("  Data:");

		total = packet->data_len - 20;
		ptr = packet->data + 20;

		while (total > 0) {
			int attrlen;

			printf("\t\t");
			if (total < 2) { /* too short */
				printf("%02x\n", *ptr);
				break;
			}

			if (ptr[1] > total) { /* too long */
				for (i = 0; i < total; i++) {
					printf("%02x ", ptr[i]);
				}
				break;
			}

			printf("%02x  %02x  ", ptr[0], ptr[1]);
			attrlen = ptr[1] - 2;
			ptr += 2;
			total -= 2;

			for (i = 0; i < attrlen; i++) {
				if ((i > 0) && ((i & 0x0f) == 0x00))
					printf("\t\t\t");
				printf("%02x ", ptr[i]);
				if ((i & 0x0f) == 0x0f) printf("\n");
			}

			if ((attrlen & 0x0f) != 0x00) printf("\n");

			ptr += attrlen;
			total -= attrlen;
		}
	}
	fflush(stdout);
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
	if ((sleep_time == -1) || (sleep_time > (int) timeout)) {
		sleep_time = (int) timeout;
	}

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
		rcode = fr_packet_list_id_alloc(pl, ipproto,
						&request->packet, NULL);
		if (!rcode) {
			int mysockfd;

#ifdef WITH_TCP
			if (proto) {
				mysockfd = fr_tcp_client_socket(NULL,
								&server_ipaddr,
								server_port);
			} else
#endif
			mysockfd = fr_socket(&client_ipaddr, 0);
			if (mysockfd < 0) {
				fr_perror("radclient: Can't open new socket: %s",
					  strerror(errno));
				exit(1);
			}
			if (!fr_packet_list_socket_add(pl, mysockfd, ipproto,
						       &server_ipaddr,
						       server_port, NULL)) {
				fr_perror("radclient: Can't add new socket");
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
		if (request->password[0] != '\0') {
			VALUE_PAIR *vp;

			if ((vp = pairfind(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY)) != NULL) {
				pairstrcpy(vp, request->password);

			} else if ((vp = pairfind(request->packet->vps, PW_CHAP_PASSWORD, 0, TAG_ANY)) != NULL) {
				bool already_hex = false;

				/*
				 *	If it's 17 octets, it *might* be already encoded.
				 *	Or, it might just be a 17-character password (maybe UTF-8)
				 *	Check it for non-printable characters.  The odds of ALL
				 *	of the characters being 32..255 is (1-7/8)^17, or (1/8)^17,
				 *	or 1/(2^51), which is pretty much zero.
				 */
				if (vp->length == 17) {
					for (i = 0; i < 17; i++) {
						if (vp->vp_octets[i] < 32) {
							already_hex = true;
							break;
						}
					}
				}

				/*
				 *	Allow the user to specify ASCII or hex CHAP-Password
				 */
				if (!already_hex) {
					uint8_t *p;
					size_t len, len2;

					len = len2 = strlen(request->password);
					if (len2 < 17) len2 = 17;

					p = talloc_zero_array(vp, uint8_t, len2);

					memcpy(p, request->password, len);

					rad_chap_encode(request->packet,
							p,
							fr_rand() & 0xff, vp);
					vp->vp_octets = p;
					vp->length = 17;
				}
			} else if (pairfind(request->packet->vps, PW_MSCHAP_PASSWORD, 0, TAG_ANY) != NULL) {
				mschapv1_encode(request->packet,
						&request->packet->vps,
						request->password);
			} else if (fr_debug_flag) {
				printf("WARNING: No password in the request\n");
			}
		}

		request->timestamp = time(NULL);
		request->tries = 1;
		request->resend++;

#ifdef WITH_TCP
		/*
		 *	WTF?
		 */
		if (client_port == 0) {
			client_ipaddr = request->packet->src_ipaddr;
			client_port = request->packet->src_port;
		}
#endif

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

			fr_perror("radclient: no reply from server for ID %d socket %d",
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
		fr_perror("radclient: Failed to send packet for ID %d",
			  request->packet->id);
	}

	if (fr_debug_flag > 2) print_hex(request->packet);

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

	if (wait_time <= 0) {
		tv.tv_sec = 0;
	} else {
		tv.tv_sec = wait_time;
	}
	tv.tv_usec = 0;

	/*
	 *	No packet was received.
	 */
	if (select(max_fd, &set, NULL, NULL, &tv) <= 0) {
		return 0;
	}

	/*
	 *	Look for the packet.
	 */

	reply = fr_packet_list_recv(pl, &set);
	if (!reply) {
		fr_perror("radclient: received bad packet");
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
	 *	udpfromto issues.  We may have bound to "*",
	 *	and we want to find the replies that are sent to
	 *	(say) 127.0.0.1.
	 */
	reply->dst_ipaddr = client_ipaddr;
	reply->dst_port = client_port;
#ifdef WITH_TCP
	reply->src_ipaddr = server_ipaddr;
	reply->src_port = server_port;
#endif

	if (fr_debug_flag > 2) print_hex(reply);

	packet_p = fr_packet_list_find_byreply(pl, reply);
	if (!packet_p) {
		fr_perror("radclient: received reply to request we did not send. (id=%d socket %d)",
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
		fr_perror("rad_verify");
		stats.lost++;
		goto packet_done; /* shared secret is incorrect */
	}

	if (print_filename) {
		printf("%s:%d %d\n", request->files->packets, request->request_number, reply->code);
	}

	deallocate_id(request);
	request->reply = reply;
	reply = NULL;

	/*
	 *	If this fails, we're out of memory.
	 */
	if (rad_decode(request->reply, request->packet, secret) != 0) {
		fr_perror("rad_decode");
		stats.lost++;
		goto packet_done;
	}

	/* libradius debug already prints out the value pairs for us */
	if (!fr_debug_flag && do_output) {
		printf("Received reply ID %d, code %d, length = %zd\n",
		       request->reply->id, request->reply->code,
		       request->reply->data_len);
		vp_printlist(stdout, request->reply->vps);
	}

	/*
	 *	Increment counters...
	 */
	if ((request->reply->code == PW_CODE_AUTHENTICATION_ACK) ||
	    (request->reply->code == PW_CODE_ACCOUNTING_RESPONSE) ||
	    (request->reply->code == PW_CODE_COA_ACK) ||
	    (request->reply->code == PW_CODE_DISCONNECT_ACK)) {
		stats.accepted++;
	} else {
		stats.rejected++;
	}

	/*
	 *	If we had an expected response code, check to see if the
	 *	packet matched that.
	 */
	if (request->reply->code != request->filter_code) {
		if (is_radius_code(request->packet_code)) {
			printf("Expected %s got %s\n", fr_packet_codes[request->filter_code],
			       fr_packet_codes[request->reply->code]);
		} else {
			printf("Expected %u got %i\n", request->filter_code,
			       request->reply->code);
		}
		stats.failed++;
	/*
	 *	Check if the contents of the packet matched the filter
	 */
	} else if (!request->filter) {
		stats.passed++;
	} else {
		pairsort(&request->reply->vps, attrtagcmp);
		if (pairvalidate(request->filter, request->reply->vps)) {
			printf("Packet passed filter\n");
			stats.passed++;
		} else {
			printf("Packet failed filter\n");
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


static int getport(char const *name)
{
	struct	servent		*svp;

	svp = getservbyname (name, "udp");
	if (!svp) {
		return 0;
	}

	return ntohs(svp->s_port);
}

int main(int argc, char **argv)
{
	int c;
	char const *radius_dir = RADDBDIR;
	char const *dict_dir = DICTDIR;
	char filesecret[256];
	FILE *fp;
	int do_summary = false;
	int persec = 0;
	int parallel = 1;
	rc_request_t	*this;
	int force_af = AF_UNSPEC;

	fr_debug_flag = 0;

#ifndef NDEBUG
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radclient");
		exit(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	filename_tree = rbtree_create(filename_cmp, NULL, 0);
	if (!filename_tree) {
	oom:
		fr_perror("radclient: Out of memory");
		exit(1);
	}

	while ((c = getopt(argc, argv, "46c:d:D:f:Fhi:n:p:qr:sS:t:vx"
#ifdef WITH_TCP
		"P:"
#endif
			   )) != EOF) switch(c) {
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
			if (!isdigit((int) *optarg))
				usage();
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
			       fr_perror("radclient: Error opening %s: %s",
				         optarg, strerror(errno));
			       exit(1);
			}
			if (fgets(filesecret, sizeof(filesecret), fp) == NULL) {
			       fr_perror("radclient: Error reading %s: %s",
				         optarg, strerror(errno));
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
			       fr_perror("radclient: Secret in %s is too short", optarg);
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
			printf("%s\n", radclient_version);
			exit(0);
			break;
		case 'x':
			fr_debug_flag++;
			fr_log_fp = stdout;
			break;
		case 'h':
		default:
			usage();
			break;
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if ((argc < 3)  ||
	    ((secret == NULL) && (argc < 4))) {
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

	/*
	 *	Resolve hostname.
	 */
	if (force_af == AF_UNSPEC) force_af = AF_INET;
	server_ipaddr.af = force_af;
	if (strcmp(argv[1], "-") != 0) {
		char *p;
		char const *hostname = argv[1];
		char const *portname = argv[1];
		char buffer[256];

		if (*argv[1] == '[') { /* IPv6 URL encoded */
			p = strchr(argv[1], ']');
			if ((size_t) (p - argv[1]) >= sizeof(buffer)) {
				usage();
			}

			memcpy(buffer, argv[1] + 1, p - argv[1] - 1);
			buffer[p - argv[1] - 1] = '\0';

			hostname = buffer;
			portname = p + 1;

		}
		p = strchr(portname, ':');
		if (p && (strchr(p + 1, ':') == NULL)) {
			*p = '\0';
			portname = p + 1;
		} else {
			portname = NULL;
		}

		if (ip_hton(hostname, force_af, &server_ipaddr) < 0) {
			fr_perror("radclient: Failed to find IP address for host %s: %s\n", hostname, strerror(errno));
			exit(1);
		}

		/*
		 *	Strip port from hostname if needed.
		 */
		if (portname) server_port = atoi(portname);
	}

	/*
	 *	See what kind of request we want to send.
	 */
	if (strcmp(argv[2], "auth") == 0) {
		if (server_port == 0) server_port = getport("radius");
		if (server_port == 0) server_port = PW_AUTH_UDP_PORT;
		packet_code = PW_CODE_AUTHENTICATION_REQUEST;

	} else if (strcmp(argv[2], "challenge") == 0) {
		if (server_port == 0) server_port = getport("radius");
		if (server_port == 0) server_port = PW_AUTH_UDP_PORT;
		packet_code = PW_CODE_ACCESS_CHALLENGE;

	} else if (strcmp(argv[2], "acct") == 0) {
		if (server_port == 0) server_port = getport("radacct");
		if (server_port == 0) server_port = PW_ACCT_UDP_PORT;
		packet_code = PW_CODE_ACCOUNTING_REQUEST;
		do_summary = false;

	} else if (strcmp(argv[2], "status") == 0) {
		if (server_port == 0) server_port = getport("radius");
		if (server_port == 0) server_port = PW_AUTH_UDP_PORT;
		packet_code = PW_CODE_STATUS_SERVER;

	} else if (strcmp(argv[2], "disconnect") == 0) {
		if (server_port == 0) server_port = PW_COA_UDP_PORT;
		packet_code = PW_CODE_DISCONNECT_REQUEST;

	} else if (strcmp(argv[2], "coa") == 0) {
		if (server_port == 0) server_port = PW_COA_UDP_PORT;
		packet_code = PW_CODE_COA_REQUEST;

	} else if (strcmp(argv[2], "auto") == 0) {
		packet_code = -1;

	} else if (isdigit((int) argv[2][0])) {
		if (server_port == 0) server_port = getport("radius");
		if (server_port == 0) server_port = PW_AUTH_UDP_PORT;
		packet_code = atoi(argv[2]);
	} else {
		usage();
	}

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
		fr_perror("radclient: Failed parsing input files");
		exit(1);
	}

	/*
	 *	No packets read.  Die.
	 */
	if (!request_head) {
		fr_perror("radclient: Nothing to send");
		exit(1);
	}

	/*
	 *	Bind to the first specified IP address and port.
	 *	This means we ignore later ones.
	 */
	if (request_head->packet->src_ipaddr.af == AF_UNSPEC) {
		memset(&client_ipaddr, 0, sizeof(client_ipaddr));
		client_ipaddr.af = server_ipaddr.af;
		client_port = 0;
	} else {
		client_ipaddr = request_head->packet->src_ipaddr;
		client_port = request_head->packet->src_port;
	}
#ifdef WITH_TCP
	if (proto) {
		sockfd = fr_tcp_client_socket(NULL, &server_ipaddr, server_port);
	} else
#endif
	sockfd = fr_socket(&client_ipaddr, client_port);
	if (sockfd < 0) {
		fr_perror("radclient: socket");
		exit(1);
	}

	pl = fr_packet_list_create(1);
	if (!pl) {
		fr_perror("radclient: Out of memory");
		exit(1);
	}

	if (!fr_packet_list_socket_add(pl, sockfd, ipproto, &server_ipaddr,
				       server_port, NULL)) {
		fr_perror("radclient: Out of memory");
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
				send_one_packet(this);

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
	while (request_head) talloc_free(request_head);
	dict_free();

	if (do_summary) {
		printf("\tAccess-Accepts  : %" PRIu64 "\n"
		       "\tAccess-Rejects  : %" PRIu64 "\n"
		       "\tLost            : %" PRIu64 "\n"
		       "\tPassed filter   : %" PRIu64 "\n"
		       "\tFailed filter   : %" PRIu64 "\n",
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
