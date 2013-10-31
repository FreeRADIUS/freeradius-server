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
#include <freeradius-devel/conf.h>

#include <ctype.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#include <assert.h>

typedef struct REQUEST REQUEST;	/* to shut up warnings about mschap.h */

#include "smbdes.h"
#include "mschap.h"

static int success = 0;
static int retries = 3;
static float timeout = 5;
static char const *secret = NULL;
static int do_output = 1;
static int totalapp = 0;
static int totaldeny = 0;
static int totallost = 0;

static int server_port = 0;
static int packet_code = 0;
static fr_ipaddr_t server_ipaddr;
static int resend_count = 1;
static int done = 1;
static int print_filename = 0;

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

struct rc_request {
	rc_request_t	*prev;
	rc_request_t	*next;

	char const	*filename;

	int		request_number; /* in the file */
	char		password[256];
	time_t		timestamp;
	RADIUS_PACKET	*packet;
	RADIUS_PACKET	*reply;

	int		resend;
	int		tries;
	int		done;
};


static rc_request_t *request_head = NULL;
static rc_request_t *rc_request_tail = NULL;

char const *radclient_version = "radclient version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" RADIUSD_VERSION_COMMIT ")"
#endif
", built on " __DATE__ " at " __TIME__;

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "Usage: radclient [options] server[:port] <command> [<secret>]\n");

	fprintf(stderr, "  <command>     One of auth, acct, status, coa, or disconnect.\n");
	fprintf(stderr, "  -c <count>    Send each packet 'count' times.\n");
	fprintf(stderr, "  -d <raddb>    Set dictionary directory.\n");
	fprintf(stderr, "  -f <file>     Read packets from file, not stdin.\n");
	fprintf(stderr, "  -F            Print the file name, packet number and reply code.\n");
	fprintf(stderr, "  -h            Print usage help information.\n");
	fprintf(stderr, "  -i <id>       Set request id to 'id'.  Values may be 0..255\n");
	fprintf(stderr, "  -n <num>      Send N requests/s\n");
	fprintf(stderr, "  -p <num>      Send 'num' packets from a file in parallel.\n");
	fprintf(stderr, "  -q            Do not print anything out.\n");
	fprintf(stderr, "  -r <retries>  If timeout, retry sending the packet 'retries' times.\n");
	fprintf(stderr, "  -s            Print out summary information of auth results.\n");
	fprintf(stderr, "  -S <file>     read secret from file, not command line.\n");
	fprintf(stderr, "  -t <timeout>  Wait 'timeout' seconds before retrying (may be a floating point number).\n");
	fprintf(stderr, "  -v            Show program version information.\n");
	fprintf(stderr, "  -x            Debugging mode.\n");
	fprintf(stderr, "  -4            Use IPv4 address of server\n");
	fprintf(stderr, "  -6            Use IPv6 address of server.\n");
#ifdef WITH_TCP
	fprintf(stderr, "  -P <proto>    Use proto (tcp or udp) for transport.\n");
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
static int radclient_init(TALLOC_CTX *ctx, char const *filename)
{
	FILE *fp;
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	rc_request_t *request;
	int filedone = 0;
	int request_number = 1;

	assert(filename != NULL);

	/*
	 *	Determine where to read the VP's from.
	 */
	if (strcmp(filename, "-") != 0) {
		fp = fopen(filename, "r");
		if (!fp) {
			fprintf(stderr, "radclient: Error opening %s: %s\n",
				filename, strerror(errno));
			return 0;
		}
	} else {
		fp = stdin;
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
			goto oom;
		}
		talloc_set_destructor(request, _rc_request_free);

		request->packet = rad_alloc(request, 1);
		if (!request->packet) {
			goto oom;
		}

#ifdef WITH_TCP
		request->packet->src_ipaddr = client_ipaddr;
		request->packet->src_port = client_port;
		request->packet->dst_ipaddr = server_ipaddr;
		request->packet->dst_port = server_port;
#endif

		request->filename = filename;
		request->packet->id = -1; /* allocate when sending */
		request->request_number = request_number++;

		/*
		 *	Read the VP's.
		 */
		request->packet->vps = readvp2(request, fp, &filedone, "radclient:");
		if (!request->packet->vps) {
			talloc_free(request);

			if (fp != stdin) {
				fclose(fp);
			}
			return 1;
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
					uint8_t *p;

					p = talloc_array(vp, uint8_t, vp->length + 2);

					memcpy(p + 2, vp->vp_octets, vp->length);
					p[0] = vp->da->attr - PW_DIGEST_REALM + 1;
					vp->length += 2;
					p[1] = vp->length;

					pairmemsteal(vp, p);

					da = dict_attrbyvalue(PW_DIGEST_ATTRIBUTES, 0);
					if (!da) {
						goto oom;
					}

					vp->da = da;
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

	} while (!filedone); /* loop until the file is done. */

	if (fp != stdin) fclose(fp);

	/*
	 *	And we're done.
	 */
	return 1;

	oom:
	fprintf(stderr, "radclient: Out of memory\n");
	talloc_free(request);

	if (fp != stdin) fclose(fp);
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
			fprintf(stderr, "radclient: No server was given, but request %d in file %s did not contain Packet-Dst-IP-Address\n",
				request->request_number, request->filename);
			return -1;
		}
		request->packet->dst_ipaddr = server_ipaddr;
	}
	if (request->packet->code == 0) {
		if (packet_code == -1) {
			fprintf(stderr, "radclient: Request was \"auto\", but request %d in file %s did not contain Packet-Type\n",
				request->request_number, request->filename);
			return -1;
		}
		request->packet->code = packet_code;
	}
	request->packet->sockfd = -1;

	return 0;
}


/*
 *	For request handline.
 */
static int filename_cmp(void const *one, void const *two)
{
	return strcmp((char const *) one, (char const *) two);
}

static int filename_walk(UNUSED void *context, void *data)
{
	char const	*filename = data;

	/*
	 *	Read request(s) from the file.
	 */
	if (!radclient_init(NULL, filename)) {
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
	assert(request->done == 0);

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
				fprintf(stderr, "radclient: Can't open new socket: %s\n",
					strerror(errno));
				exit(1);
			}
			if (!fr_packet_list_socket_add(pl, mysockfd, ipproto,
						       &server_ipaddr,
						       server_port, NULL)) {
				fprintf(stderr, "radclient: Can't add new socket\n");
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
				int already_hex = 0;

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
							already_hex = 1;
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

			fprintf(stderr, "radclient: no reply from server for ID %d socket %d\n",
				request->packet->id, request->packet->sockfd);
			deallocate_id(request);

			/*
			 *	Normally we mark it "done" when we've received
			 *	the reply, but this is a special case.
			 */
			if (request->resend == resend_count) {
				request->done = 1;
			}
			totallost++;
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
		fprintf(stderr, "radclient: Failed to send packet for ID %d: %s\n",
			request->packet->id, fr_strerror());
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
		fprintf(stderr, "radclient: received bad packet: %s\n",
			fr_strerror());
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
		fprintf(stderr, "radclient: received reply to request we did not send. (id=%d socket %d)\n", reply->id, reply->sockfd);
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
		totallost++;
		goto packet_done; /* shared secret is incorrect */
	}

	if (print_filename) printf("%s:%d %d\n",
				   request->filename,
				   request->request_number,
				   reply->code);
	deallocate_id(request);
	request->reply = reply;
	reply = NULL;

	/*
	 *	If this fails, we're out of memory.
	 */
	if (rad_decode(request->reply, request->packet, secret) != 0) {
		fr_perror("rad_decode");
		totallost++;
		goto packet_done;
	}

	/* libradius debug already prints out the value pairs for us */
	if (!fr_debug_flag && do_output) {
		printf("Received reply ID %d, code %d, length = %zd\n",
		       request->reply->id, request->reply->code,
		       request->reply->data_len);
		vp_printlist(stdout, request->reply->vps);
	}

	if ((request->reply->code == PW_CODE_AUTHENTICATION_ACK) ||
	    (request->reply->code == PW_CODE_ACCOUNTING_RESPONSE) ||
	    (request->reply->code == PW_CODE_COA_ACK) ||
	    (request->reply->code == PW_CODE_DISCONNECT_ACK)) {
		success = 1;		/* have a good reply */
		totalapp++;
	} else {
		totaldeny++;
	}

	if (request->resend == resend_count) {
		request->done = 1;
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
	char *p;
	int c;
	char const *radius_dir = RADDBDIR;
	char filesecret[256];
	FILE *fp;
	int do_summary = 0;
	int persec = 0;
	int parallel = 1;
	rc_request_t	*this;
	int force_af = AF_UNSPEC;

	fr_debug_flag = 0;

	talloc_set_log_stderr();

	filename_tree = rbtree_create(filename_cmp, NULL, 0);
	if (!filename_tree) {
		fprintf(stderr, "radclient: Out of memory\n");
		exit(1);
	}

	while ((c = getopt(argc, argv, "46c:d:f:Fhi:n:p:qr:sS:t:vx"
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
		case 'd':
			radius_dir = optarg;
			break;
		case 'f':
			rbtree_insert(filename_tree, optarg);
			break;
		case 'F':
			print_filename = 1;
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
			do_output = 0;
			fr_log_fp = NULL; /* no output from you, either! */
			break;
		case 'r':
			if (!isdigit((int) *optarg))
				usage();
			retries = atoi(optarg);
			if ((retries == 0) || (retries > 1000)) usage();
			break;
		case 's':
			do_summary = 1;
			break;
		case 'S':
		       fp = fopen(optarg, "r");
		       if (!fp) {
			       fprintf(stderr, "radclient: Error opening %s: %s\n",
				       optarg, strerror(errno));
			       exit(1);
		       }
		       if (fgets(filesecret, sizeof(filesecret), fp) == NULL) {
			       fprintf(stderr, "radclient: Error reading %s: %s\n",
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
			       fprintf(stderr, "radclient: Secret in %s is too short\n", optarg);
			       exit(1);
		       }
		       secret = filesecret;
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

	if (dict_init(radius_dir, RADIUS_DICTIONARY) < 0) {
		fr_perror("radclient");
		return 1;
	}

	/*
	 *	Resolve hostname.
	 */
	if (force_af == AF_UNSPEC) force_af = AF_INET;
	server_ipaddr.af = force_af;
	if (strcmp(argv[1], "-") != 0) {
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
			fprintf(stderr, "radclient: Failed to find IP address for host %s: %s\n", hostname, strerror(errno));
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
		do_summary = 0;

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
		if (!radclient_init(NULL, "-")) {
			exit(1);
		}
	}

	/*
	 *	Walk over the list of filenames, creating the requests.
	 */
	if (rbtree_walk(filename_tree, InOrder, filename_walk, NULL) != 0) {
		fprintf(stderr, "Failed walking over filenames\n");
		exit(1);
	}

	/*
	 *	No packets read.  Die.
	 */
	if (!request_head) {
		fprintf(stderr, "radclient: Nothing to send.\n");
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
		fprintf(stderr, "radclient: socket: %s\n", fr_strerror());
		exit(1);
	}

	pl = fr_packet_list_create(1);
	if (!pl) {
		fprintf(stderr, "radclient: Out of memory\n");
		exit(1);
	}

	if (!fr_packet_list_socket_add(pl, sockfd, ipproto, &server_ipaddr,
				       server_port, NULL)) {
		fprintf(stderr, "radclient: Out of memory\n");
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

		done = 1;
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
			if (this->filename != filename) {
				filename = this->filename;
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
					done = 0;
					sleep_time = 0;
				}
			} else { /* haven't sent this packet, we're not done */
				assert(this->done == 0);
				assert(this->reply == NULL);
				done = 0;
			}
		}

		/*
		 *	Still have outstanding requests.
		 */
		if (fr_packet_list_num_elements(pl) > 0) {
			done = 0;
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
		printf("\n\t   Total approved auths:  %d\n", totalapp);
		printf("\t     Total denied auths:  %d\n", totaldeny);
		printf("\t       Total lost auths:  %d\n", totallost);
	}

	if (success) return 0;

	return 1;
}
