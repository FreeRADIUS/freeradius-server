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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */
static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_UNISTD_H
#	include <unistd.h>
#endif

#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/socket.h>

#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#	include <sys/select.h>
#endif

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#include <assert.h>

#include "conf.h"
#include "radpaths.h"
#include "missing.h"

static int retries = 10;
static float timeout = 3;
static const char *secret = NULL;
static int do_output = 1;
static int totalapp = 0;
static int totaldeny = 0;
static int totallost = 0;

static int server_port = 0;
static int packet_code = 0;
static uint32_t server_ipaddr = 0;
static int resend_count = 1;
static int done = 1;

static int sockfd;
static int radius_id[256];
static int last_used_id = 0;

static rbtree_t *filename_tree = NULL;
static rbtree_t *request_tree = NULL;

static int sleep_time = -1;

typedef struct radclient_t {
	struct		radclient_t *prev;
	struct		radclient_t *next;

	const char	*filename;
	int		packet_number; /* in the file */
	char		password[256];
	time_t		timestamp;
	RADIUS_PACKET	*request;
	RADIUS_PACKET	*reply;
	int		resend;
	int		tries;
	int		done;
} radclient_t;

static radclient_t *radclient_head = NULL;
static radclient_t *radclient_tail = NULL;


static void usage(void)
{
	fprintf(stderr, "Usage: radclient [options] server[:port] <command> [<secret>]\n");
	
	fprintf(stderr, "  <command>    One of auth, acct, status, or disconnect.\n");
	fprintf(stderr, "  -c count    Send each packet 'count' times.\n");
	fprintf(stderr, "  -d raddb    Set dictionary directory.\n");
	fprintf(stderr, "  -f file     Read packets from file, not stdin.\n");
	fprintf(stderr, "  -r retries  If timeout, retry sending the packet 'retries' times.\n");
	fprintf(stderr, "  -t timeout  Wait 'timeout' seconds before retrying (may be a floating point number).\n");
	fprintf(stderr, "  -i id       Set request id to 'id'.  Values may be 0..255\n");
	fprintf(stderr, "  -S file     read secret from file, not command line.\n");
	fprintf(stderr, "  -q          Do not print anything out.\n");
	fprintf(stderr, "  -s          Print out summary information of auth results.\n");
	fprintf(stderr, "  -v          Show program version information.\n");
	fprintf(stderr, "  -x          Debugging mode.\n");

	exit(1);
}

/*
 *	Free a radclient struct
 */
static void radclient_free(radclient_t *radclient)
{
	radclient_t *prev, *next;

	if (radclient->request) rad_free(&radclient->request);
	if (radclient->reply) rad_free(&radclient->reply);

	prev = radclient->prev;
	next = radclient->next;

	if (prev) {
		assert(radclient_head != radclient);
		prev->next = next;
	} else {
		assert(radclient_head == radclient);
		radclient_head = next;
	}
	
	if (next) {
		assert(radclient_tail != radclient);
		next->prev = prev;
	} else {
		assert(radclient_tail == radclient);
		radclient_tail = prev;
	}

	free(radclient);
}

/*
 *	Initialize a radclient data structure
 */
static radclient_t *radclient_init(const char *filename)
{
	FILE *fp;
	VALUE_PAIR *vp;
	radclient_t *start, *radclient, *prev = NULL;
	int filedone = 0;
	int packet_number = 1;

	start = NULL;

	/*
	 *	Determine where to read the VP's from.
	 */
	if (filename && (strcmp(filename, "-") != 0)) {
		fp = fopen(filename, "r");
		if (!fp) {
			fprintf(stderr, "radclient: Error opening %s: %s\n",
				filename, strerror(errno));
			return NULL;
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
		radclient = malloc(sizeof(*radclient));
		if (!radclient) {
			perror("radclient: ");
			return NULL; /* memory leak "start" */
		}
		memset(radclient, 0, sizeof(*radclient));
		
		radclient->request = rad_alloc(1);
		if (!radclient->request) {
			librad_perror("radclient: ");
			radclient_free(radclient);
			return NULL; /* memory leak "start" */
		}
		
		radclient->filename = filename;
		radclient->request->id = -1; /* allocate when sending */
		radclient->packet_number = packet_number++;
		
		/*
		 *	Read the VP's.
		 */
		radclient->request->vps = readvp2(fp, &filedone, "radclient:");
		if (!radclient->request->vps) {
			radclient_free(radclient);
			return NULL; /* memory leak "start" */
		}
		
		/*
		 *	Keep a copy of the the User-Password attribute.
		 */
		if ((vp = pairfind(radclient->request->vps, PW_PASSWORD)) != NULL) {
			strNcpy(radclient->password, (char *)vp->strvalue, sizeof(vp->strvalue));
			/*
			 *	Otherwise keep a copy of the CHAP-Password attribute.
			 */
		} else if ((vp = pairfind(radclient->request->vps, PW_CHAP_PASSWORD)) != NULL) {
			strNcpy(radclient->password, (char *)vp->strvalue, sizeof(vp->strvalue));
		} else {
			radclient->password[0] = '\0';
		}
		
		/*
		 *  Fix up Digest-Attributes issues
		 */
		for (vp = radclient->request->vps; vp != NULL; vp = vp->next) {
			switch (vp->attribute) {
			default:
				break;
				
				/*
				 *	Allow it to set the packet type in
				 *	the attributes read from the file.
				 */
			case PW_PACKET_TYPE:
				radclient->request->code = vp->lvalue;
				break;
				
			case PW_PACKET_DST_PORT:
				radclient->request->dst_port = (vp->lvalue & 0xffff);
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
				memmove(&vp->strvalue[2], &vp->strvalue[0], vp->length);
				vp->strvalue[0] = vp->attribute - PW_DIGEST_REALM + 1;
				vp->length += 2;
				vp->strvalue[1] = vp->length;
				vp->attribute = PW_DIGEST_ATTRIBUTES;
				break;
			}
		} /* loop over the VP's we read in */

		if (!start) {
			start = radclient;
			prev = start;
		} else {
			prev->next = radclient;
			radclient->prev = prev;
			prev = radclient;
		}
	} while (!filedone); /* loop until the file is done. */
	
	if (fp != stdin) fclose(fp);
	
	/*
	 *	And we're done.
	 */
	return start;
}


/*
 *	Sanity check each argument.
 */
static int radclient_sane(radclient_t *radclient)
{
	if (radclient->request->dst_port == 0) {
		radclient->request->dst_port = server_port;
	}
	radclient->request->dst_ipaddr = server_ipaddr;

	if (radclient->request->code == 0) {
		if (packet_code == -1) {
			fprintf(stderr, "radclient: Request was \"auto\", but request %d in file %s did not contain Packet-Type\n",
				radclient->packet_number, radclient->filename);
			return -1;
		}

		radclient->request->code = packet_code;
	}
	radclient->request->sockfd = sockfd;

	return 0;
}


/*
 *	For request handline.
 */
static int filename_cmp(const void *one, const void *two)
{
	return strcmp((const char *) one, (const char *) two);
}

static int filename_walk(void *data)
{
	const char	*filename = data;
	radclient_t	*radclient;

	/*
	 *	Initialize the request we're about
	 *	to send.
	 */
	radclient = radclient_init(filename);
	if (!radclient) {
		exit(1);
	}
	
	if (!radclient_head) {
		assert(radclient_tail == NULL);
		radclient_head = radclient;
	} else {
		assert(radclient_tail->next == NULL);
		radclient_tail->next = radclient;
		radclient->prev = radclient_tail;
	}

	/*
	 *	We may have had a list of "radclient" structures
	 *	returned to us.
	 */
	while (radclient->next) radclient = radclient->next;
	radclient_tail = radclient;

	return 0;
}


/*
 *	Compare two RADIUS_PACKET data structures, based on a number
 *	of criteria.
 */
static int request_cmp(const void *one, const void *two)
{
	const radclient_t *a = one;
	const radclient_t *b = two;

	/*
	 *	The following code looks unreasonable, but it's
	 *	the only way to make the comparisons work.
	 */
	if (a->request->id < b->request->id) return -1;
	if (a->request->id > b->request->id) return +1;

	if (a->request->dst_ipaddr < b->request->dst_ipaddr) return -1;
	if (a->request->dst_ipaddr > b->request->dst_ipaddr) return +1;

	if (a->request->dst_port < b->request->dst_port) return -1;
	if (a->request->dst_port > b->request->dst_port) return +1;

	/*
	 *	Everything's equal.  Say so.
	 */
	return 0;
}

/*
 *	"Free" a request.
 */
static void request_free(void *data)
{
	radclient_t *radclient = (radclient_t *) data;

	if (!radclient || !radclient->request ||
	    (radclient->request->id < 0)) {
		return;
	}

	/*
	 *	One more unused RADIUS ID.
	 */
	radius_id[radclient->request->id] = 0;
	radclient->request->id = -1;

	/*
	 *	If we've already sent a packet, free up the old one,
	 *	and ensure that the next packet has a unique
	 *	authentication vector.
	 */
	if (radclient->request->data) {
		free(radclient->request->data);
		radclient->request->data = NULL;
	}

	if (radclient->reply) rad_free(&radclient->reply);
}


/*
 *	Send one packet.
 */
static int send_one_packet(radclient_t *radclient)
{
	int i;

	/*
	 *	Sent this packet as many times as requested.
	 *	ignore it.
	 */
	if (radclient->resend >= resend_count) {
		radclient->done = 1;
		return 0;
	}

	/*
	 *	Remember when we have to wake up, to re-send the
	 *	request, of we didn't receive a response.
	 */
	if ((sleep_time == -1) ||
	    (sleep_time > (int) timeout)) {
		sleep_time = (int) timeout;
	}

	/*
	 *	Haven't sent the packet yet.  Initialize it.
	 */
	if (radclient->request->id == -1) {
		int found = 0;

		assert(radclient->reply == NULL);

		/*
		 *	Find a free packet Id
		 */
		for (i = 0; i < 256; i++) {
			if (radius_id[(last_used_id + i) & 0xff] == 0) {
				last_used_id = (last_used_id + i) & 0xff;
				radius_id[last_used_id] = 1;
				radclient->request->id = last_used_id++;
				found = 1;
				break;
			}
		}

		/*
		 *	Didn't find a free packet ID, we're not done,
		 *	we don't sleep, and we stop trying to process
		 *	this packet.
		 */
		if (!found) {
			done = 0;
			sleep_time = 0;
			return 0;
		}

		assert(radclient->request->id != -1);
		assert(radclient->request->data == NULL);
		
		librad_md5_calc(radclient->request->vector, radclient->request->vector,
				sizeof(radclient->request->vector));
		
		/*
		 *	Update the password, so it can be encrypted with the
		 *	new authentication vector.
		 */
		if (radclient->password[0] != '\0') {
			VALUE_PAIR *vp;

			if ((vp = pairfind(radclient->request->vps, PW_PASSWORD)) != NULL) {
				strNcpy((char *)vp->strvalue, radclient->password, strlen(radclient->password) + 1);
				vp->length = strlen(radclient->password);
				
			} else if ((vp = pairfind(radclient->request->vps, PW_CHAP_PASSWORD)) != NULL) {
				strNcpy((char *)vp->strvalue, radclient->password, strlen(radclient->password) + 1);
				vp->length = strlen(radclient->password);
				
				rad_chap_encode(radclient->request, (char *) vp->strvalue, radclient->request->id, vp);
				vp->length = 17;
			}
		}

		radclient->timestamp = time(NULL);
		radclient->tries = 1;
		radclient->resend++;

		/*
		 *	Duplicate found.  Serious error!
		 */
		if (rbtree_insert(request_tree, radclient) == 0) {
			assert(0 == 1);
		}

	} else if (radclient->tries == retries) {
		rbnode_t *node;
		assert(radclient->request->id >= 0);

		/*
		 *	Delete the request from the tree of outstanding
		 *	requests.
		 */
		node = rbtree_find(request_tree, radclient);
		assert(node != NULL);

		fprintf(stderr, "radclient: no response from server for ID %d\n", radclient->request->id);
		rbtree_delete(request_tree, node);
		totallost++;
		return -1;

		/*
		 *	FIXME: Do stuff for packet loss.
		 */

	} else {		/* radclient->request->id >= 0 */
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
		if ((now - radclient->timestamp) < timeout) {
			/*
			 *	When we walk over the tree sending
			 *	packets, we update the minimum time
			 *	required to sleep.
			 */
			if ((sleep_time == -1) ||
			    (sleep_time > (now - radclient->timestamp))) {
				sleep_time = now - radclient->timestamp;
			}
			return 0;
		}

		radclient->timestamp = now;
		radclient->tries++;
	}


	/*
	 *	Send the packet.
	 */
	rad_send(radclient->request, NULL, secret);

	return 0;
}

/*
 *	Receive one packet, maybe.
 */
static int recv_one_packet(int wait_time)
{
	fd_set		set;
	struct timeval  tv;
	radclient_t	myclient, *radclient;
	RADIUS_PACKET	myrequest, *reply;
	rbnode_t	*node;

	
	/* And wait for reply, timing out as necessary */
	FD_ZERO(&set);
	FD_SET(sockfd, &set);
	
	if (wait_time <= 0) {
		tv.tv_sec = 0;
	} else {
		tv.tv_sec = wait_time;
	}
	tv.tv_usec = 0;
	
	/*
	 *	No packet was received.
	 */
	if (select(sockfd + 1, &set, NULL, NULL, &tv) != 1) {
		return 0;
	}
	
	/*
	 *	Look for the packet.
	 */
	reply = rad_recv(sockfd);
	if (!reply) {
		fprintf(stderr, "radclient: received bad packet\n");
		return -1;	/* bad packet */
	}

	myclient.request = &myrequest;
	myrequest.id = reply->id;
	myrequest.dst_ipaddr = reply->src_ipaddr;
	myrequest.dst_port = reply->src_port;

	node = rbtree_find(request_tree, &myclient);
	if (!node) {
		fprintf(stderr, "radclient: received response to request we did not send.\n");
		return -1;	/* got reply to packet we didn't send */
	}

	radclient = rbtree_node2data(request_tree, node);
	assert(radclient != NULL);
	rbtree_delete(request_tree, node);
	assert(radclient->request->id == -1);
	assert(radclient->request->data == NULL);

	assert(radclient->reply == NULL);
	radclient->reply = reply;

	/*
	 *	FIXME: Do stuff to process the reply.
	 */
	if (rad_decode(reply, radclient->request, secret) != 0) {
		librad_perror("rad_decode");
		totallost++;
		return -1;
	}

	/* libradius debug already prints out the value pairs for us */
	if (!librad_debug && do_output) {
		printf("Received response ID %d, code %d, length = %d\n",
		       reply->id, reply->code, reply->data_len);
		vp_printlist(stdout, reply->vps);
	}
	if (reply->code != PW_AUTHENTICATION_REJECT) {
		totalapp++;
	} else {
		totaldeny++;
	}

	if (radclient->reply) rad_free(&radclient->reply);

	return 0;
}

/*
 *	Walk over the tree, sending packets.
 */
static int radclient_send(radclient_t *radclient)
{
	/*
	 *	Send the current packet.
	 */
	send_one_packet(radclient);

	/*
	 *	Do rad_recv(), and look for the response in the tree,
	 *	but don't wait for a response.
	 */
	recv_one_packet(0);

	/*
	 *	Still elements to wa
	 */
	if (radclient->resend < resend_count) {
		done = 0;
		sleep_time = 0;
	}

	return 0;
}

static int getport(const char *name)
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
	const char *radius_dir = RADDBDIR;
	char filesecret[256];
	FILE *fp;
	int do_summary = 0;
	int id;
	radclient_t	*this;

	id = ((int)getpid() & 0xff);
	librad_debug = 0;

	filename_tree = rbtree_create(filename_cmp, NULL, 0);
	if (!filename_tree) {
		fprintf(stderr, "radclient: Out of memory\n");
		exit(1);
	}

	request_tree = rbtree_create(request_cmp, request_free, 0);
	if (!request_tree) {
		fprintf(stderr, "radclient: Out of memory\n");
		exit(1);
	}

	while ((c = getopt(argc, argv, "c:d:f:hi:qst:r:S:xv")) != EOF) switch(c) {
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
		case 'q':
			do_output = 0;
			break;
		case 'x':
			librad_debug++;
			break;
		case 'r':
			if (!isdigit((int) *optarg)) 
				usage();
			retries = atoi(optarg);
			break;
		case 'i':
			if (!isdigit((int) *optarg)) 
				usage();
			id = atoi(optarg);
			if ((id < 0) || (id > 255)) {
				usage();
			}
			break;
		case 's':
			do_summary = 1;
			break;
		case 't':
			if (!isdigit((int) *optarg)) 
				usage();
			timeout = atof(optarg);
			break;
		case 'v':
			printf("radclient: $Id$ built on " __DATE__ " at " __TIME__ "\n");
			exit(0);
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
		librad_perror("radclient");
		return 1;
	}

	/*
	 *	Strip port from hostname if needed.
	 */
	if ((p = strchr(argv[1], ':')) != NULL) {
		*p++ = 0;
		server_port = atoi(p);
	}

	/*
	 *	Grab the socket.
	 */
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("radclient: socket: ");
		exit(1);
	}
	memset(radius_id, 0, sizeof(radius_id));

	/*
	 *	See what kind of request we want to send.
	 */
	if (strcmp(argv[2], "auth") == 0) {
		if (server_port == 0) server_port = getport("radius");
		if (server_port == 0) server_port = PW_AUTH_UDP_PORT;
		packet_code = PW_AUTHENTICATION_REQUEST;

	} else if (strcmp(argv[2], "acct") == 0) {
		if (server_port == 0) server_port = getport("radacct");
		if (server_port == 0) server_port = PW_ACCT_UDP_PORT;
		packet_code = PW_ACCOUNTING_REQUEST;
		do_summary = 0;

	} else if (strcmp(argv[2], "status") == 0) {
		if (server_port == 0) server_port = getport("radius");
		if (server_port == 0) server_port = PW_AUTH_UDP_PORT;
		packet_code = PW_STATUS_SERVER;

	} else if (strcmp(argv[2], "disconnect") == 0) {
		if (server_port == 0) server_port = PW_POD_UDP_PORT;
		packet_code = PW_DISCONNECT_REQUEST;

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
	 *	Resolve hostname.
	 */
	server_ipaddr = ip_getaddr(argv[1]);
	if (server_ipaddr == INADDR_NONE) {
		fprintf(stderr, "radclient: Failed to find IP address for host %s\n", argv[1]);
		exit(1);
	}

	/*
	 *	Add the secret.
	 */
	if (argv[3]) secret = argv[3];

	/*
	 *	Walk over the list of filenames, creating the requests.
	 */
	if (rbtree_walk(filename_tree, filename_walk, InOrder) != 0) {
		exit(1);
	}

	/*
	 *	No packets read.  Die.
	 */
	if (!radclient_head) {
		fprintf(stderr, "radclient: Nothing to send.\n");
		exit(1);
	}

	/*
	 *	Walk over the list of packets, sanity checking
	 *	everything.
	 */
	for (this = radclient_head; this != NULL; this = this->next) {
		if (radclient_sane(this) != 0) {
			exit(1);
		}
	}

	last_used_id = getpid() & 0xff;

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
		radclient_t *next;
		const char *filename = NULL;

		done = 1;
		sleep_time = -1;

		/*
		 *	Walk over the packets, sending them.
		 */
		
		for (this = radclient_head; this != NULL; this = next) {
			next = this->next;

			/*
			 *	Packets from multiple '-f' are sent
			 *	in parallel.  Packets from one file
			 *	are sent in series.
			 */
			if (this->filename != filename) {
				filename = this->filename;
				radclient_send(this);
				if (this->done) {
					radclient_free(this);
				}
			} else {
				assert(this->done == 0);
				assert(this->reply == NULL);
				done = 0;
			}
		}

		/*
		 *	Still have outstanding requests.
		 */
		if (rbtree_num_elements(request_tree) > 0) {
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
	rbtree_free(request_tree);

	if (do_summary) {
		printf("\n\t   Total approved auths:  %d\n", totalapp);
		printf("\t     Total denied auths:  %d\n", totaldeny);
		printf("\t       Total lost auths:  %d\n", totallost);
	}

	return 0;
}
