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
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/server/packet.h>
#include <freeradius-devel/radius/list.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/util/chap.h>
#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/md4.h>
#endif
#include <ctype.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <assert.h>

typedef struct request_s request_t;	/* to shut up warnings about mschap.h */

#include "smbdes.h"
#include "mschap.h"

#include "radclient.h"

#define pair_update_request(_attr, _da) do { \
		_attr = fr_pair_find_by_da(&request->request_pairs, NULL, _da); \
		if (!_attr) { \
			_attr = fr_pair_afrom_da(request, _da); \
			assert(_attr != NULL); \
			fr_pair_append(&request->request_pairs, _attr); \
		} \
	} while (0)

static int retries = 3;
static fr_time_delta_t timeout = fr_time_delta_wrap((int64_t)5 * NSEC);	/* 5 seconds */
static fr_time_delta_t sleep_time = fr_time_delta_wrap(-1);
static char *secret = NULL;
static bool do_output = true;

static const char *attr_coa_filter_name = "User-Name";

static rc_stats_t stats;

static uint16_t server_port = 0;
static int packet_code = FR_RADIUS_CODE_UNDEFINED;
static fr_ipaddr_t server_ipaddr;
static int resend_count = 1;
static int ignore_count = 0;
static bool done = true;
static bool print_filename = false;
static bool blast_radius = false;

static fr_ipaddr_t client_ipaddr;
static uint16_t client_port = 0;

static int sockfd;
static int last_used_id = -1;

static int ipproto = IPPROTO_UDP;

static bool do_coa = false;
static int coafd;
static uint16_t coa_port = FR_COA_UDP_PORT;
static fr_rb_tree_t *coa_tree = NULL;

static fr_packet_list_t *packet_list = NULL;

static fr_dlist_head_t rc_request_list;

static char const *radclient_version = RADIUSD_VERSION_BUILD("radclient");

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t radclient_dict[];
fr_dict_autoload_t radclient_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_cleartext_password;

static fr_dict_attr_t const *attr_ms_chap_challenge;
static fr_dict_attr_t const *attr_ms_chap_password;
static fr_dict_attr_t const *attr_ms_chap_response;

static fr_dict_attr_t const *attr_radclient_test_name;
static fr_dict_attr_t const *attr_request_authenticator;

static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_chap_challenge;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;
static fr_dict_attr_t const *attr_proxy_state;

static fr_dict_attr_t const *attr_radclient_coa_filename;
static fr_dict_attr_t const *attr_radclient_coa_filter;

static fr_dict_attr_t const *attr_coa_filter = NULL;

extern fr_dict_attr_autoload_t radclient_dict_attr[];
fr_dict_attr_autoload_t radclient_dict_attr[] = {
	{ .out = &attr_cleartext_password, .name = "Password.Cleartext", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_challenge, .name = "Vendor-Specific.Microsoft.CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_chap_password, .name = "Password.MS-CHAP", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ms_chap_response, .name = "Vendor-Specific.Microsoft.CHAP-Response", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ .out = &attr_radclient_test_name, .name = "Radclient-Test-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_request_authenticator, .name = "Request-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_freeradius },

	{ .out = &attr_radclient_coa_filename, .name = "Radclient-CoA-Filename", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_radclient_coa_filter, .name = "Radclient-CoA-Filter", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_chap_challenge, .name = "CHAP-Challenge", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_proxy_state, .name = "Proxy-State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	DICT_AUTOLOAD_TERMINATOR
};

static NEVER_RETURNS void usage(void)
{
	fprintf(stderr, "Usage: radclient [options] server[:port] <command> [<secret>]\n");

	fprintf(stderr, "  <command>                         One of auth, acct, status, coa, disconnect or auto.\n");
	fprintf(stderr, "  -4                                Use IPv4 address of server\n");
	fprintf(stderr, "  -6                                Use IPv6 address of server.\n");
	fprintf(stderr, "  -A <attribute>		     Use named 'attribute' to match CoA requests to packets.  Default is User-Name\n");
	fprintf(stderr, "  -b                                Mandate checks for Blast RADIUS issue (this is not set by default).\n");
	fprintf(stderr, "  -C [<client_ip>:]<client_port>    Client source port and source IP address.  Port values may be 1..65535\n");
	fprintf(stderr, "  -c <count>			     Send each packet 'count' times.\n");
	fprintf(stderr, "  -d <raddb>                        Set user dictionary directory (defaults to " RADDBDIR ").\n");
	fprintf(stderr, "  -D <dictdir>                      Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(stderr, "  -f <request>[:<expected>][:<coa_reply>][:<coa_expected>]  Read packets from file, not stdin.\n");
	fprintf(stderr, "                                    If a second file is provided, it will be used to verify responses\n");
	fprintf(stderr, "  -F                                Print the file name, packet number and reply code.\n");
	fprintf(stderr, "  -h                                Print usage help information.\n");
	fprintf(stderr, "  -i <id>                           Set request id to 'id'.  Values may be 0..255\n");
	fprintf(stderr, "  -n <num>                          Send N requests/s\n");
	fprintf(stderr, "  -o <port>                         Set CoA listening port (defaults to 3799)\n");
	fprintf(stderr, "  -p <num>                          Send 'num' packets from a file in parallel.\n");
	fprintf(stderr, "  -P <proto>                        Use proto (tcp or udp) for transport.\n");
	fprintf(stderr, "  -r <retries>                      If timeout, retry sending the packet 'retries' times.\n");
	fprintf(stderr, "  -s                                Print out summary information of auth results.\n");
	fprintf(stderr, "  -S <file>                         read secret from file, not command line.\n");
	fprintf(stderr, "  -t <timeout>                      Wait 'timeout' seconds before retrying (may be a floating point number).\n");
	fprintf(stderr, "  -v                                Show program version information.\n");
	fprintf(stderr, "  -x                                Debugging mode.\n");

	fr_exit_now(EXIT_SUCCESS);
}

/*
 *	Free a radclient struct, which may (or may not)
 *	already be in the list.
 */
static int _rc_request_free(rc_request_t *request)
{
	fr_dlist_remove(&rc_request_list, request);

	if (do_coa) (void) fr_rb_delete_by_inline_node(coa_tree, &request->node);

	return 0;
}

#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/provider.h>

static OSSL_PROVIDER *openssl_default_provider = NULL;
static OSSL_PROVIDER *openssl_legacy_provider = NULL;

static int openssl3_init(void)
{
	/*
	 *	Load the default provider for most algorithms
	 */
	openssl_default_provider = OSSL_PROVIDER_load(NULL, "default");
	if (!openssl_default_provider) {
		ERROR("(TLS) Failed loading default provider");
		return -1;
	}

	/*
	 *	Needed for MD4
	 *
	 *	https://www.openssl.org/docs/man3.0/man7/migration_guide.html#Legacy-Algorithms
	 */
	openssl_legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
	if (!openssl_legacy_provider) {
		ERROR("(TLS) Failed loading legacy provider");
		return -1;
	}

	fr_md5_openssl_init();
	fr_md4_openssl_init();

	return 0;
}

static void openssl3_free(void)
{
	if (openssl_default_provider && !OSSL_PROVIDER_unload(openssl_default_provider)) {
		ERROR("Failed unloading default provider");
	}
	openssl_default_provider = NULL;

	if (openssl_legacy_provider && !OSSL_PROVIDER_unload(openssl_legacy_provider)) {
		ERROR("Failed unloading legacy provider");
	}
	openssl_legacy_provider = NULL;

	fr_md5_openssl_free();
	fr_md4_openssl_free();
}
#else
#define openssl3_init()
#define openssl3_free()
#endif

static int mschapv1_encode(fr_packet_t *packet, fr_pair_list_t *list,
			   char const *password)
{
	unsigned int		i;
	uint8_t			*p;
	fr_pair_t		*challenge, *reply;
	uint8_t			nthash[16];

	fr_pair_delete_by_da(list, attr_ms_chap_challenge);
	fr_pair_delete_by_da(list, attr_ms_chap_response);

	MEM(challenge = fr_pair_afrom_da(packet, attr_ms_chap_challenge));

	fr_pair_append(list, challenge);

	MEM(p = talloc_array(challenge, uint8_t, 8));
	fr_pair_value_memdup_buffer_shallow(challenge, p, false);

	for (i = 0; i < challenge->vp_length; i++) {
		p[i] = fr_rand();
	}

	MEM(reply = fr_pair_afrom_da(packet, attr_ms_chap_response));
	fr_pair_append(list, reply);
	p = talloc_zero_array(reply, uint8_t, 50); /* really reply->da->flags.length */
	fr_pair_value_memdup_buffer_shallow(reply, p, false);

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
static void radclient_get_port(fr_radius_packet_code_t type, uint16_t *port)
{
	switch (type) {
	default:
	case FR_RADIUS_CODE_ACCESS_REQUEST:
	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
	case FR_RADIUS_CODE_STATUS_SERVER:
		if (*port == 0) *port = getport("radius");
		if (*port == 0) *port = FR_AUTH_UDP_PORT;
		return;

	case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
		if (*port == 0) *port = getport("radacct");
		if (*port == 0) *port = FR_ACCT_UDP_PORT;
		return;

	case FR_RADIUS_CODE_DISCONNECT_REQUEST:
		if (*port == 0) *port = FR_POD_UDP_PORT;
		return;

	case FR_RADIUS_CODE_COA_REQUEST:
		if (*port == 0) *port = FR_COA_UDP_PORT;
		return;

	case FR_RADIUS_CODE_UNDEFINED:
		if (*port == 0) *port = 0;
		return;
	}
}

/*
 *	Resolve a port to a request type
 */
static fr_radius_packet_code_t radclient_get_code(uint16_t port)
{
	/*
	 *	getport returns 0 if the service doesn't exist
	 *	so we need to return early, to avoid incorrect
	 *	codes.
	 */
	if (port == 0) return FR_RADIUS_CODE_UNDEFINED;

	if ((port == getport("radius")) || (port == FR_AUTH_UDP_PORT) || (port == FR_AUTH_UDP_PORT_ALT)) {
		return FR_RADIUS_CODE_ACCESS_REQUEST;
	}
	if ((port == getport("radacct")) || (port == FR_ACCT_UDP_PORT) || (port == FR_ACCT_UDP_PORT_ALT)) {
		return FR_RADIUS_CODE_ACCOUNTING_REQUEST;
	}
	if (port == FR_COA_UDP_PORT) return FR_RADIUS_CODE_COA_REQUEST;

	return FR_RADIUS_CODE_UNDEFINED;
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
 *	Read one CoA reply and possibly filter
 */
static int coa_init(rc_request_t *parent, FILE *coa_reply, char const *reply_filename, bool *coa_reply_done, FILE *coa_filter, char const *filter_filename, bool *coa_filter_done)
{
	rc_request_t	*request;
	fr_pair_t	*vp;

	/*
	 *	Allocate it.
	 */
	MEM(request = talloc_zero(parent, rc_request_t));
	MEM(request->reply = fr_packet_alloc(request, false));

	/*
	 *	Don't initialize src/dst IP/port, or anything else.  That will be read from the network.
	 */
	fr_pair_list_init(&request->filter);
	fr_pair_list_init(&request->request_pairs);
	fr_pair_list_init(&request->reply_pairs);

	/*
	 *	Read the reply VP's.
	 */
	if (fr_pair_list_afrom_file(request, dict_radius,
				    &request->reply_pairs, coa_reply, coa_reply_done) < 0) {
		REDEBUG("Error parsing \"%s\"", reply_filename);
	error:
		talloc_free(request);
		return -1;
	}

	/*
	 *	The reply can be empty.  In which case we just send an empty ACK.
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_packet_type);
	if (vp) request->reply->code = vp->vp_uint32;

	/*
	 *	Read in filter VP's.
	 */
	if (coa_filter) {
		if (fr_pair_list_afrom_file(request, dict_radius,
					    &request->filter, coa_filter, coa_filter_done) < 0) {
			REDEBUG("Error parsing \"%s\"", filter_filename);
			goto error;
		}

		if (*coa_filter_done && !*coa_reply_done) {
			REDEBUG("Differing number of replies/filters in %s:%s "
				"(too many replies))", reply_filename, filter_filename);
			goto error;
		}

		if (!*coa_filter_done && *coa_reply_done) {
			REDEBUG("Differing number of replies/filters in %s:%s "
				"(too many filters))", reply_filename, filter_filename);
			goto error;
		}

		/*
		 *	This allows efficient list comparisons later
		 */
		fr_pair_list_sort(&request->filter, fr_pair_cmp_by_da);
	}

	request->name = parent->name;

	/*
	 *	Automatically set the response code from the request code
	 *	(if one wasn't already set).
	 */
	if (request->filter_code == FR_RADIUS_CODE_UNDEFINED) {
		request->filter_code = FR_RADIUS_CODE_COA_REQUEST;
	}

	parent->coa = request;

	/*
	 *	Ensure that the packet is also tracked in the CoA tree.
	 */
	fr_assert(coa_tree);
	if (!fr_rb_insert(coa_tree, parent)) {
		ERROR("Failed inserting packet from %s into CoA tree", request->name);
		fr_exit_now(1);
	}

	return 0;
}

/*
 *	Initialize a radclient data structure and add it to
 *	the global linked list.
 */
static int radclient_init(TALLOC_CTX *ctx, rc_file_pair_t *files)
{
	FILE		*packets, *filters = NULL;

	fr_pair_t	*vp;
	rc_request_t	*request = NULL;
	bool		packets_done = false;
	uint64_t	num = 0;

	FILE		*coa_reply = NULL;
	FILE		*coa_filter = NULL;
	bool		coa_reply_done = false;
	bool		coa_filter_done = false;

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
				goto error;
			}
		}

		if (files->coa_reply) {
			coa_reply = fopen(files->coa_reply, "r");
			if (!coa_reply) {
				ERROR("Error opening %s: %s", files->coa_reply, fr_syserror(errno));
				goto error;
			}
		}

		if (files->coa_filter) {
			coa_filter = fopen(files->coa_filter, "r");
			if (!coa_filter) {
				ERROR("Error opening %s: %s", files->coa_filter, fr_syserror(errno));
				goto error;
			}
		}
	} else {
		packets = stdin;
	}

	/*
	 *	Loop until the file is done.
	 */
	do {
		char const *coa_reply_filename = NULL;
		char const *coa_filter_filename = NULL;

		/*
		 *	Allocate it.
		 */
		MEM(request = talloc_zero(ctx, rc_request_t));
		MEM(request->packet = fr_packet_alloc(request, true));
		request->packet->uctx = request;

		request->packet->socket.inet.src_ipaddr = client_ipaddr;
		request->packet->socket.inet.src_port = client_port;
		request->packet->socket.inet.dst_ipaddr = server_ipaddr;
		request->packet->socket.inet.dst_port = server_port;
		request->packet->socket.type = (ipproto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;

		request->files = files;
		request->packet->id = last_used_id;
		request->num = num++;

		fr_pair_list_init(&request->filter);
		fr_pair_list_init(&request->request_pairs);
		fr_pair_list_init(&request->reply_pairs);

		/*
		 *	Read the request VP's.
		 */
		if (fr_pair_list_afrom_file(request, dict_radius,
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
		if (fr_pair_list_empty(&request->request_pairs)) {
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

			vp = fr_pair_find_by_da(&request->filter, NULL, attr_packet_type);
			if (vp) {
				request->filter_code = vp->vp_uint32;
				fr_pair_delete(&request->filter, vp);
			}

			/*
			 *	This allows efficient list comparisons later
			 */
			fr_pair_list_sort(&request->filter, fr_pair_cmp_by_da);
		}

		/*
		 *	Process special attributes
		 */
		for (vp = fr_pair_list_head(&request->request_pairs);
		     vp;
		     vp = fr_pair_list_next(&request->request_pairs, vp)) {
			/*
			 *	Allow it to set the packet type in
			 *	the attributes read from the file.
			 */
			if (vp->da == attr_packet_type) {
				request->packet->code = vp->vp_uint32;
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
				pair_update_request(request->password, attr_cleartext_password);
				fr_pair_value_bstrndup(request->password, vp->vp_strvalue, vp->vp_length, true);
			} else if (vp->da == attr_ms_chap_password) {
				pair_update_request(request->password, attr_cleartext_password);
				fr_pair_value_bstrndup(request->password, vp->vp_strvalue, vp->vp_length, true);

			} else if (vp->da == attr_radclient_test_name) {
				request->name = vp->vp_strvalue;

			} else if (vp->da == attr_radclient_coa_filename) {
				coa_reply_filename = vp->vp_strvalue;

			} else if (vp->da == attr_radclient_coa_filter) {
				coa_filter_filename = vp->vp_strvalue;
			}
		} /* loop over the VP's we read in */

		/*
		 *	Use the default set on the command line
		 */
		if (request->packet->code == FR_RADIUS_CODE_UNDEFINED) request->packet->code = packet_code;

		/*
		 *	Fill in the packet header from attributes, and then
		 *	re-realize the attributes.
		 */
		fr_packet_net_from_pairs(request->packet, &request->request_pairs);

		/*
		 *	Default to the filename
		 */
		if (!request->name) request->name = request->files->packets;

		/*
		 *	Automatically set the response code from the request code
		 *	(if one wasn't already set).
		 */
		if (request->filter_code == FR_RADIUS_CODE_UNDEFINED) {
			switch (request->packet->code) {
			case FR_RADIUS_CODE_ACCESS_REQUEST:
				request->filter_code = FR_RADIUS_CODE_ACCESS_ACCEPT;
				break;

			case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
				request->filter_code = FR_RADIUS_CODE_ACCOUNTING_RESPONSE;
				break;

			case FR_RADIUS_CODE_COA_REQUEST:
				request->filter_code = FR_RADIUS_CODE_COA_ACK;
				break;

			case FR_RADIUS_CODE_DISCONNECT_REQUEST:
				request->filter_code = FR_RADIUS_CODE_DISCONNECT_ACK;
				break;

			case FR_RADIUS_CODE_STATUS_SERVER:
				switch (radclient_get_code(request->packet->socket.inet.dst_port)) {
				case FR_RADIUS_CODE_ACCESS_REQUEST:
					request->filter_code = FR_RADIUS_CODE_ACCESS_ACCEPT;
					break;

				case FR_RADIUS_CODE_ACCOUNTING_REQUEST:
					request->filter_code = FR_RADIUS_CODE_ACCOUNTING_RESPONSE;
					break;

				default:
					request->filter_code = FR_RADIUS_CODE_UNDEFINED;
					break;
				}
				break;

			case FR_RADIUS_CODE_UNDEFINED:
				REDEBUG("Packet-Type must be defined,"
					"or a well known RADIUS port");
				goto error;

			default:
				REDEBUG("Can't determine expected reply.Packet-Type for Packet-Type %i",
					request->packet->code);
				goto error;
			}
		/*
		 *	Automatically set the request code from the response code
		 *	(if one wasn't already set).
		 */
		} else if (request->packet->code == FR_RADIUS_CODE_UNDEFINED) {
			switch (request->filter_code) {
			case FR_RADIUS_CODE_ACCESS_ACCEPT:
			case FR_RADIUS_CODE_ACCESS_REJECT:
				request->packet->code = FR_RADIUS_CODE_ACCESS_REQUEST;
				break;

			case FR_RADIUS_CODE_ACCOUNTING_RESPONSE:
				request->packet->code = FR_RADIUS_CODE_ACCOUNTING_REQUEST;
				break;

			case FR_RADIUS_CODE_DISCONNECT_ACK:
			case FR_RADIUS_CODE_DISCONNECT_NAK:
				request->packet->code = FR_RADIUS_CODE_DISCONNECT_REQUEST;
				break;

			case FR_RADIUS_CODE_COA_ACK:
			case FR_RADIUS_CODE_COA_NAK:
				request->packet->code = FR_RADIUS_CODE_COA_REQUEST;
				break;

			default:
				REDEBUG("Can't determine expected Packet-Type for reply.Packet-Type %i",
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
		 *	Read in the CoA filename and filter.
		 */
		if (coa_reply_filename) {
			if (coa_reply) {
				RDEBUG("Cannot specify CoA file on both the command line and via Radclient-CoA-Filename");
				goto error;
			}

			coa_reply = fopen(coa_reply_filename, "r");
			if (!coa_reply) {
				ERROR("Error opening %s: %s", coa_reply_filename, fr_syserror(errno));
				goto error;
			}

			if (coa_filter_filename) {
				coa_filter = fopen(coa_filter_filename, "r");
				if (!coa_filter) {
					ERROR("Error opening %s: %s", coa_filter_filename, fr_syserror(errno));
					goto error;
				}
			} else {
				coa_filter = NULL;
			}

			if (coa_init(request, coa_reply, coa_reply_filename, &coa_reply_done,
				     coa_filter, coa_filter_filename, &coa_filter_done) < 0) {
				goto error;
			}

			fclose(coa_reply);
			coa_reply = NULL;
			if (coa_filter) {
				fclose(coa_filter);
				coa_filter = NULL;
			}
			do_coa = true;

		} else if (coa_reply) {
			if (coa_init(request, coa_reply, coa_reply_filename, &coa_reply_done,
				     coa_filter, coa_filter_filename, &coa_filter_done) < 0) {
				goto error;
			}

			if (coa_reply_done != packets_done) {
				REDEBUG("Differing number of packets in input file and coa_reply in %s:%s ",
				        files->packets, files->coa_reply);
				goto error;

			}
		}

		/*
		 *	Add it to the tail of the list.
		 */
		fr_dlist_insert_tail(&rc_request_list, request);

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
	if (coa_reply) fclose(coa_reply);
	if (coa_filter) fclose(coa_filter);

	/*
	 *	And we're done.
	 */
	return 0;

error:
	talloc_free(request);

	if (packets != stdin) fclose(packets);
	if (filters) fclose(filters);
	if (coa_reply) fclose(coa_reply);
	if (coa_filter) fclose(coa_filter);

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


static int8_t request_cmp(void const *one, void const *two)
{
	rc_request_t const *a = one, *b = two;
	fr_pair_t *vp1, *vp2;

	vp1 = fr_pair_find_by_da(&a->request_pairs, NULL, attr_coa_filter);
	vp2 = fr_pair_find_by_da(&b->request_pairs, NULL, attr_coa_filter);

	if (!vp1) return -1;
	if (!vp2) return +1;

	return fr_value_box_cmp(&vp1->data, &vp2->data);
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
	if (request->reply) fr_packet_free(&request->reply);
}

/*
 *	Send one packet.
 */
static int send_one_packet(rc_request_t *request)
{
	assert(request->done == false);

#ifdef STATIC_ANALYZER
	if (!secret) fr_exit_now(1);
#endif

	/*
	 *	Remember when we have to wake up, to re-send the
	 *	request, of we didn't receive a reply.
	 */
	if ((fr_time_delta_eq(sleep_time, fr_time_delta_wrap(-1)) || (fr_time_delta_gt(sleep_time, timeout)))) {
		sleep_time = timeout;
	}

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
		rcode = fr_packet_list_id_alloc(packet_list, ipproto, request->packet, NULL);
		if (!rcode) {
			int mysockfd;

			if (ipproto == IPPROTO_TCP) {
				mysockfd = fr_socket_client_tcp(NULL, NULL,
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

				if (fr_socket_bind(mysockfd, NULL, &client_ipaddr, &port) < 0) {
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

			if ((vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_chap_password)) != NULL) {
				uint8_t		buffer[17];
				fr_pair_t	*challenge;

				/*
				 *	Use CHAP-Challenge pair if present, otherwise create CHAP-Challenge and
				 *	populate with current Request Authenticator.
				 *
				 *	Request Authenticator is re-calculated by fr_packet_sign
				 */
				challenge = fr_pair_find_by_da(&request->request_pairs, NULL, attr_chap_challenge);
				if (!challenge || (challenge->vp_length < 7)) {
					pair_update_request(challenge, attr_chap_challenge);
					fr_pair_value_memdup(challenge, request->packet->vector, RADIUS_AUTH_VECTOR_LENGTH, false);
				}

				fr_chap_encode(buffer,
					       fr_rand() & 0xff, challenge->vp_octets, challenge->vp_length,
					       request->password->vp_strvalue,
					       request->password->vp_length);
				fr_pair_value_memdup(vp, buffer, sizeof(buffer), false);

			} else if (fr_pair_find_by_da_nested(&request->request_pairs, NULL, attr_ms_chap_password) != NULL) {
				mschapv1_encode(request->packet, &request->request_pairs, request->password->vp_strvalue);

			} else {
				DEBUG("WARNING: No password in the request");
			}
		}

		request->timestamp = fr_time();
		request->tries = 1;
		request->resend++;

	} else {		/* request->packet->id >= 0 */
		fr_time_t now = fr_time();

		/*
		 *	FIXME: Accounting packets are never retried!
		 *	The Acct-Delay-Time attribute is updated to
		 *	reflect the delay, and the packet is re-sent
		 *	from scratch!
		 */

		/*
		 *	Not time for a retry, do so.
		 */
		if (fr_time_delta_lt(fr_time_sub(now, request->timestamp), timeout)) {
			/*
			 *	When we walk over the tree sending
			 *	packets, we update the minimum time
			 *	required to sleep.
			 */
			if (fr_time_delta_eq(sleep_time, fr_time_delta_wrap(-1)) ||
			    fr_time_delta_gt(sleep_time, fr_time_sub(now, request->timestamp))) {
				sleep_time = fr_time_sub(now, request->timestamp);
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
	if (fr_packet_send(request->packet, &request->request_pairs, NULL, secret) < 0) {
		REDEBUG("Failed to send packet for ID %d", request->packet->id);
		deallocate_id(request);
		request->done = true;
		return -1;
	}

	fr_radius_packet_log(&default_log, request->packet, &request->request_pairs, false);

	return 0;
}

/*
 *	Receive a CoA packet, maybe.
 */
static int recv_coa_packet(fr_time_delta_t wait_time)
{
	fd_set			set;
	fr_time_delta_t		our_wait_time;
	rc_request_t		*request, *parent;
	fr_packet_t		*packet;
	rc_request_t		my;

#ifdef STATIC_ANALYZER
	if (!secret) fr_exit_now(1);
#endif

	/* And wait for reply, timing out as necessary */
	FD_ZERO(&set);
	FD_SET(coafd, &set);

	our_wait_time = !fr_time_delta_ispos(wait_time) ? fr_time_delta_from_sec(0) : wait_time;

	/*
	 *	No packet was received.
	 */
	if (select(coafd + 1, &set, NULL, NULL, &fr_time_delta_to_timeval(our_wait_time)) <= 0) return 0;

	/*
	 *	Read a packet from a network.
	 */
	packet = fr_packet_recv(NULL, coafd, 0, 200, false);
	if (!packet) {
		DEBUG("Failed reading CoA packet");
		return 0;
	}

	/*
	 *	Fails the signature validation: not a real reply.
	 */
	if (fr_packet_verify(packet, NULL, secret) < 0) {
		DEBUG("CoA verification failed");
		return 0;
	}

	fr_pair_list_init(&my.request_pairs);

	/*
	 *	Decode the packet before looking up the parent, so that we can compare the pairs.
	 */
	if (fr_radius_decode_simple(packet, &my.request_pairs,
				    packet->data, packet->data_len,
				    NULL, secret) < 0) {
		DEBUG("Failed decoding CoA packet");
		return 0;
	}

	fr_radius_packet_log(&default_log, packet, &my.request_pairs, true);

	/*
	 *	Find a Access-Request which has the same User-Name / etc. as this CoA packet.
	 */
	my.name = "receive CoA request";
	my.packet = packet;

	parent = fr_rb_find(coa_tree, &my);
	if (!parent) {
		DEBUG("No matching request packet for CoA packet %u %u", packet->data[0], packet->data[1]);
		talloc_free(packet);
		return 0;
	}
	assert(parent->coa);

	request = parent->coa;
	request->packet = talloc_steal(request, packet);

	fr_pair_list_steal(request, &my.request_pairs);
	fr_pair_list_append(&request->request_pairs, &my.request_pairs);

	/*
	 *	If we had an expected response code, check to see if the
	 *	packet matched that.
	 */
	if (request->packet->code != request->filter_code) {
		if (FR_RADIUS_PACKET_CODE_VALID(request->reply->code)) {
			REDEBUG("%s: Expected %s got %s", request->name, fr_radius_packet_name[request->filter_code],
				fr_radius_packet_name[request->packet->code]);
		} else {
			REDEBUG("%s: Expected %u got %i", request->name, request->filter_code,
				request->packet->code);
		}
		stats.failed++;

	/*
	 *	Check if the contents of the packet matched the filter
	 */
	} else if (fr_pair_list_empty(&request->filter)) {
		stats.passed++;

	} else {
		fr_pair_t const *failed[2];

		fr_pair_list_sort(&request->request_pairs, fr_pair_cmp_by_da);
		if (fr_pair_validate(failed, &request->filter, &request->request_pairs)) {
			RDEBUG("%s: CoA request passed filter", request->name);
			stats.passed++;
		} else {
			fr_pair_validate_debug(failed);
			REDEBUG("%s: CoA Request for failed filter", request->name);
			stats.failed++;
		}
	}

	request->reply->id = request->packet->id;

	request->reply->socket.type = SOCK_DGRAM;
	request->reply->socket.af = client_ipaddr.af;
	request->reply->socket.fd = coafd;
	request->reply->socket.inet.src_ipaddr = client_ipaddr;
	request->reply->socket.inet.src_port = coa_port;
	request->reply->socket.inet.dst_ipaddr = packet->socket.inet.src_ipaddr;
	request->reply->socket.inet.dst_port = packet->socket.inet.src_port;

	if (!request->reply->code) switch (packet->code) {
	case FR_RADIUS_CODE_COA_REQUEST:
		request->reply->code = FR_RADIUS_CODE_COA_ACK;
		break;

	case FR_RADIUS_CODE_DISCONNECT_REQUEST:
		request->reply->code = FR_RADIUS_CODE_DISCONNECT_ACK;
		break;

	default:
		RDEBUG("Failed getting reply packet type");
		return 0;
	}

	fr_radius_packet_log(&default_log, request->reply, &request->reply_pairs, false);


	/*
	 *	Send reply.
	 */
	if (fr_packet_send(request->reply, &request->reply_pairs, packet, secret) < 0) {
		REDEBUG("Failed sending CoA reply");
		return 0;
	}

	fr_rb_remove(coa_tree, request);

	/*
	 *	No longer waiting for a CoA packet for this request.
	 */
	TALLOC_FREE(parent->coa);
	return 0;
}


/*
 *	Do Blast RADIUS checks.
 *
 *	The request is an Access-Request, and does NOT contain Proxy-State.
 *
 *	The reply is a raw packet, and is NOT yet decoded.
 */
static int blast_radius_check(rc_request_t *request, fr_packet_t *reply)
{
	uint8_t *attr, *end;
	fr_pair_t *vp;
	bool have_message_authenticator = false;

	/*
	 *	We've received a raw packet.  Nothing has (as of yet) checked
	 *	anything in it other than the length, and that it's a
	 *	well-formed RADIUS packet.
	 */
	switch (reply->data[0]) {
	case FR_RADIUS_CODE_ACCESS_ACCEPT:
	case FR_RADIUS_CODE_ACCESS_REJECT:
	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
	case FR_RADIUS_CODE_PROTOCOL_ERROR:
		if (reply->data[1] != request->packet->id) {
			ERROR("Invalid reply ID %d to Access-Request ID %d", reply->data[1], request->packet->id);
			return -1;
		}
		break;

	default:
		ERROR("Invalid reply code %d to Access-Request", reply->data[0]);
		return -1;
	}

	/*
	 *	If the reply has a Message-Authenticator, then it MIGHT be fine.
	 */
	attr = reply->data + 20;
	end = reply->data + reply->data_len;

	/*
	 *	It should be the first attribute, so we warn if it isn't there.
	 *
	 *	But it's not a fatal error.
	 */
	if (blast_radius && (attr[0] != FR_MESSAGE_AUTHENTICATOR)) {
		RDEBUG("WARNING The %s reply packet does not have Message-Authenticator as the first attribute.  The packet may be vulnerable to Blast RADIUS attacks.",
		       fr_radius_packet_name[reply->data[0]]);
	}

	/*
	 *	Set up for Proxy-State checks.
	 *
	 *	If we see a Proxy-State in the reply which we didn't send, then it's a Blast RADIUS attack.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_proxy_state);

	while (attr < end) {
		/*
		 *	Blast RADIUS work-arounds require that
		 *	Message-Authenticator is the first attribute in the
		 *	reply.  Note that we don't check for it being the
		 *	first attribute, but simply that it exists.
		 *
		 *	That check is a balance between securing the reply
		 *	packet from attacks, and not violating the RFCs which
		 *	say that there is no order to attributes in the
		 *	packet.
		 *
		 *	However, no matter the status of the '-b' flag we
		 *	still can check for the signature of the attack, and
		 *	discard packets which are suspicious.  This behavior
		 *	protects radclient from the attack, without mandating
		 *	new behavior on the server side.
		 *
		 *	Note that we don't set the '-b' flag by default.
		 *	radclient is intended for testing / debugging, and is
		 *	not intended to be used as part of a secure login /
		 *	user checking system.
		 */
		if (attr[0] == FR_MESSAGE_AUTHENTICATOR) {
			have_message_authenticator = true;
			goto next;
		}

		/*
		 *	If there are Proxy-State attributes in the reply, they must
		 *	match EXACTLY the Proxy-State attributes in the request.
		 *
		 *	Note that we don't care if there are more Proxy-States
		 *	in the request than in the reply.  The Blast RADIUS
		 *	issue requires _adding_ Proxy-State attributes, and
		 *	cannot work when the server _deletes_ Proxy-State
		 *	attributes.
		 */
		if (attr[0] == FR_PROXY_STATE) {
			if (!vp || (vp->vp_length != (size_t) (attr[1] - 2)) || (memcmp(vp->vp_octets, attr + 2, vp->vp_length) != 0)) {
				ERROR("Invalid reply to Access-Request ID %d - Discarding packet due to Blast RADIUS attack being detected.", request->packet->id);
				ERROR("We received a Proxy-State in the reply which we did not send, or which is different from what we sent.");
				return -1;
			}

			vp = fr_pair_find_by_da(&request->request_pairs, vp, attr_proxy_state);
		}

	next:
		attr += attr[1];
	}

	/*
	 *	If "-b" is set, then we require Message-Authenticator in the reply.
	 */
	if (blast_radius && !have_message_authenticator) {
		ERROR("The %s reply packet does not contain Message-Authenticator - discarding packet due to Blast RADIUS checks.",
		      fr_radius_packet_name[reply->data[0]]);
		return -1;
	}

	/*
	 *	The packet doesn't look like it's a Blast RADIUS attack.  The
	 *	caller will now verify the packet signature.
	 */
	return 0;
}

/*
 *	Receive one packet, maybe.
 */
static int recv_one_packet(fr_time_delta_t wait_time)
{
	fd_set			set;
	fr_time_delta_t		our_wait_time;
	rc_request_t		*request;
	fr_packet_t		*reply, *packet;
	volatile int		max_fd;

#ifdef STATIC_ANALYZER
	if (!secret) fr_exit_now(1);
#endif

	/* And wait for reply, timing out as necessary */
	FD_ZERO(&set);

	max_fd = fr_packet_list_fd_set(packet_list, &set);
	if (max_fd < 0) fr_exit_now(1); /* no sockets to listen on! */

	our_wait_time = !fr_time_delta_ispos(wait_time) ? fr_time_delta_from_sec(0) : wait_time;

	if (do_coa && fr_rb_num_elements(coa_tree) > 0) {
		FD_SET(coafd, &set);
		if (coafd >= max_fd) max_fd = coafd + 1;
	}

	/*
	 *	See if a packet was received.
	 */
retry:
	if (select(max_fd, &set, NULL, NULL, &fr_time_delta_to_timeval(our_wait_time)) <= 0) return 0;

	/*
	 *	Read a CoA packet
	 */
	if (FD_ISSET(coafd, &set)) {
		recv_coa_packet(fr_time_delta_wrap(0));
		FD_CLR(coafd, &set);
		our_wait_time = fr_time_delta_from_sec(0);
		goto retry;
	}

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

	packet = fr_packet_list_find_byreply(packet_list, reply);
	if (!packet) {
		ERROR("Received reply to request we did not send. (id=%d socket %d)",
		      reply->id, reply->socket.fd);
		fr_packet_free(&reply);
		return -1;	/* got reply to packet we didn't send */
	}
	request = packet->uctx;

	/*
	 *	We want radclient to be able to send any packet, including
	 *	imperfect ones.  However, we do NOT want to be vulnerable to
	 *	the "Blast RADIUS" issue.  Instead of adding command-line
	 *	flags to enable/disable similar flags to what the server
	 *	sends, we just do a few more smart checks to double-check
	 *	things.
	 */
	if ((request->packet->code == FR_RADIUS_CODE_ACCESS_REQUEST) &&
	    blast_radius_check(request, reply) < 0) {
		fr_packet_free(&reply);
		return -1;
	}

	/*
	 *	Fails the signature validation: not a real reply.
	 *	FIXME: Silently drop it and listen for another packet.
	 */
	if (fr_packet_verify(reply, request->packet, secret) < 0) {
		REDEBUG("Reply verification failed");
		stats.lost++;
		goto packet_done; /* shared secret is incorrect */
	}

	if (print_filename) {
		RDEBUG("%s response code %d", request->files->packets, reply->code);
	}

	if (request->tries < ignore_count) {
		RDEBUG("Ignoring response %d due to -e ignore_count=%d", request->tries, ignore_count);
		goto packet_done;
	}

	deallocate_id(request);
	request->reply = reply;
	reply = NULL;

	/*
	 *	If this fails, we're out of memory.
	 */
	if (fr_radius_decode_simple(request, &request->reply_pairs,
				    request->reply->data, request->reply->data_len,
				    request->packet->vector, secret) < 0) {
		REDEBUG("Reply decode failed");
		stats.lost++;
		goto packet_done;
	}
	PAIR_LIST_VERIFY(&request->reply_pairs);
	fr_radius_packet_log(&default_log, request->reply, &request->reply_pairs, true);

	/*
	 *	Increment counters...
	 */
	switch (request->reply->code) {
	case FR_RADIUS_CODE_ACCESS_ACCEPT:
	case FR_RADIUS_CODE_ACCOUNTING_RESPONSE:
	case FR_RADIUS_CODE_COA_ACK:
	case FR_RADIUS_CODE_DISCONNECT_ACK:
		stats.accepted++;
		break;

	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
		break;

	case FR_RADIUS_CODE_PROTOCOL_ERROR:
		stats.error++;
		break;
	default:
		stats.rejected++;
	}

	fr_strerror_clear();	/* Clear strerror buffer */

	/*
	 *	If we had an expected response code, check to see if the
	 *	packet matched that.
	 */
	if ((request->filter_code != FR_RADIUS_CODE_UNDEFINED) && (request->reply->code != request->filter_code)) {
		if (FR_RADIUS_PACKET_CODE_VALID(request->reply->code)) {
			REDEBUG("%s: Expected %s got %s", request->name, fr_radius_packet_name[request->filter_code],
				fr_radius_packet_name[request->reply->code]);
		} else {
			REDEBUG("%s: Expected %u got %i", request->name, request->filter_code,
				request->reply->code);
		}
		stats.failed++;
	/*
	 *	Check if the contents of the packet matched the filter
	 */
	} else if (fr_pair_list_empty(&request->filter)) {
		stats.passed++;
	} else {
		fr_pair_t const *failed[2];

		fr_pair_list_sort(&request->reply_pairs, fr_pair_cmp_by_da);
		if (fr_pair_validate(failed, &request->filter, &request->reply_pairs)) {
			RDEBUG("%s: Response passed filter", request->name);
			stats.passed++;
		} else {
			fr_pair_validate_debug(failed);
			REDEBUG("%s: Response for failed filter", request->name);
			stats.failed++;
		}
	}

	if (request->resend == resend_count) {
		request->done = true;
	}

packet_done:
	fr_packet_free(&request->reply);
	fr_packet_free(&reply);	/* may be NULL */

	return 0;
}

/**
 *
 * @hidecallgraph
 */
int main(int argc, char **argv)
{
	int		ret = EXIT_SUCCESS;
	int		c;
	char		const *raddb_dir = RADDBDIR;
	char		const *dict_dir = DICTDIR;
	char		filesecret[256];
	FILE		*fp;
	int		do_summary = false;
	int		persec = 0;
	int		parallel = 1;
	int		force_af = AF_UNSPEC;
#ifndef NDEBUG
	TALLOC_CTX	*autofree;
#endif
	fr_dlist_head_t	filenames;
	rc_request_t	*request;

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
	fr_atexit_global_setup();

#ifndef NDEBUG
	autofree = talloc_autofree_context();

	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("radclient");
		fr_exit_now(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	fr_dlist_talloc_init(&rc_request_list, rc_request_t, entry);

	fr_dlist_talloc_init(&filenames, rc_file_pair_t, entry);

	/*
	 *	Always log to stdout
	 */
	default_log.dst = L_DST_STDOUT;
	default_log.fd = STDOUT_FILENO;
	default_log.print_level = false;

	while ((c = getopt(argc, argv, "46bc:A:C:d:D:e:f:Fhi:n:o:p:P:r:sS:t:vx")) != -1) switch (c) {
		case '4':
			force_af = AF_INET;
			break;

		case '6':
			force_af = AF_INET6;
			break;

		case 'A':
			attr_coa_filter_name = optarg;
			break;

		case 'b':
			blast_radius = true;
			break;

		case 'c':
			if (!isdigit((uint8_t) *optarg)) usage();

			resend_count = atoi(optarg);

			if (resend_count < 1) usage();
			break;

		case 'C':
		{
			int tmp;

			if (strchr(optarg, ':')) {
				if (fr_inet_pton_port(&client_ipaddr, &client_port,
						      optarg, -1, AF_UNSPEC, true, false) < 0) {
					fr_perror("Failed parsing source address");
					fr_exit_now(1);
				}
				break;
			}

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

		case 'e':	/* magical extra stuff */
			if (strncmp(optarg, "ignore_count=", 13) == 0) {
				ignore_count = atoi(optarg + 13);
				break;
			}
			usage();

			/*
			 *	packet,filter,coa_reply,coa_filter
			 */
		case 'f':
		{
			char const *p;
			rc_file_pair_t *files;

			MEM(files = talloc_zero(talloc_autofree_context(), rc_file_pair_t));

			/*
			 *	Commas are nicer than colons.
			 */
			c = ':';

			p = strchr(optarg, c);
			if (!p) {
				c = ',';
				p = strchr(optarg, c);
			}
			if (!p) {
				files->packets = optarg;
				files->filters = NULL;
			} else {
				char *q;

				MEM(files->packets = talloc_strndup(files, optarg, p - optarg));
				files->filters = p + 1;

				/*
				 *	Look for CoA filename
				 */
				q = strchr(files->filters, c);
				if (q) {
					do_coa = true;

					*(q++) = '\0';
					files->coa_reply = q;

					q = strchr(files->coa_reply, c);
					if (q) {
						*(q++) = '\0';
						files->coa_filter = q;
					}
				}
			}
			fr_dlist_insert_tail(&filenames, files);
		}
			break;

		case 'F':
			print_filename = true;
			break;

		case 'i':
			if (!isdigit((uint8_t) *optarg))
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

		case 'o':
			coa_port = atoi(optarg);
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
			if (!isdigit((uint8_t) *optarg)) usage();
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
			if (fr_time_delta_from_str(&timeout, optarg, strlen(optarg), FR_TIME_RES_SEC) < 0) {
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
		fr_exit_now(EXIT_FAILURE);
	}

	if (!fr_dict_global_ctx_init(NULL, true, dict_dir)) {
		fr_perror("radclient");
		fr_exit_now(EXIT_FAILURE);
	}

	if (fr_radius_global_init() < 0) {
		fr_perror("radclient");
		fr_exit_now(EXIT_FAILURE);
	}

	if (fr_dict_autoload(radclient_dict) < 0) {
		fr_perror("radclient");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_attr_autoload(radclient_dict_attr) < 0) {
		fr_perror("radclient");
		exit(EXIT_FAILURE);
	}

	if (fr_dict_read(fr_dict_unconst(dict_freeradius), raddb_dir, FR_DICTIONARY_FILE) == -1) {
		fr_log_perror(&default_log, L_ERR, __FILE__, __LINE__, NULL,
			      "Failed to initialize the dictionaries");
		exit(EXIT_FAILURE);
	}

	if (do_coa) {
		attr_coa_filter = fr_dict_attr_by_name(NULL, fr_dict_root(dict_radius), attr_coa_filter_name);
		if (!attr_coa_filter) {
			ERROR("Unknown or invalid CoA filter attribute %s", optarg);
			fr_exit_now(1);
		}

		/*
		 *	If there's no attribute given to match CoA to requests, use User-Name
		 */
		if (!attr_coa_filter) attr_coa_filter = attr_user_name;

		MEM(coa_tree = fr_rb_inline_talloc_alloc(NULL, rc_request_t, node, request_cmp, NULL));
	}
	packet_global_init();

	fr_strerror_clear();	/* Clear the error buffer */

	/*
	 *	Get the request type
	 */
	if (!isdigit((uint8_t) argv[2][0])) {
		packet_code = fr_table_value_by_str(fr_radius_request_name_table, argv[2], -2);
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
		if (packet_code == FR_RADIUS_CODE_UNDEFINED) packet_code = radclient_get_code(server_port);
	}
	radclient_get_port(packet_code, &server_port);

	/*
	 *	Add the secret.
	 */
	if (argv[3]) secret = talloc_strdup(NULL, argv[3]);

	/*
	 *	If no '-f' is specified, we're reading from stdin.
	 */
	if (fr_dlist_num_elements(&filenames) == 0) {
		rc_file_pair_t *files;

		files = talloc_zero(talloc_autofree_context(), rc_file_pair_t);
		files->packets = "-";
		if (radclient_init(files, files) < 0) fr_exit_now(1);
	}

	/*
	 *	Walk over the list of filenames, creating the requests.
	 */
	fr_dlist_foreach(&filenames, rc_file_pair_t, files) {
		if (radclient_init(files, files)) {
			ERROR("Failed parsing input files");
			fr_exit_now(1);
		}
	}

	/*
	 *	No packets read.  Die.
	 */
	if (!fr_dlist_num_elements(&rc_request_list)) {
		ERROR("Nothing to send");
		fr_exit_now(1);
	}

	openssl3_init();

	/*
	 *	Bind to the first specified IP address and port.
	 *	This means we ignore later ones.
	 */
	request = fr_dlist_head(&rc_request_list);

	if (client_ipaddr.af == AF_UNSPEC) {
		if (request->packet->socket.inet.src_ipaddr.af == AF_UNSPEC) {
			memset(&client_ipaddr, 0, sizeof(client_ipaddr));
			client_ipaddr.af = server_ipaddr.af;
		} else {
			client_ipaddr = request->packet->socket.inet.src_ipaddr;
		}
	}

	if (client_port == 0) client_port = request->packet->socket.inet.src_port;

	if (ipproto == IPPROTO_TCP) {
		sockfd = fr_socket_client_tcp(NULL, NULL, &server_ipaddr, server_port, false);
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

		if (fr_socket_bind(sockfd, NULL, &client_ipaddr, &client_port) < 0) {
			fr_perror("Error binding socket");
			return -1;
		}
	}

	if (do_coa) {
		coafd = fr_socket_server_udp(&client_ipaddr, &coa_port, NULL, false);
		if (coafd < 0) {
			fr_perror("Error opening CoA socket");
			return -1;
		}

		if (fr_socket_bind(coafd, NULL, &client_ipaddr, &coa_port) < 0) {
			fr_perror("Error binding socket");
			return -1;
		}
	}

	MEM(packet_list = fr_packet_list_create(1));
	if (!fr_packet_list_socket_add(packet_list, sockfd, ipproto, &server_ipaddr,
				       server_port, NULL)) {
		ERROR("Failed adding socket");
		fr_exit_now(1);
	}

	/*
	 *	Walk over the list of packets, sanity checking
	 *	everything.
	 */
	fr_dlist_foreach(&rc_request_list, rc_request_t, this) {
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
		rc_request_t *this, *next;
		char const *filename = NULL;

		done = true;
		sleep_time = fr_time_delta_wrap(-1);

		/*
		 *	Walk over the packets, sending them.
		 */

		for (this = fr_dlist_head(&rc_request_list);
		     this != NULL;
		     this = next) {
			next = fr_dlist_next(&rc_request_list, this);

			/*
			 *	If there's a packet to receive,
			 *	receive it, but don't wait for a
			 *	packet.
			 */
			recv_one_packet(fr_time_delta_wrap(0));

			/*
			 *	This packet is done.  Delete it.
			 */
			if (this->done) {
				/*
				 *	We still have a CoA reply to
				 *	receive for this packet.
				 */
				if (this->coa) {
					recv_coa_packet(fr_time_delta_wrap(0));
					if (this->coa) continue;
				}

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

					psec = (persec == 1) ? fr_time_delta_from_sec(1) : fr_time_delta_wrap(1000000 / persec);

					/*
					 *	Don't sleep elsewhere.
					 */
					sleep_time = fr_time_delta_wrap(0);


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
					sleep_time = fr_time_delta_wrap(0);

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
			sleep_time = fr_time_delta_wrap(0);
		}

		/*
		 *	Nothing to do until we receive a request, so
		 *	sleep until then.  Once we receive one packet,
		 *	we go back, and walk through the whole list again,
		 *	sending more packets (if necessary), and updating
		 *	the sleep time.
		 */
		if (!done && fr_time_delta_ispos(sleep_time)) {
			recv_one_packet(sleep_time);
		}
	} while (!done);

	fr_packet_list_free(packet_list);

	fr_dlist_talloc_free(&rc_request_list);

	talloc_free(coa_tree);

	talloc_free(secret);

	fr_radius_global_free();

	if (fr_dict_autofree(radclient_dict) < 0) {
		fr_perror("radclient");
		ret = EXIT_FAILURE;
	}

#ifndef NDEBUG
	talloc_free(autofree);
#endif

	if (do_summary) {
		fr_perror("Packet summary:\n"
		      "\tAccepted      : %" PRIu64 "\n"
		      "\tRejected      : %" PRIu64 "\n"
		      "\tLost          : %" PRIu64 "\n"
		      "\tErrored       : %" PRIu64 "\n"
		      "\tPassed filter : %" PRIu64 "\n"
		      "\tFailed filter : %" PRIu64,
		      stats.accepted,
		      stats.rejected,
		      stats.lost,
		      stats.error,
		      stats.passed,
		      stats.failed
		);
	}

	/*
	 *	Ensure our atexit handlers run before any other
	 *	atexit handlers registered by third party libraries.
	 */
	fr_atexit_global_trigger_all();

	if ((stats.lost > 0) || (stats.failed > 0)) return EXIT_FAILURE;

	openssl3_free();

	return ret;
}
