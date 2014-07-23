/*
 * unittest.c	Unit test wrapper for the RADIUS daemon.
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
 * Copyright 2000-2013  The FreeRADIUS server project
 * Copyright 2013  Alan DeKok <aland@ox.org>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

/*
 *  Global variables.
 */
char const *progname = NULL;
char const *radius_dir = NULL;
char const *radacct_dir = NULL;
char const *radlog_dir = NULL;
char const *radlib_dir = NULL;
log_debug_t debug_flag = 0;
bool memory_report = false;
bool check_config = false;
bool log_stripped_names = false;

bool filedone = false;

char const *radiusd_version = "FreeRADIUS Version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
", for host " HOSTINFO ", built on " __DATE__ " at " __TIME__;

/*
 *	Static functions.
 */
static void usage(int);

void listen_free(UNUSED rad_listen_t **head)
{
	/* do nothing */
}


static rad_listen_t *listen_alloc(void *ctx)
{
	rad_listen_t *this;

	this = talloc_zero(ctx, rad_listen_t);
	if (!this) return NULL;

	this->type = RAD_LISTEN_AUTH;
	this->recv = NULL;
	this->send = NULL;
	this->print = NULL;
	this->encode = NULL;
	this->decode = NULL;

	/*
	 *	We probably don't care about this.  We can always add
	 *	fields later.
	 */
	this->data = talloc_zero(this, listen_socket_t);
	if (!this->data) {
		talloc_free(this);
		return NULL;
	}

	return this;
}

static RADCLIENT *client_alloc(void *ctx)
{
	RADCLIENT *client;

	client = talloc_zero(ctx, RADCLIENT);
	if (!client) return NULL;

	return client;
}

static REQUEST *request_setup(FILE *fp)
{
	VALUE_PAIR *vp;
	REQUEST *request;
	vp_cursor_t cursor;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_alloc(NULL);

	request->packet = rad_alloc(request, false);
	if (!request->packet) {
		ERROR("No memory");
		talloc_free(request);
		return NULL;
	}

	request->reply = rad_alloc(request, false);
	if (!request->reply) {
		ERROR("No memory");
		talloc_free(request);
		return NULL;
	}

	request->listener = listen_alloc(request);
	request->client = client_alloc(request);

	request->number = 0;

	request->master_state = REQUEST_ACTIVE;
	request->child_state = REQUEST_RUNNING;
	request->handle = NULL;
	request->server = talloc_typed_strdup(request, "default");

	request->root = &main_config;

	/*
	 *	Read packet from fp
	 */
	if (readvp2(&request->packet->vps, request->packet, fp, &filedone) < 0) {
		fr_perror("unittest");
		talloc_free(request);
		return NULL;
	}

	/*
	 *	Set the defaults for IPs, etc.
	 */
	request->packet->code = PW_CODE_ACCESS_REQUEST;

	request->packet->src_ipaddr.af = AF_INET;
	request->packet->src_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_LOOPBACK);
	request->packet->src_port = 18120;

	request->packet->dst_ipaddr.af = AF_INET;
	request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_LOOPBACK);
	request->packet->dst_port = 1812;

	/*
	 *	Copied from radclient
	 *
	 *	Fix up Digest-Attributes issues
	 */
	for (vp = fr_cursor_init(&cursor, &request->packet->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	Double quoted strings get marked up as xlat expansions,
		 *	but we don't support that here.
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

		case PW_CHAP_PASSWORD: {
			int i, already_hex = 0;

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

				len = len2 = vp->length;
				if (len2 < 17) len2 = 17;

				p = talloc_zero_array(vp, uint8_t, len2);

				memcpy(p, vp->vp_strvalue, len);

				rad_chap_encode(request->packet,
						p,
						fr_rand() & 0xff, vp);
				vp->vp_octets = p;
				vp->length = 17;
			}
		}
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
			rad_assert(da != NULL);
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

	if (debug_flag) {
		for (vp = fr_cursor_init(&cursor, &request->packet->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			/*
			 *	Take this opportunity to verify all the VALUE_PAIRs are still valid.
			 */
			if (!talloc_get_type(vp, VALUE_PAIR)) {
				ERROR("Expected VALUE_PAIR pointer got \"%s\"", talloc_get_name(vp));

				fr_log_talloc_report(vp);
				rad_assert(0);
			}

			vp_print(fr_log_fp, vp);
		}
		fflush(fr_log_fp);
	}

	/*
	 *	Build the reply template from the request.
	 */
	request->reply->sockfd = request->packet->sockfd;
	request->reply->dst_ipaddr = request->packet->src_ipaddr;
	request->reply->src_ipaddr = request->packet->dst_ipaddr;
	request->reply->dst_port = request->packet->src_port;
	request->reply->src_port = request->packet->dst_port;
	request->reply->id = request->packet->id;
	request->reply->code = 0; /* UNKNOWN code */
	memcpy(request->reply->vector, request->packet->vector,
	       sizeof(request->reply->vector));
	request->reply->vps = NULL;
	request->reply->data = NULL;
	request->reply->data_len = 0;

	/*
	 *	Debugging
	 */
	request->log.lvl = debug_flag;
	request->log.func = vradlog_request;

	request->username = pairfind(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
	request->password = pairfind(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY);

	return request;
}


static void print_packet(FILE *fp, RADIUS_PACKET *packet)
{
	VALUE_PAIR *vp;
	vp_cursor_t cursor;

	if (!packet) {
		fprintf(fp, "\n");
		return;
	}

	fprintf(fp, "%s\n", fr_packet_codes[packet->code]);

	for (vp = fr_cursor_init(&cursor, &packet->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	Take this opportunity to verify all the VALUE_PAIRs are still valid.
		 */
		if (!talloc_get_type(vp, VALUE_PAIR)) {
			ERROR("Expected VALUE_PAIR pointer got \"%s\"", talloc_get_name(vp));

			fr_log_talloc_report(vp);
			rad_assert(0);
		}

		vp_print(fp, vp);
	}
	fflush(fp);
}

/*
 *	The main guy.
 */
int main(int argc, char *argv[])
{
	int rcode = EXIT_SUCCESS;
	int argval;
	const char *input_file = NULL;
	const char *output_file = NULL;
	const char *filter_file = NULL;
	FILE *fp;
	REQUEST *request = NULL;
	VALUE_PAIR *vp;
	VALUE_PAIR *filter_vps = NULL;

	/*
	 *	If the server was built with debugging enabled always install
	 *	the basic fatal signal handlers.
	 */
#ifndef NDEBUG
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("unittest");
		exit(EXIT_FAILURE);
	}
#endif

	if ((progname = strrchr(argv[0], FR_DIR_SEP)) == NULL)
		progname = argv[0];
	else
		progname++;

	debug_flag = 0;
	set_radius_dir(NULL, RADIUS_DIR);

	/*
	 *	Ensure that the configuration is initialized.
	 */
	memset(&main_config, 0, sizeof(main_config));
	main_config.myip.af = AF_UNSPEC;
	main_config.port = 0;
	main_config.name = "radiusd";

	/*
	 *	The tests should have only IPs, not host names.
	 */
	fr_hostname_lookups = false;

	/*
	 *	We always log to stdout.
	 */
	fr_log_fp = stdout;
	default_log.dst = L_DST_STDOUT;
	default_log.fd = STDOUT_FILENO;

	/*  Process the options.  */
	while ((argval = getopt(argc, argv, "d:D:f:hi:mMn:o:xX")) != EOF) {

		switch(argval) {
			case 'd':
				set_radius_dir(NULL, optarg);
				break;

			case 'D':
				main_config.dictionary_dir = talloc_typed_strdup(NULL, optarg);
				break;

			case 'f':
				filter_file = optarg;
				break;

			case 'h':
				usage(0);
				break;

			case 'i':
				input_file = optarg;
				break;

			case 'm':
				main_config.debug_memory = true;
				break;

			case 'M':
				memory_report = true;
				main_config.debug_memory = true;
				break;

			case 'n':
				main_config.name = optarg;
				break;

			case 'o':
				output_file = optarg;
				break;

			case 'X':
				debug_flag += 2;
				main_config.log_auth = true;
				main_config.log_auth_badpass = true;
				main_config.log_auth_goodpass = true;
				break;

			case 'x':
				debug_flag++;
				break;

			default:
				usage(1);
				break;
		}
	}

	if (debug_flag) {
		version();
	}
	fr_debug_flag = debug_flag;

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radiusd");
		exit(EXIT_FAILURE);
	}

	/*  Read the configuration files, BEFORE doing anything else.  */
	if (main_config_init() < 0) {
		rcode = EXIT_FAILURE;
		goto finish;
	}

	/*
	 *  Load the modules
	 */
	if (modules_init(main_config.config) < 0) {
		rcode = EXIT_FAILURE;
		goto finish;
	}

	/* Set the panic action (if required) */
	if (main_config.panic_action &&
#ifndef NDEBUG
	    !getenv("PANIC_ACTION") &&
#endif
	    (fr_fault_setup(main_config.panic_action, argv[0]) < 0)) {
		rcode = EXIT_FAILURE;
		goto finish;
	}

	setlinebuf(stdout); /* unbuffered output */

	if (!input_file || (strcmp(input_file, "-") == 0)) {
		fp = stdin;
	} else {
		fp = fopen(input_file, "r");
		if (!fp) {
			fprintf(stderr, "Failed reading %s: %s\n",
				input_file, fr_syserror(errno));
			goto finish;
		}
	}

	/*
	 *	Grab the VPs from stdin, or from the file.
	 */
	request = request_setup(fp);
	if (!request) {
		fprintf(stderr, "Failed reading input: %s\n", fr_strerror());
		rcode = EXIT_FAILURE;
		goto finish;
	}

	/*
	 *	No filter file, OR there's no more input, OR we're
	 *	reading from a file, and it's different from the
	 *	filter file.
	 */
	if (!filter_file || filedone ||
	    ((input_file != NULL) && (strcmp(filter_file, input_file) != 0))) {
		if (output_file) {
			fclose(fp);
			fp = NULL;
		}
		filedone = false;
	}

	/*
	 *	There is a filter file.  If necessary, open it.  If we
	 *	already are reading it via "input_file", then we don't
	 *	need to re-open it.
	 */
	if (filter_file) {
		if (!fp) {
			fp = fopen(filter_file, "r");
			if (!fp) {
				fprintf(stderr, "Failed reading %s: %s\n", filter_file, strerror(errno));
				rcode = EXIT_FAILURE;
				goto finish;
			}
		}


		if (readvp2(&filter_vps, request, fp, &filedone) < 0) {
			fprintf(stderr, "Failed reading attributes from %s: %s\n",
				filter_file, fr_strerror());
			rcode = EXIT_FAILURE;
			goto finish;
		}

		/*
		 *	FIXME: loop over input packets.
		 */
		fclose(fp);
	}

	rad_virtual_server(request);

	if (!output_file || (strcmp(output_file, "-") == 0)) {
		fp = stdout;
	} else {
		fp = fopen(output_file, "w");
		if (!fp) {
			fprintf(stderr, "Failed writing %s: %s\n",
				output_file, fr_syserror(errno));
			exit(EXIT_FAILURE);
		}
	}

	print_packet(fp, request->reply);

	if (output_file) fclose(fp);

	/*
	 *	Update the list with the response type.
	 */
	vp = radius_paircreate(request->reply, &request->reply->vps,
			       PW_RESPONSE_PACKET_TYPE, 0);
	vp->vp_integer = request->reply->code;

	{
		VALUE_PAIR const *failed[2];

		if (filter_vps && !pairvalidate(failed, filter_vps, request->reply->vps)) {
			pairvalidate_debug(request, failed);
			fr_perror("Output file %s does not match attributes in filter %s",
				  output_file ? output_file : input_file, filter_file);
			rcode = EXIT_FAILURE;
			goto finish;
		}
	}

	INFO("Exiting normally");

finish:
	talloc_free(request);

	/*
	 *	Detach any modules.
	 */
	modules_free();

	xlat_free();		/* modules may have xlat's */

	/*
	 *	Free the configuration items.
	 */
	main_config_free();

	if (memory_report) {
		INFO("Allocated memory at time of report:");
		fr_log_talloc_report(NULL);
	}

	return rcode;
}


/*
 *  Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *output = status?stderr:stdout;

	fprintf(output, "Usage: %s [options]\n", progname);
	fprintf(output, "Options:\n");
	fprintf(output, "  -d raddb_dir  Configuration files are in \"raddb_dir/*\".\n");
	fprintf(output, "  -D dict_dir   Dictionary files are in \"dict_dir/*\".\n");
	fprintf(output, "  -f file       Filter reply against attributes in 'file'.\n");
	fprintf(output, "  -h            Print this help message.\n");
	fprintf(output, "  -m            On SIGINT or SIGQUIT exit cleanly instead of immediately.\n");
	fprintf(output, "  -n name       Read raddb/name.conf instead of raddb/radiusd.conf.\n");
	fprintf(output, "  -X            Turn on full debugging.\n");
	fprintf(output, "  -x            Turn on additional debugging. (-xx gives more debugging).\n");
	exit(status);
}
