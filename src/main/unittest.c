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

int filedone = 0;

char const *radiusd_version = "FreeRADIUS Version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" RADIUSD_VERSION_COMMIT ")"
#endif
", for host " HOSTINFO ", built on " __DATE__ " at " __TIME__;

/*
 *	Static functions.
 */
static void usage(int);

#ifdef WITH_VERIFY_PTR
static void die_horribly(char const *reason)
{
	ERROR("talloc abort: %s\n", reason);
	abort();
}
#endif

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
	REQUEST *request;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_alloc(NULL);

	request->packet = rad_alloc(request, 0);
	if (!request->packet) {
		ERROR("No memory");
		request_free(&request);
		return NULL;
	}

	request->reply = rad_alloc(request, 0);
	if (!request->reply) {
		ERROR("No memory");
		request_free(&request);
		return NULL;
	}

	request->listener = listen_alloc(request);
	request->client = client_alloc(request);

	request->number = 0;

	request->master_state = REQUEST_ACTIVE;
	request->child_state = REQUEST_ACTIVE;
	request->handle = NULL;
	request->server = talloc_strdup(request, "default");

	request->root = &mainconfig;

	/*
	 *	Read packet from fp
	 */
	request->packet->vps = readvp2(request->packet, fp, &filedone, "radiusd:");
	if (!request->packet->vps) {
		talloc_free(request);
		return NULL;
	}

	if (debug_flag) {
		VALUE_PAIR *vp;
		vp_cursor_t cursor;

		for (vp = fr_cursor_init(&cursor, &request->packet->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			/*
			 *	Take this opportunity to verify all the VALUE_PAIRs are still valid.
			 */
			if (!talloc_get_type(vp, VALUE_PAIR)) {
				ERROR("Expected VALUE_PAIR pointer got \"%s\"", talloc_get_name(vp));
				
				log_talloc_report(vp);
				rad_assert(0);
			}
			
			vp_print(fr_log_fp, vp);
		}
		fflush(fr_log_fp);
	}

	/*
	 *	FIXME: set IPs, etc.
	 */
	request->packet->code = PW_CODE_AUTHENTICATION_REQUEST;

	request->packet->src_ipaddr.af = AF_INET;
	request->packet->src_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_LOOPBACK);
	request->packet->src_port = 18120;

	request->packet->dst_ipaddr.af = AF_INET;
	request->packet->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_LOOPBACK);
	request->packet->dst_port = 1812;

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
	request->options = debug_flag;
	request->radlog = radlog_request;

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

			log_talloc_report(vp);
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
	REQUEST *request;
	VALUE_PAIR *filter_vps = NULL;

	if ((progname = strrchr(argv[0], FR_DIR_SEP)) == NULL)
		progname = argv[0];
	else
		progname++;

	debug_flag = 0;
	radius_dir = talloc_strdup(NULL, RADIUS_DIR);

	/*
	 *	Ensure that the configuration is initialized.
	 */
	memset(&mainconfig, 0, sizeof(mainconfig));
	mainconfig.myip.af = AF_UNSPEC;
	mainconfig.port = -1;
	mainconfig.name = "radiusd";

	/*
	 *	The tests should have only IPs, not host names.
	 */
	fr_hostname_lookups = false;

	/*
	 *	We always log to stdout.
	 */
	fr_log_fp = stdout;
	default_log.dest = L_DST_STDOUT;
	default_log.fd = STDOUT_FILENO;

	/*  Process the options.  */
	while ((argval = getopt(argc, argv, "d:D:f:hi:mMn:o:xX")) != EOF) {

		switch(argval) {
			case 'd':
				if (radius_dir) {
					rad_const_free(radius_dir);
				}
				radius_dir = talloc_strdup(NULL, optarg);
				break;

			case 'D':
				mainconfig.dictionary_dir = talloc_strdup(NULL, optarg);
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
				mainconfig.debug_memory = 1;
				break;

			case 'M':
				memory_report = 1;
				mainconfig.debug_memory = 1;
				break;

			case 'n':
				mainconfig.name = optarg;
				break;

			case 'o':
				output_file = optarg;
				break;

			case 'X':
				debug_flag += 2;
				mainconfig.log_auth = true;
				mainconfig.log_auth_badpass = true;
				mainconfig.log_auth_goodpass = true;
				break;

			case 'x':
				debug_flag++;
				break;

			default:
				usage(1);
				break;
		}
	}

	if (memory_report) {
		talloc_enable_null_tracking();
#ifdef WITH_VERIFY_PTR
		talloc_set_abort_fn(die_horribly);
#endif
	}
	talloc_set_log_fn(log_talloc);

	if (debug_flag) {
		version();
	}
	fr_debug_flag = debug_flag;

	/*  Read the configuration files, BEFORE doing anything else.  */
	if (read_mainconfig(0) < 0) {
		exit(EXIT_FAILURE);
	}

	setlinebuf(stdout); /* unbuffered output */

	if (!input_file || (strcmp(input_file, "-") == 0)) {
		fp = stdin;
	} else {
		fp = fopen(input_file, "r");
		if (!fp) {
			fprintf(stderr, "Failed reading %s: %s\n",
				input_file, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/*
	 *	Grab the VPs from stdin, or from the file.
	 */
	request = request_setup(fp);
	if (!request) {
		fprintf(stderr, "Failed reading input: %s\n", fr_strerror());
		exit(EXIT_FAILURE);
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
		filedone = 0;
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
				fprintf(stderr, "Failed reading %s: %s\n",
					filter_file, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		filter_vps = readvp2(request, fp, &filedone, "radiusd");
		if (!filter_vps) {
			fprintf(stderr, "Failed reading attributes from %s: %s\n",
				filter_file, fr_strerror());
			exit(EXIT_FAILURE);
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
				output_file, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	print_packet(fp, request->reply);

	if (output_file) fclose(fp);

	if (filter_vps && !pairvalidate(filter_vps, request->reply->vps)) {
		fprintf(stderr, "Output file %s does not match attributes in filter %s\n",
			output_file ? output_file : input_file, filter_file);
		exit(EXIT_FAILURE);
	}

	talloc_free(request);

	INFO("Exiting normally.");

	/*
	 *	Detach any modules.
	 */
	detach_modules();

	xlat_free();		/* modules may have xlat's */

	/*
	 *	Free the configuration items.
	 */
	free_mainconfig();

	rad_const_free(radius_dir);

	if (memory_report) {
		INFO("Allocated memory at time of report:");
		log_talloc_report(NULL);
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
