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
#include <freeradius-devel/state.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#include <ctype.h>

/*
 *  Global variables.
 */
char const *radacct_dir = NULL;
char const *radlog_dir = NULL;
bool log_stripped_names = false;

static bool memory_report = false;
static bool filedone = false;

char const *radiusd_version = "FreeRADIUS Version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
", for host " HOSTINFO
#ifndef ENABLE_REPRODUCIBLE_BUILDS
", built on " __DATE__ " at " __TIME__
#endif
;

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
	VALUE_PAIR	*vp;
	REQUEST		*request;
	vp_cursor_t	cursor;
	struct timeval	now;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_alloc(NULL);
	gettimeofday(&now, NULL);
	request->timestamp = now.tv_sec;

	request->packet = rad_alloc(request, false);
	if (!request->packet) {
		ERROR("No memory");
		talloc_free(request);
		return NULL;
	}
	request->packet->timestamp = now;

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
	if (fr_pair_list_afrom_file(request->packet, &request->packet->vps, fp, &filedone) < 0) {
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
			request->packet->dst_ipaddr.prefix = 32;
			break;

		case PW_PACKET_DST_IPV6_ADDRESS:
			request->packet->dst_ipaddr.af = AF_INET6;
			request->packet->dst_ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
			request->packet->dst_ipaddr.prefix = 128;
			break;

		case PW_PACKET_SRC_PORT:
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

		case PW_CHAP_PASSWORD: {
			int i, already_hex = 0;

			/*
			 *	If it's 17 octets, it *might* be already encoded.
			 *	Or, it might just be a 17-character password (maybe UTF-8)
			 *	Check it for non-printable characters.  The odds of ALL
			 *	of the characters being 32..255 is (1-7/8)^17, or (1/8)^17,
			 *	or 1/(2^51), which is pretty much zero.
			 */
			if (vp->vp_length == 17) {
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

				len = len2 = vp->vp_length;
				if (len2 < 17) len2 = 17;

				p = talloc_zero_array(vp, uint8_t, len2);

				memcpy(p, vp->vp_strvalue, len);

				rad_chap_encode(request->packet,
						p,
						fr_rand() & 0xff, vp);
				vp->vp_octets = p;
				vp->vp_length = 17;
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

			p = talloc_array(vp, uint8_t, vp->vp_length + 2);

			memcpy(p + 2, vp->vp_octets, vp->vp_length);
			p[0] = vp->da->attr - PW_DIGEST_REALM + 1;
			vp->vp_length += 2;
			p[1] = vp->vp_length;

			da = dict_attrbyvalue(PW_DIGEST_ATTRIBUTES, 0);
			rad_assert(da != NULL);
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
		}
	} /* loop over the VP's we read in */

	if (rad_debug_lvl) {
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
	request->log.lvl = rad_debug_lvl;
	request->log.func = vradlog_request;

	request->username = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
	request->password = fr_pair_find_by_num(request->packet->vps, PW_USER_PASSWORD, 0, TAG_ANY);

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


#include <freeradius-devel/modpriv.h>

/*
 *	%{poke:sql.foo=bar}
 */
static ssize_t xlat_poke(UNUSED void *instance, REQUEST *request,
			 char const *fmt, char *out, size_t outlen)
{
	int i;
	void *data, *base;
	char *p, *q;
	module_instance_t *mi;
	char *buffer;
	CONF_SECTION *modules;
	CONF_PAIR *cp;
	CONF_PARSER const *variables;
	size_t len;

	rad_assert(outlen > 1);
	rad_assert(request != NULL);
	rad_assert(fmt != NULL);
	rad_assert(out != NULL);

	*out = '\0';

	modules = cf_section_sub_find(request->root->config, "modules");
	if (!modules) return 0;

	buffer = talloc_strdup(request, fmt);
	if (!buffer) return 0;

	p = strchr(buffer, '.');
	if (!p) return 0;

	*(p++) = '\0';

	mi = module_find(modules, buffer);
	if (!mi) {
		RDEBUG("Failed finding module '%s'", buffer);
	fail:
		talloc_free(buffer);
		return 0;
	}

	q = strchr(p, '=');
	if (!q) {
		RDEBUG("Failed finding '=' in string '%s'", fmt);
		goto fail;
	}

	*(q++) = '\0';

	if (strchr(p, '.') != NULL) {
		RDEBUG("Can't do sub-sections right now");
		goto fail;
	}

	cp = cf_pair_find(mi->cs, p);
	if (!cp) {
		RDEBUG("No such item '%s'", p);
		goto fail;
	}

	/*
	 *	Copy the old value to the output buffer, that way
	 *	tests can restore it later, if they need to.
	 */
	len = strlcpy(out, cf_pair_value(cp), outlen);

	if (cf_pair_replace(mi->cs, cp, q) < 0) {
		RDEBUG("Failed replacing pair");
		goto fail;
	}

	base = mi->insthandle;
	variables = mi->entry->module->config;

	/*
	 *	Handle the known configuration parameters.
	 */
	for (i = 0; variables[i].name != NULL; i++) {
		int ret;

		if (variables[i].type == PW_TYPE_SUBSECTION) continue;
		/* else it's a CONF_PAIR */

		/*
		 *	Not the pair we want.  Skip it.
		 */
		if (strcmp(variables[i].name, p) != 0) continue;

		if (variables[i].data) {
			data = variables[i].data; /* prefer this. */
		} else if (base) {
			data = ((char *)base) + variables[i].offset;
		} else {
			DEBUG2("Internal sanity check 2 failed in cf_section_parse");
			goto fail;
		}

		/*
		 *	Parse the pair we found, or a default value.
		 */
		ret = cf_item_parse(mi->cs, variables[i].name, variables[i].type, data, variables[i].dflt);
		if (ret < 0) {
			DEBUG2("Failed inserting new value into module instance data");
			goto fail;
		}
		break;		/* we found it, don't do any more */
	}

	talloc_free(buffer);

	return len;
}


/*
 *	Read a file compose of xlat's and expected results
 */
static bool do_xlats(char const *filename, FILE *fp)
{
	int		lineno = 0;
	ssize_t		len;
	char		*p;
	char		input[8192];
	char		output[8192];
	REQUEST		*request;
	struct timeval	now;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_alloc(NULL);
	gettimeofday(&now, NULL);
	request->timestamp = now.tv_sec;

	request->log.lvl = rad_debug_lvl;
	request->log.func = vradlog_request;

	output[0] = '\0';

	while (fgets(input, sizeof(input), fp) != NULL) {
		lineno++;

		/*
		 *	Ignore blank lines and comments
		 */
		p = input;
		while (isspace((int) *p)) p++;

		if (*p < ' ') continue;
		if (*p == '#') continue;

		p = strchr(p, '\n');
		if (!p) {
			if (!feof(fp)) {
				fprintf(stderr, "Line %d too long in %s\n",
					lineno, filename);
				TALLOC_FREE(request);
				return false;
			}
		} else {
			*p = '\0';
		}

		/*
		 *	Look for "xlat"
		 */
		if (strncmp(input, "xlat ", 5) == 0) {
			ssize_t slen;
			char const *error = NULL;
			char *fmt = talloc_typed_strdup(NULL, input + 5);
			xlat_exp_t *head;

			slen = xlat_tokenize(fmt, fmt, &head, &error);
			if (slen <= 0) {
				talloc_free(fmt);
				snprintf(output, sizeof(output), "ERROR offset %d '%s'", (int) -slen, error);
				continue;
			}

			if (input[slen + 5] != '\0') {
				talloc_free(fmt);
				snprintf(output, sizeof(output), "ERROR offset %d 'Too much text' ::%s::", (int) slen, input + slen + 5);
				continue;
			}

			len = radius_xlat_struct(output, sizeof(output), request, head, NULL, NULL);
			if (len < 0) {
				snprintf(output, sizeof(output), "ERROR expanding xlat: %s", fr_strerror());
				continue;
			}

			TALLOC_FREE(fmt); /* also frees 'head' */
			continue;
		}

		/*
		 *	Look for "data".
		 */
		if (strncmp(input, "data ", 5) == 0) {
			if (strcmp(input + 5, output) != 0) {
				fprintf(stderr, "Mismatch at line %d of %s\n\tgot      : %s\n\texpected : %s\n",
					lineno, filename, output, input + 5);
				TALLOC_FREE(request);
				return false;
			}
			continue;
		}

		fprintf(stderr, "Unknown keyword in %s[%d]\n", filename, lineno);
		TALLOC_FREE(request);
		return false;
	}

	TALLOC_FREE(request);
	return true;
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
	bool xlat_only = false;
	fr_state_t *state = NULL;

	fr_talloc_fault_setup();

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

	rad_debug_lvl = 0;
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
	while ((argval = getopt(argc, argv, "d:D:f:hi:mMn:o:O:xX")) != EOF) {

		switch (argval) {
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

			case 'O':
				if (strcmp(optarg, "xlat_only") == 0) {
					xlat_only = true;
					break;
				}

				fprintf(stderr, "Unknown option '%s'\n", optarg);
				exit(EXIT_FAILURE);

			case 'X':
				rad_debug_lvl += 2;
				main_config.log_auth = true;
				main_config.log_auth_badpass = true;
				main_config.log_auth_goodpass = true;
				break;

			case 'x':
				rad_debug_lvl++;
				break;

			default:
				usage(1);
				break;
		}
	}

	if (rad_debug_lvl) version_print();
	fr_debug_lvl = rad_debug_lvl;

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("radiusd");
		exit(EXIT_FAILURE);
	}

	/*
	 *  Initialising OpenSSL once, here, is safer than having individual modules do it.
	 */
#ifdef HAVE_OPENSSL_CRYPTO_H
	tls_global_init(false, false);
#endif

	if (xlat_register("poke", xlat_poke, NULL, NULL) < 0) {
		rcode = EXIT_FAILURE;
		goto finish;
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

	state =fr_state_init(NULL);

	/*
	 *  Set the panic action (if required)
	 */
	{
		char const *panic_action = NULL;

		panic_action = getenv("PANIC_ACTION");
		if (!panic_action) panic_action = main_config.panic_action;

		if (panic_action && (fr_fault_setup(panic_action, argv[0]) < 0)) {
			fr_perror("radiusd");
			exit(EXIT_FAILURE);
		}
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
	 *	For simplicity, read xlat's.
	 */
	if (xlat_only) {
		if (!do_xlats(input_file, fp)) rcode = EXIT_FAILURE;
		if (input_file) fclose(fp);
		goto finish;
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


		if (fr_pair_list_afrom_file(request, &filter_vps, fp, &filedone) < 0) {
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
	vp = radius_pair_create(request->reply, &request->reply->vps,
			       PW_RESPONSE_PACKET_TYPE, 0);
	vp->vp_integer = request->reply->code;

	{
		VALUE_PAIR const *failed[2];

		if (filter_vps && !fr_pair_validate(failed, filter_vps, request->reply->vps)) {
			fr_pair_validate_debug(request, failed);
			fr_perror("Output file %s does not match attributes in filter %s (%s)",
				  output_file ? output_file : input_file, filter_file, fr_strerror());
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

	xlat_unregister("poke", xlat_poke, NULL);

	xlat_free();		/* modules may have xlat's */

	fr_state_delete(state);

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

	fprintf(output, "Usage: %s [options]\n", main_config.name);
	fprintf(output, "Options:\n");
	fprintf(output, "  -d raddb_dir  Configuration files are in \"raddb_dir/*\".\n");
	fprintf(output, "  -D dict_dir   Dictionary files are in \"dict_dir/*\".\n");
	fprintf(output, "  -f file       Filter reply against attributes in 'file'.\n");
	fprintf(output, "  -h            Print this help message.\n");
	fprintf(output, "  -i file       File containing request attributes.\n");
	fprintf(output, "  -m            On SIGINT or SIGQUIT exit cleanly instead of immediately.\n");
	fprintf(output, "  -n name       Read raddb/name.conf instead of raddb/radiusd.conf.\n");
	fprintf(output, "  -X            Turn on full debugging.\n");
	fprintf(output, "  -x            Turn on additional debugging. (-xx gives more debugging).\n");
	exit(status);
}
