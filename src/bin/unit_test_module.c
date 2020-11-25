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
 * @file unit_test_module.c
 * @brief Module test framework
 *
 * @copyright 2000-2018 The FreeRADIUS server project
 * @copyright 2013 Alan DeKok (aland@freeradius.org)
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/value.h>

#include <freeradius-devel/tls/base.h>

#include <freeradius-devel/unlang/base.h>

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/radius/radius.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#include <ctype.h>

#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	goto cleanup; \
} while (0)

/*
 *  Global variables.
 */
static bool filedone = false;
static int my_debug_lvl = 0;

char const *radiusd_version = RADIUSD_VERSION_STRING_BUILD("unit_test_module");

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_protocol;

#define PROTOCOL_NAME unit_test_module_dict[1].proto

extern fr_dict_autoload_t unit_test_module_dict[];
fr_dict_autoload_t unit_test_module_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_protocol, .proto = "radius" }, /* hacked in-place with '-p protocol' */
	{ NULL }
};

static fr_dict_attr_t const *attr_packet_dst_ip_address;
static fr_dict_attr_t const *attr_packet_dst_ipv6_address;
static fr_dict_attr_t const *attr_packet_dst_port;
static fr_dict_attr_t const *attr_packet_src_ip_address;
static fr_dict_attr_t const *attr_packet_src_ipv6_address;
static fr_dict_attr_t const *attr_packet_src_port;
static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t unit_test_module_dict_attr[];
fr_dict_attr_autoload_t unit_test_module_dict_attr[] = {
	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_ipv6_address, .name = "Packet-Dst-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ipv6_address, .name = "Packet-Src-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_protocol },

	{ NULL }
};


static uint32_t access_request;

/*
 *	Static functions.
 */
static void usage(main_config_t const *config, int status);


static RADCLIENT *client_alloc(TALLOC_CTX *ctx, char const *ip, char const *name)
{
	CONF_SECTION *cs;
	CONF_PAIR *cp;
	RADCLIENT *client;

	cs = cf_section_alloc(ctx, NULL, "client", name);
	cp = cf_pair_alloc(cs, "ipaddr", ip, T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
	cf_pair_add(cs, cp);

	cp = cf_pair_alloc(cs, "secret", "supersecret", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	cf_pair_add(cs, cp);

	cp = cf_pair_alloc(cs, "nas_type", "test", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	cf_pair_add(cs, cp);

	cp = cf_pair_alloc(cs, "shortname", "test", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	cf_pair_add(cs, cp);

	cp = cf_pair_alloc(cs, "groups", "foo", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	cf_pair_add(cs, cp);

	cp = cf_pair_alloc(cs, "groups", "bar", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	cf_pair_add(cs, cp);

	cp = cf_pair_alloc(cs, "groups", "baz", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	cf_pair_add(cs, cp);

	client = client_afrom_cs(ctx, cs, NULL);
	if (!client) {
		PERROR("Failed creating test client");
		fr_assert(0);
	}
	talloc_steal(client, cs);
	fr_assert(client);

	return client;
}

static request_t *request_from_file(TALLOC_CTX *ctx, FILE *fp, fr_event_list_t *el, RADCLIENT *client)
{
	fr_pair_t	*vp;
	request_t		*request;
	fr_cursor_t	cursor;

	static int	number = 0;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_local_alloc(ctx);

	/*
	 *	FIXME - Should be less RADIUS centric, but everything
	 *	else assumes RADIUS at the moment so we can fix this later.
	 */
	request->dict = fr_dict_by_protocol_name(PROTOCOL_NAME);
	if (!request->dict) {
		ERROR("%s dictionary failed to load", PROTOCOL_NAME);
		talloc_free(request);
		return NULL;
	}

	request->packet = fr_radius_alloc(request, false);
	if (!request->packet) {
		ERROR("No memory");
		talloc_free(request);
		return NULL;
	}
	request->packet->timestamp = fr_time();

	request->reply = fr_radius_alloc(request, false);
	if (!request->reply) {
		ERROR("No memory");
		talloc_free(request);
		return NULL;
	}

	request->client = client;

	request->number = number++;
	request->name = talloc_typed_asprintf(request, "%" PRIu64, request->number);

	request->master_state = REQUEST_ACTIVE;
	request->server_cs = virtual_server_find("default");
	fr_assert(request->server_cs != NULL);

	request->config = main_config;

	/*
	 *	Read packet from fp
	 */
	if (fr_pair_list_afrom_file(request->packet, dict_protocol, &request->request_pairs, fp, &filedone) < 0) {
		fr_perror("%s", main_config->name);
		talloc_free(request);
		return NULL;
	}

	/*
	 *	Set the defaults for IPs, etc.
	 */
	request->packet->code = access_request;

	request->packet->socket.proto = IPPROTO_UDP;
	request->packet->socket.inet.src_ipaddr.af = AF_INET;
	request->packet->socket.inet.src_ipaddr.prefix = 32;
	request->packet->socket.inet.src_ipaddr.addr.v4.s_addr = htonl(INADDR_LOOPBACK);
	request->packet->socket.inet.src_port = 18120;

	request->packet->socket.inet.dst_ipaddr.af = AF_INET;
	request->packet->socket.inet.dst_ipaddr.prefix = 32;
	request->packet->socket.inet.dst_ipaddr.addr.v4.s_addr = htonl(INADDR_LOOPBACK);
	request->packet->socket.inet.dst_port = 1812;

	for (vp = fr_cursor_init(&cursor, &request->request_pairs);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	Double quoted strings get marked up as xlat expansions,
		 *	but we don't support that here.
		 */
		if (vp->type == VT_XLAT) {
			vp->vp_strvalue = vp->xlat;
			vp->xlat = NULL;
			vp->type = VT_DATA;
		}

		if (vp->da == attr_packet_type) {
			request->packet->code = vp->vp_uint32;
		} else if (vp->da == attr_packet_dst_port) {
			request->packet->socket.inet.dst_port = vp->vp_uint16;
		} else if ((vp->da == attr_packet_dst_ip_address) ||
			   (vp->da == attr_packet_dst_ipv6_address)) {
			memcpy(&request->packet->socket.inet.dst_ipaddr, &vp->vp_ip, sizeof(request->packet->socket.inet.dst_ipaddr));
		} else if (vp->da == attr_packet_src_port) {
			request->packet->socket.inet.src_port = vp->vp_uint16;
		} else if ((vp->da == attr_packet_src_ip_address) ||
			   (vp->da == attr_packet_src_ipv6_address)) {
			memcpy(&request->packet->socket.inet.src_ipaddr, &vp->vp_ip, sizeof(request->packet->socket.inet.src_ipaddr));
		}
	} /* loop over the VP's we read in */

	/*
	 *	"0" is uniformly the "bad packet" type.
	 */
	if (!request->packet->code) {
		fr_strerror_printf("No 'Packet-Type' was found in the request list.  Cannot send unknown packet");
		return NULL;
	}

	if (fr_debug_lvl) {
		for (vp = fr_cursor_init(&cursor, &request->request_pairs);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			/*
			 *	Take this opportunity to verify all the fr_pair_ts are still valid.
			 */
			if (!talloc_get_type(vp, fr_pair_t)) {
				ERROR("Expected fr_pair_t pointer got \"%s\"", talloc_get_name(vp));

				fr_log_talloc_report(vp);
				fr_assert(0);
			}

			fr_log(&default_log, L_DBG, __FILE__, __LINE__, "%pP", vp);
		}
	}

	/*
	 *	Build the reply template from the request.
	 */
	fr_socket_addr_swap(&request->reply->socket, &request->packet->socket);

	request->reply->id = request->packet->id;
	request->reply->code = 0; /* UNKNOWN code */
	memcpy(request->reply->vector, request->packet->vector, sizeof(request->reply->vector));
	request->reply_pairs = NULL;
	request->reply->data = NULL;
	request->reply->data_len = 0;

	/*
	 *	Debugging
	 */
	request->log.dst = talloc_zero(request, log_dst_t);
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;
	request->log.lvl = fr_debug_lvl;

	fr_request_async_bootstrap(request, el);

	return request;
}


static void print_packet(FILE *fp, fr_radius_packet_t *packet)
{
	fr_pair_t *vp;
	fr_cursor_t cursor;
	fr_dict_enum_t *dv;

	if (!packet) {
		fprintf(fp, "\n");
		return;
	}

	dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(packet->code));
	if (dv) fprintf(fp, "%s\n", dv->name);

	for (vp = fr_cursor_init(&cursor, &packet->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		/*
		 *	Take this opportunity to verify all the fr_pair_ts are still valid.
		 */
		if (!talloc_get_type(vp, fr_pair_t)) {
			ERROR("Expected fr_pair_t pointer got \"%s\"", talloc_get_name(vp));

			fr_log_talloc_report(vp);
			fr_assert(0);
		}

		fr_log(&default_log, L_DBG, __FILE__, __LINE__, "%pP", vp);
	}
	fflush(fp);
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
	request_t		*request;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_alloc(NULL);

	request->log.dst = talloc_zero(request, log_dst_t);
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;

	request->master_state = REQUEST_ACTIVE;
	request->server_cs = virtual_server_find("default");
	fr_assert(request->server_cs != NULL);

	request->config = main_config;

	request->log.lvl = fr_debug_lvl;
	output[0] = '\0';

	while (fgets(input, sizeof(input), fp) != NULL) {
		lineno++;

		/*
		 *	Ignore blank lines and comments
		 */
		p = input;
		fr_skip_whitespace(p);

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
			ssize_t			slen;
			TALLOC_CTX		*xlat_ctx = talloc_init_const("xlat");
			char			*fmt = talloc_typed_strdup(xlat_ctx, input + 5);
			xlat_exp_t		*head = NULL;
			fr_sbuff_parse_rules_t	p_rules = { .escapes = &fr_value_unescape_double };

			slen = xlat_tokenize_ephemeral(xlat_ctx, &head, NULL,
						       &FR_SBUFF_IN(fmt, talloc_array_length(fmt) - 1), &p_rules, NULL);
			if (slen <= 0) {
				talloc_free(xlat_ctx);
				snprintf(output, sizeof(output), "ERROR offset %d '%s'", (int) -slen,
					 fr_strerror());
				continue;
			}

			if (input[slen + 5] != '\0') {
				talloc_free(xlat_ctx);
				snprintf(output, sizeof(output), "ERROR offset %d 'Too much text' ::%s::",
					 (int) slen, input + slen + 5);
				continue;
			}

			len = xlat_eval_compiled(output, sizeof(output), request, head, NULL, NULL);
			if (len < 0) {
				talloc_free(xlat_ctx);
				snprintf(output, sizeof(output), "ERROR expanding xlat: %s", fr_strerror());
				continue;
			}

			TALLOC_FREE(xlat_ctx); /* also frees 'head' */
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
 *	Verify the result of the map.
 */
static int map_proc_verify(CONF_SECTION *cs, UNUSED void *mod_inst, UNUSED void *proc_inst,
			   tmpl_t const *src, UNUSED map_t const *maps)
{
	if (!src) {
		cf_log_err(cs, "Missing source");

		return -1;
	}

	return 0;
}

static rlm_rcode_t mod_map_proc(UNUSED void *mod_inst, UNUSED void *proc_inst, UNUSED request_t *request,
			      	UNUSED fr_value_box_t **src, UNUSED map_t const *maps)
{
	return RLM_MODULE_FAIL;
}

static void request_run(fr_event_list_t *el, request_t *request)
{
	rlm_rcode_t	rcode;
	module_method_t	process;
	void		*inst;
	fr_dict_enum_t	*dv;
	fr_heap_t	*backlog;
	request_t	*child;

	dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->packet->code));
	if (!dv) return;

	if (virtual_server_get_process_by_name(request->server_cs, dv->name, &process, &inst) < 0) {
		REDEBUG("Cannot run virtual server '%s' - %s", cf_section_name2(request->server_cs), fr_strerror());
		return;
	}

	MEM(backlog = fr_heap_talloc_alloc(request, fr_pointer_cmp, request_t, runnable_id));
	request->backlog = backlog;
	request->el = el;

	if (process(&rcode, &(module_ctx_t){ .instance = inst }, request) != UNLANG_ACTION_YIELD) goto done;

	while (true) {
		bool wait_for_event;
		int num_events;

		wait_for_event = (fr_heap_num_elements(backlog) == 0);

	corral:
		num_events = fr_event_corral(el, fr_time(), wait_for_event);
		if (num_events < 0) {
			PERROR("Failed retrieving events");
			break;
		}

		/*
		 *	Service outstanding events.
		 */
		if (num_events > 0) fr_event_service(el);

		/*
		 *	The request is not runnable.  Wait for events.
		 *
		 *	Note that we do NOT run any child requests.
		 *	There may be child requests in the backlog,
		 *	but we just ignore them.
		 */
		if (request->runnable_id < 0) {
			wait_for_event = true;
			goto corral;
		}

		/*
		 *	Run the parent request in preference to any
		 *	child requests.
		 */
		(void) fr_heap_extract(backlog, request);

		if (process(&rcode, &(module_ctx_t){ .instance = inst }, request) != UNLANG_ACTION_YIELD) break;
	}

done:
	/*
	 *	Parallel-detach creates detached, but runnable
	 *	children.  We don't want to run them, so we just clean
	 *	them up here.
	 */
	while ((child = fr_heap_pop(backlog)) != NULL) talloc_free(child);

	/*
	 *	We do NOT run detached child requests.  We just ignore
	 *	them.
	 */
	talloc_free(backlog);
}

static request_t *request_clone(request_t *old)
{
	request_t *request;

	request = request_alloc(NULL);
	if (!request) return NULL;

	if (!request->packet) request->packet = fr_radius_alloc(request, false);
	if (!request->reply) request->reply = fr_radius_alloc(request, false);

	memcpy(request->packet, old->packet, sizeof(*request->packet));
	(void) fr_pair_list_copy(request->packet, &request->request_pairs, &old->packet->vps);
	request->packet->timestamp = fr_time();
	request->number = old->number++;

	return request;
}

/**
 *
 * @hidecallgraph
 */
int main(int argc, char *argv[])
{
	int			ret = EXIT_SUCCESS;
	int			c;
	int			count = 1;
	const char 		*input_file = NULL;
	const char		*output_file = NULL;
	const char		*filter_file = NULL;
	FILE			*fp;
	request_t			*request = NULL;
	fr_pair_t		*vp;
	fr_pair_list_t		filter_vps;
	bool			xlat_only = false;
	fr_event_list_t		*el = NULL;
	RADCLIENT		*client = NULL;
	fr_dict_t		*dict = NULL;
	fr_dict_t const		*dict_check;
	char const 		*receipt_file = NULL;

	TALLOC_CTX		*autofree;
	TALLOC_CTX		*thread_ctx;

	char			*p;
	main_config_t		*config;
	dl_module_loader_t	*dl_modules = NULL;

	fr_pair_list_init(&filter_vps);
	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_thread_local_atexit_setup();

	autofree = talloc_autofree_context();
	thread_ctx = talloc_new(autofree);

	config = main_config_alloc(autofree);
	if (!config) {
		fr_perror("unit_test_module");
		fr_exit_now(EXIT_FAILURE);
	}

	p = strrchr(argv[0], FR_DIR_SEP);
	if (!p) {
		main_config_name_set_default(config, argv[0], false);
	} else {
		main_config_name_set_default(config, p + 1, false);
	}

	fr_talloc_fault_setup();

	/*
	 *	If the server was built with debugging enabled always install
	 *	the basic fatal signal handlers.
	 */
#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), argv[0]) < 0) {
		fr_perror("%s", config->name);
		fr_exit_now(EXIT_FAILURE);
	}
#else
	fr_disable_null_tracking_on_free(autofree);
#endif

	fr_debug_lvl = 0;
	fr_time_start();

	/*
	 *	The tests should have only IPs, not host names.
	 */
	fr_hostname_lookups = false;

	/*
	 *	We always log to stdout.
	 */
	default_log.dst = L_DST_STDOUT;
	default_log.fd = STDOUT_FILENO;
	default_log.print_level = true;

	/*  Process the options.  */
	while ((c = getopt(argc, argv, "c:d:D:f:hi:mMn:o:O:p:r:xXz")) != -1) {
		switch (c) {
			case 'c':
				count = atoi(optarg);
				break;

			case 'd':
				main_config_raddb_dir_set(config, optarg);
				break;

			case 'D':
				main_config_dict_dir_set(config, optarg);
				break;

			case 'f':
				filter_file = optarg;
				break;

			case 'h':
				usage(config, EXIT_SUCCESS);
				break;

			case 'i':
				input_file = optarg;
				break;

			case 'M':
				talloc_enable_leak_report();
				break;

			case 'n':
				config->name = optarg;
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
				fr_exit_now(EXIT_FAILURE);

			case 'p':
				PROTOCOL_NAME = optarg;
				break;

			case 'r':
				receipt_file = optarg;
				break;

			case 'X':
				fr_debug_lvl += 2;
				default_log.print_level = true;
				break;

			case 'x':
				fr_debug_lvl++;
				if (fr_debug_lvl > 2) default_log.print_level = true;
				break;

			case 'z':
				my_debug_lvl++;
				break;

			default:
				usage(config, EXIT_FAILURE);
				break;
		}
	}

	if (receipt_file && (fr_unlink(receipt_file) < 0)) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

#ifdef HAVE_OPENSSL_CRYPTO_H
	/*
	 *  Mismatch between build time OpenSSL and linked SSL, better to die
	 *  here than segfault later.
	 */
	if (ssl_check_consistency() < 0) EXIT_WITH_FAILURE;

	/*
	 *  Initialising OpenSSL once, here, is safer than having individual modules do it.
	 *  Must be called before display_version to ensure relevant engines are loaded.
	 *
	 *  fr_openssl_init() must be called before *ANY* OpenSSL functions are used, which is why
	 *  it's called so early.
	 */
	if (fr_openssl_init() < 0) EXIT_WITH_FAILURE;
#endif

	if (fr_debug_lvl) dependency_version_print();

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("%s", config->name);
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	/*
	 *	Initialize the DL infrastructure, which is used by the
	 *	config file parser.
	 */
	dl_modules = dl_module_loader_init(config->lib_dir);
	if (!dl_modules) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (!fr_dict_global_ctx_init(autofree, config->dict_dir)) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

#ifdef HAVE_OPENSSL_CRYPTO_H
	if (fr_tls_dict_init() < 0) EXIT_WITH_FAILURE;
#endif

	/*
	 *	Load the custom dictionary
	 */
	if (fr_dict_read(dict, config->raddb_dir, FR_DICTIONARY_FILE) == -1) {
		PERROR("Failed to initialize the dictionaries");
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_autoload(unit_test_module_dict) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}
	if (fr_dict_attr_autoload(unit_test_module_dict_attr) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (log_global_init(&default_log, false) < 0) {
		EXIT_WITH_FAILURE;
	}

	if (strcmp(PROTOCOL_NAME, "radius") == 0) {
		access_request = FR_CODE_ACCESS_REQUEST;
	} else {
		/*
		 *	The caller MUST specify a Packet-Type.
		 */
		access_request = 0;
	}

	if (map_proc_register(NULL, "test-fail", mod_map_proc, map_proc_verify, 0) < 0) {
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Initialise the interpreter, registering operations.
	 */
	if (unlang_init() < 0) return -1;

	/*  Read the configuration files, BEFORE doing anything else.  */
	if (main_config_init(config) < 0) {
		EXIT_WITH_FAILURE;
	}

	if (modules_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (virtual_servers_init(config->root_cs) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Create a dummy client on 127.0.0.1, if one doesn't already exist.
	 */
	client = client_find(NULL, &(fr_ipaddr_t) { .af = AF_INET, .prefix = 32, .addr.v4.s_addr = htonl(INADDR_LOOPBACK) },
			     IPPROTO_IP);
	if (!client) {
		client = client_alloc(NULL, "127.0.0.1", "test");
		client_add(NULL, client);
	}

	if (server_init(config->root_cs) < 0) EXIT_WITH_FAILURE;

	if (!virtual_server_find("default")) {
		ERROR("Cannot find virtual server 'default'");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Do some sanity checking.
	 */
	dict_check = virtual_server_namespace("default");
	if (!dict_check || (dict_check != dict_protocol)) {
		ERROR("Virtual server namespace does not match requested namespace '%s'", PROTOCOL_NAME);
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Create a dummy event list
	 */
	el = fr_event_list_alloc(NULL, NULL, NULL);
	fr_assert(el != NULL);

	/*
	 *	Simulate thread specific instantiation
	 */
	if (modules_thread_instantiate(thread_ctx, el) < 0) EXIT_WITH_FAILURE;
	if (xlat_thread_instantiate(thread_ctx) < 0) EXIT_WITH_FAILURE;

	/*
	 *  Set the panic action (if required)
	 */
	{
		char const *panic_action = NULL;

		panic_action = getenv("PANIC_ACTION");
		if (!panic_action) panic_action = config->panic_action;

		if (panic_action && (fr_fault_setup(autofree, panic_action, argv[0]) < 0)) {
			fr_perror("%s", config->name);
			EXIT_WITH_FAILURE;
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
			EXIT_WITH_FAILURE;
		}
	}

	/*
	 *	For simplicity, read xlat's.
	 */
	if (xlat_only) {
		if (!do_xlats(input_file, fp)) ret = EXIT_FAILURE;
		if (input_file) fclose(fp);
		goto cleanup;
	}

	/*
	 *	Grab the VPs from stdin, or from the file.
	 */
	request = request_from_file(autofree, fp, el, client);
	if (!request) {
		fr_perror("Failed reading input");
		EXIT_WITH_FAILURE;
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
				fprintf(stderr, "Failed reading %s: %s\n", filter_file, fr_syserror(errno));
				EXIT_WITH_FAILURE;
			}
		}

		if (fr_pair_list_afrom_file(request, dict_protocol, &filter_vps, fp, &filedone) < 0) {
			fr_perror("Failed reading attributes from %s", filter_file);
			EXIT_WITH_FAILURE;
		}

		/*
		 *	Filter files can't be empty.
		 */
		if (!filter_vps) {
			fr_perror("No attributes in filter file %s", filter_file);
			EXIT_WITH_FAILURE;
		}

		/*
		 *	FIXME: loop over input packets.
		 */
		fclose(fp);
	}

	if (count == 1) {
		request_run(el, request);
	} else {
		int i;
		request_t *old = request_clone(request);
		talloc_free(request);

		for (i = 0; i < count; i++) {
			request = request_clone(old);
			request_run(el, request);
			talloc_free(request);
		}
	}

	if (!output_file || (strcmp(output_file, "-") == 0)) {
		fp = stdout;
	} else {
		fp = fopen(output_file, "w");
		if (!fp) {
			fprintf(stderr, "Failed writing %s: %s\n", output_file, fr_syserror(errno));
			goto cleanup;
		}
	}

	print_packet(fp, request->reply);

	if (output_file) fclose(fp);

	/*
	 *	Update the list with the response type, so that it can
	 *	be matched in filters.
	 */
	if (filter_vps) {
		fr_pair_t const *failed[2];

		MEM(pair_add_reply(&vp, attr_packet_type) >= 0);
		vp->vp_uint32 = request->reply->code;


		if (!fr_pair_validate(failed, &filter_vps, &request->reply_pairs)) {
			fr_pair_validate_debug(request, failed);
			fr_perror("Output file %s does not match attributes in filter %s",
				  output_file ? output_file : input_file, filter_file);
			ret = EXIT_FAILURE;
			goto cleanup;
		}
	}

	INFO("Exiting normally");

cleanup:
	talloc_free(request);

	/*
	 *	Free thread data
	 */
	talloc_free(thread_ctx);

	/*
	 *	Free the event list.
	 */
	talloc_free(el);

	/*
	 *	Free request specific logging infrastructure
	 */
	log_global_free();

	server_free();

	/*
	 *	Free any resources used by the unlang interpreter.
	 */
	unlang_free();

	/*
	 *	And now nothing should be left anywhere except the
	 *	parsed configuration items.
	 */
	main_config_free(&config);

	/*
	 *	Free any autoload dictionaries
	 */
	fr_dict_autofree(unit_test_module_dict);

	/*
	 *	Free our explicitly loaded internal dictionary
	 */
	fr_dict_free(&dict);

	if (dl_modules) talloc_free(dl_modules);

	if (receipt_file && (ret == EXIT_SUCCESS) && (fr_touch(NULL, receipt_file, 0644, true, 0755) <= 0)) {
		fr_perror("unit_test_module");
		ret = EXIT_FAILURE;
	}

	return ret;
}


/*
 *  Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(main_config_t const *config, int status)
{
	FILE *output = status ? stderr : stdout;

	fprintf(output, "Usage: %s [options]\n", config->name);
	fprintf(output, "Options:\n");
	fprintf(output, "  -c <count>         Run packets through the interpreter <count> times\n");
	fprintf(output, "  -d <raddb_dir>     Configuration files are in \"raddb_dir/*\".\n");
	fprintf(output, "  -D <dict_dir>      Dictionary files are in \"dict_dir/*\".\n");
	fprintf(output, "  -f <file>          Filter reply against attributes in 'file'.\n");
	fprintf(output, "  -h                 Print this help message.\n");
	fprintf(output, "  -i <file>          File containing request attributes.\n");
	fprintf(output, "  -m                 On SIGINT or SIGQUIT exit cleanly instead of immediately.\n");
	fprintf(output, "  -n <name>          Read raddb/name.conf instead of raddb/radiusd.conf.\n");
	fprintf(output, "  -o <file>          Output file for the reply.\n");
	fprintf(output, "  -p <radius|...>    Define which protocol namespace is used to read the file\n");
	fprintf(output, "                     Use radius, dhcpv4, or dhcpv6\n");
	fprintf(output, "  -X                 Turn on full debugging.\n");
	fprintf(output, "  -x                 Turn on additional debugging. (-xx gives more debugging).\n");
	fprintf(output, "  -r <receipt_file>  Create the <receipt_file> as a 'success' exit.\n");

	fr_exit_now(status);
}
