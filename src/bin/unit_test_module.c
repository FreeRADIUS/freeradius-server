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
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/io/listen.h>

#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/version.h>

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

/*
 *	Static functions.
 */
static void usage(main_config_t const *config, int status);


static RADCLIENT *client_alloc(TALLOC_CTX *ctx, char const *ip, char const *name)
{
	CONF_SECTION *cs;
	RADCLIENT *client;

	cs = cf_section_alloc(ctx, NULL, "client", name);
	MEM(cf_pair_alloc(cs, "ipaddr", ip, T_OP_EQ, T_BARE_WORD, T_BARE_WORD));
	MEM(cf_pair_alloc(cs, "secret", "supersecret", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "nas_type", "test", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "shortname", "test", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "groups", "foo", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "groups", "bar", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));
	MEM(cf_pair_alloc(cs, "groups", "baz", T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING));

	client = client_afrom_cs(ctx, cs, NULL);
	if (!client) {
		PERROR("Failed creating test client");
		fr_assert(0);
	}
	talloc_steal(client, cs);
	fr_assert(client);

	return client;
}

static request_t *request_from_file(TALLOC_CTX *ctx, FILE *fp, RADCLIENT *client, CONF_SECTION *server_cs)
{
	fr_pair_t	*vp;
	request_t	*request;
	fr_dcursor_t	cursor;

	static int	number = 0;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_local_alloc_external(ctx, NULL);

	/*
	 *	FIXME - Should be less RADIUS centric, but everything
	 *	else assumes RADIUS at the moment so we can fix this later.
	 */
	request->dict = fr_dict_by_protocol_name(PROTOCOL_NAME);
	if (!request->dict) {
		fr_strerror_printf_push("%s dictionary failed to load", PROTOCOL_NAME);
	error:
		talloc_free(request);
		return NULL;
	}

	request->packet = fr_radius_packet_alloc(request, false);
	if (!request->packet) {
		fr_strerror_const("No memory");
		goto error;
	}
	request->packet->timestamp = fr_time();

	request->reply = fr_radius_packet_alloc(request, false);
	if (!request->reply) {
		fr_strerror_const("No memory");
		goto error;
	}

	request->client = client;
	request->number = number++;
	request->name = talloc_typed_asprintf(request, "%" PRIu64, request->number);
	request->master_state = REQUEST_ACTIVE;

	/*
	 *	Read packet from fp
	 */
	if (fr_pair_list_afrom_file(request->request_ctx, dict_protocol, &request->request_pairs, fp, &filedone) < 0) {
		goto error;
	}

	/*
	 *	Pretend that the attributes came in "over the wire".
	 *
	 *	@todo - do this only for protocol attributes, and not internal ones?
	 */
	fr_pair_list_tainted(&request->request_pairs);

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_packet_type);
	if (!vp) {
		fr_strerror_printf("Input packet does not specify a Packet-Type");
		goto error;
	}
	/*
	 *	Set the defaults for IPs, etc.
	 */
	request->packet->code = vp->vp_uint32;

	/*
	 *	Now delete the packet-type to ensure
	 *	the virtual attribute gets used in
	 *	the tests.
	 */
	fr_pair_delete_by_da(&request->request_pairs, attr_packet_type);

	request->packet->socket = (fr_socket_t){
		.proto = IPPROTO_UDP,
		.inet = {
			.src_ipaddr = {
				.af = AF_INET,
				.prefix = 32,
				.addr = {
					.v4 = {
						.s_addr = htonl(INADDR_LOOPBACK)
					}
				}
			},
			.src_port = 18120,
			.dst_ipaddr = {
				.af = AF_INET,
				.prefix = 32,
				.addr = {
					.v4 = {
						.s_addr = htonl(INADDR_LOOPBACK)
					}
				}
			},
			.dst_port = 1812
		}
	};

	for (vp = fr_pair_dcursor_init(&cursor, &request->request_pairs);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
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

	if (fr_debug_lvl) {
		for (vp = fr_pair_dcursor_init(&cursor, &request->request_pairs);
		     vp;
		     vp = fr_dcursor_next(&cursor)) {
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
	fr_pair_list_init(&request->reply_pairs);
	request->reply->data = NULL;
	request->reply->data_len = 0;

	/*
	 *	Debugging
	 */
	request->log.dst = talloc_zero(request, log_dst_t);
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;
	request->log.lvl = fr_debug_lvl;


	/*
	 *	New async listeners
	 */
	request->async = talloc_zero(request, fr_async_t);
	unlang_call_push(request, server_cs, UNLANG_TOP_FRAME);

	return request;
}


static void print_packet(FILE *fp, fr_radius_packet_t *packet, fr_pair_list_t *list)
{
	fr_pair_t *vp;
	fr_dcursor_t cursor;
	fr_dict_enum_value_t *dv;

	if (fr_pair_list_empty(list)) {
		fprintf(fp, "\n");
		return;
	}

	dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(packet->code));
	if (dv) fprintf(fp, "%s\n", dv->name);

	for (vp = fr_pair_dcursor_init(&cursor, list);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
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
static bool do_xlats(fr_event_list_t *el, char const *filename, FILE *fp)
{
	int		lineno = 0;
	ssize_t		len;
	char		*p;
	char		input[8192];
	char		output[8192];
	request_t	*request;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_alloc_internal(NULL, NULL);
	if (!request->packet) request->packet = fr_radius_packet_alloc(request, false);
	if (!request->reply) request->reply = fr_radius_packet_alloc(request, false);

	request->packet->socket = (fr_socket_t){
		.proto = IPPROTO_UDP,
		.inet = {
			.src_ipaddr = {
				.af = AF_INET,
				.prefix = 32,
				.addr = {
					.v4 = {
						.s_addr = htonl(INADDR_LOOPBACK)
					}
				}
			},
			.src_port = 18120,
			.dst_ipaddr = {
				.af = AF_INET,
				.prefix = 32,
				.addr = {
					.v4 = {
						.s_addr = htonl(INADDR_LOOPBACK)
					}
				}
			},
			.dst_port = 1812
		}
	};

	request->log.dst = talloc_zero(request, log_dst_t);
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;

	request->master_state = REQUEST_ACTIVE;
	request->log.lvl = fr_debug_lvl;
	output[0] = '\0';

	request->async = talloc_zero(request, fr_async_t);

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
			xlat_exp_head_t		*head = NULL;
			fr_sbuff_parse_rules_t	p_rules = { .escapes = &fr_value_unescape_double };

			slen = xlat_tokenize_ephemeral(xlat_ctx, &head, el,
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
		 *	Look for "xlat_expr"
		 */
		if (strncmp(input, "xlat_expr ", 10) == 0) {
			ssize_t			slen;
			TALLOC_CTX		*xlat_ctx = talloc_init_const("xlat");
			char			*fmt = talloc_typed_strdup(xlat_ctx, input + 10);
			xlat_exp_head_t		*head = NULL;

			slen = xlat_tokenize_ephemeral_expression(xlat_ctx, &head, el,
								  &FR_SBUFF_IN(fmt, talloc_array_length(fmt) - 1),
								  NULL,
								  &(tmpl_rules_t) {
									  .attr = {
										  .dict_def = dict_protocol,
										  .allow_unresolved = true,
									  }
										  }
								);
			if (slen <= 0) {
				talloc_free(xlat_ctx);
				snprintf(output, sizeof(output), "ERROR offset %d '%s'", (int) -slen,
					 fr_strerror());
				continue;
			}

			if (input[slen + 10] != '\0') {
				talloc_free(xlat_ctx);
				snprintf(output, sizeof(output), "ERROR offset %d Unexpected text '%s' after parsing",
					 (int) slen, input + slen + 10);
				continue;
			}

			if (xlat_resolve(head, NULL) < 0) {
				talloc_free(xlat_ctx);
				snprintf(output, sizeof(output), "ERROR resolving xlat: %s", fr_strerror());
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
		 *	Look for "match".
		 */
		if (strncmp(input, "match ", 6) == 0) {
			if (strcmp(input + 6, output) != 0) {
				fprintf(stderr, "Mismatch at line %d of %s\n\tgot      : %s\n\texpected : %s\n",
					lineno, filename, output, input + 6);
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
			   tmpl_t const *src, UNUSED map_list_t const *maps)
{
	if (!src) {
		cf_log_err(cs, "Missing source");

		return -1;
	}

	return 0;
}

static rlm_rcode_t mod_map_proc(UNUSED void *mod_inst, UNUSED void *proc_inst, UNUSED request_t *request,
			      	UNUSED fr_value_box_list_t *src, UNUSED map_list_t const *maps)
{
	return RLM_MODULE_FAIL;
}

static request_t *request_clone(request_t *old, int number, CONF_SECTION *server_cs)
{
	request_t *request;

	request = request_alloc_internal(NULL, NULL);
	if (!request) return NULL;

	if (!request->packet) request->packet = fr_radius_packet_alloc(request, false);
	if (!request->reply) request->reply = fr_radius_packet_alloc(request, false);

	memcpy(request->packet, old->packet, sizeof(*request->packet));
	(void) fr_pair_list_copy(request->request_ctx, &request->request_pairs, &old->request_pairs);
	request->packet->timestamp = fr_time();
	request->number = number;
	request->name = talloc_typed_asprintf(request, "%" PRIu64, request->number);

	unlang_call_push(request, server_cs, UNLANG_TOP_FRAME);

	request->master_state = REQUEST_ACTIVE;
	request->dict = old->dict;

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
	request_t		*request = NULL;
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

	CONF_SECTION		*server_cs;

	fr_pair_list_init(&filter_vps);
	/*
	 *	Must be called first, so the handler is called last
	 */
	fr_atexit_global_setup();

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
	fr_hostname_lookups = fr_reverse_lookups = false;

	/*
	 *	We always log to stdout.
	 */
	default_log.dst = L_DST_STDOUT;
	default_log.fd = STDOUT_FILENO;
	default_log.print_level = true;

	/*  Process the options.  */
	while ((c = getopt(argc, argv, "c:d:D:f:hi:mMn:o:O:p:r:S:xXz")) != -1) {
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

			case 'S': /* Migration support */
				if (main_config_parse_option(optarg) < 0) {
					fprintf(stderr, "%s: Unknown configuration option '%s'\n",
						config->name, optarg);
					fr_exit_now(EXIT_FAILURE);
				}
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

#ifdef WITH_TLS
	/*
	 *  Mismatch between build time OpenSSL and linked SSL, better to die
	 *  here than segfault later.
	 */
	if (fr_openssl_version_consistent() < 0) EXIT_WITH_FAILURE;

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
	modules_init(config->lib_dir);

	if (!fr_dict_global_ctx_init(NULL, true, config->dict_dir)) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

#ifdef WITH_TLS
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

	if (map_proc_register(NULL, "test-fail", mod_map_proc, map_proc_verify, 0) < 0) {
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Initialise the interpreter, registering operations.
	 *      This initialises
	 */
	if (unlang_init_global() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Ensure that we load the correct virtual server for the
	 *	protocol, if necessary.
	 */
	if (!getenv("PROTOCOL")) {
		setenv("PROTOCOL", PROTOCOL_NAME, true);
	}

	/*
	 *	Setup the global structures for module lists
	 */
	if (modules_rlm_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}
	if (virtual_servers_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (main_config_init(config) < 0) {
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

	server_cs = virtual_server_find("default");
	if (!server_cs) {
		ERROR("Cannot find virtual server 'default'");
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Do some sanity checking.
	 */
	dict_check = virtual_server_dict_by_name("default");
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
	if (modules_rlm_thread_instantiate(thread_ctx, el) < 0) EXIT_WITH_FAILURE;
	if (virtual_servers_thread_instantiate(thread_ctx, el) < 0) EXIT_WITH_FAILURE;
	if (xlat_thread_instantiate(thread_ctx, el) < 0) EXIT_WITH_FAILURE;
	unlang_thread_instantiate(thread_ctx);

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
		if (!do_xlats(el, input_file, fp)) ret = EXIT_FAILURE;
		if (input_file) fclose(fp);
		goto cleanup;
	}

	/*
	 *	Grab the VPs from stdin, or from the file.
	 */
	request = request_from_file(autofree, fp, client, server_cs);
	if (!request) {
		fr_perror("Failed reading input from %s", input_file);
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

		if (fr_pair_list_afrom_file(request->request_ctx, dict_protocol, &filter_vps, fp, &filedone) < 0) {
			fr_perror("Failed reading attributes from %s", filter_file);
			EXIT_WITH_FAILURE;
		}

		/*
		 *	Filter files can't be empty.
		 */
		if (fr_pair_list_empty(&filter_vps)) {
			fr_perror("No attributes in filter file %s", filter_file);
			EXIT_WITH_FAILURE;
		}

		/*
		 *	FIXME: loop over input packets.
		 */
		fclose(fp);
	}

	if (count == 1) {
		unlang_interpret_synchronous(el, request);

	} else {
		int i;
		request_t *cached = request;

		for (i = 0; i < count; i++) {
			request = request_clone(cached, i, server_cs);

#ifndef NDEBUG
			/*
			 *	Artificially limit the number of instructions which are run.
			 */
			if (config->ins_max) {
				if (config->ins_countup) {
					request->ins_max = i + 1;
				} else {
					request->ins_max = config->ins_max;
				}
				request->ins_count = 0;
			}
#endif

			unlang_interpret_synchronous(el, request);
			talloc_free(request);
		}

		request = cached;
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

	print_packet(fp, request->reply, &request->reply_pairs);

	if (output_file) fclose(fp);

	/*
	 *	Update the list with the response type, so that it can
	 *	be matched in filters.
	 *
	 *	Some state machines already include a response Packet-Type
	 *	so we need to try and update it, else we end up with two!
	 */
	if (!fr_pair_list_empty(&filter_vps)) {
		fr_pair_t const *failed[2];

		MEM(pair_update_reply(&vp, attr_packet_type) >= 0);
		vp->vp_uint32 = request->reply->code;


		if (!fr_pair_validate(failed, &filter_vps, &request->reply_pairs)) {
			fr_pair_validate_debug(request, failed);
			fr_perror("Output file %s does not match attributes in filter %s",
				  output_file ? output_file : "-", filter_file);
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
	 *	Ensure all thread local memory is cleaned up
	 *	at the appropriate time.  This emulates what's
	 *	done with worker/network threads in the
	 *	scheduler.
	 */
	fr_atexit_thread_trigger_all();

	/*
	 *	Give processes a chance to exit
	 */
	if (el) fr_event_list_reap_signal(el, fr_time_delta_from_sec(5), SIGKILL);

	/*
	 *	Free the event list.
	 */
	talloc_free(el);

	/*
	 *	Ensure all thread local memory is cleaned up
	 *	at the appropriate time.  This emulates what's
	 *	done with worker/network threads in the
	 *	scheduler.
	 */
	fr_atexit_thread_trigger_all();

	/*
	 *	Free request specific logging infrastructure
	 */
	log_global_free();

	server_free();

	/*
	 *	Free any resources used by the unlang interpreter.
	 */
	unlang_free_global();

	/*
	 *	Free modules, this needs to be done explicitly
	 *	because some libraries used by modules use atexit
	 *	handlers registered after ours, and they may deinit
	 *	themselves before we free the modules and cause
	 *	crashes on exit.
	 */
	modules_rlm_free();

	/*
	 *	Same with virtual servers and proto modules.
	 */
	virtual_servers_free();

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
	if (fr_dict_free(&dict, __FILE__) < 0) {
		fr_perror("unit_test_module - dict");
		ret = EXIT_FAILURE;
	}

	/*
	 *	Free any openssl resources and the TLS dictionary
	 */
#ifdef WITH_TLS
	fr_openssl_free();
#endif

	if (receipt_file && (ret == EXIT_SUCCESS) && (fr_touch(NULL, receipt_file, 0644, true, 0755) <= 0)) {
		fr_perror("unit_test_module");
		ret = EXIT_FAILURE;
	}

	if (talloc_free(autofree) < 0) {
		fr_perror("unit_test_module - autofree");
		ret = EXIT_FAILURE;
	}

	/*
	 *	Ensure our atexit handlers run before any other
	 *	atexit handlers registered by third party libraries.
	 */
	fr_atexit_global_trigger_all();

	return ret;
}


/*
 *  Display the syntax for starting this program.
 */
static NEVER_RETURNS void usage(main_config_t const *config, int status)
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
