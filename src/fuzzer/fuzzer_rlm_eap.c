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
 *   along with this program; if not, write to the Free Software Foundation,
 *   Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/**
 * @file src/fuzzer/fuzzer_rlm_eap.c
 * @brief Fuzz the rlm_eap request path with the EAP-MD5 submodule.
 *
 * The first byte selects a preloaded EAP configuration profile.  The
 * remaining input is one or more EAP frames separated by "FUZZ".  A frame
 * normally contains one raw EAP packet.  Frames beginning with "CBND" use:
 *
 *   "CBND" | EAP packet | EAP-Channel-Binding-Message value
 *
 * The next "FUZZ" delimiter bounds the frame.  The EAP length field determines
 * where the channel-binding value begins.  The envelope adds the RADIUS
 * channel-binding attribute to the request.
 * Packets are installed in a RADIUS Access-Request and run through the
 * configured eap module and unlang interpreter.
 */
RCSID("$Id$")

#include <freeradius-devel/fuzzer/common.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/thread.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/main_loop.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/unlang/interpret.h>

static fr_dict_attr_t const	*attr_eap_message;
static fr_dict_attr_t const	*attr_eap_channel_binding_message;
static fr_dict_attr_t const	*attr_state;
static fr_dict_t const		*dict_radius;
static fr_event_list_t		*el;
static TALLOC_CTX		*thread_ctx;
static main_config_t		*config;
static uint8_t const		frame_delimiter[] = "FUZZ";
static uint8_t const		chbind_frame_magic[] = "CBND";
static char const * const	server_names[] = {
	"fuzz-md5",
	"fuzz-md5-realm",
	"fuzz-gtc",
	"fuzz-mschapv2",
	"fuzz-tls",
	"fuzz-peap-ttls"
};
static CONF_SECTION		*server_cs[NUM_ELEMENTS(server_names)];

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len);

typedef struct {
	uint8_t const	*eap;
	size_t		eap_len;
	uint8_t const	*chbind;
	size_t		chbind_len;
} eap_frame_t;

static void eap_frame_parse(eap_frame_t *out, uint8_t const *data, size_t len)
{
	size_t eap_len;

	if ((len < sizeof(chbind_frame_magic) - 1 + 4) ||
		(memcmp(data, chbind_frame_magic, sizeof(chbind_frame_magic) - 1) != 0)) {
		out->eap = data;
		out->eap_len = len;
		out->chbind = NULL;
		out->chbind_len = 0;
		return;
	}

	eap_len = ((size_t)data[sizeof(chbind_frame_magic) + 1] << 8) |
		  data[sizeof(chbind_frame_magic) + 2];
	if (eap_len > (len - (sizeof(chbind_frame_magic) - 1)))
		eap_len = len - (sizeof(chbind_frame_magic) - 1);

	out->eap = data + sizeof(chbind_frame_magic) - 1;
	out->eap_len = eap_len;
	out->chbind = out->eap + eap_len;
	out->chbind_len = len - (sizeof(chbind_frame_magic) - 1) - eap_len;
}

static void cancel_request(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t when, void *uctx)
{
	request_t *request = talloc_get_type_abort(uctx, request_t);

	unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
	request->rcode = RLM_MODULE_TIMEOUT;
}

static void fuzzer_rlm_eap_free(void)
{
	talloc_free(thread_ctx);
	server_free();
	virtual_servers_free();
	modules_rlm_free();
	main_loop_free();
	main_config_free(&config);
#ifdef WITH_TLS
	fr_tls_dict_free();
	fr_openssl_free();
#endif
	log_global_free();
}

static request_t *request_alloc(TALLOC_CTX *ctx, CONF_SECTION *server, eap_frame_t const *frame,
				fr_pair_t const *state)
{
	request_t	*request;
	fr_pair_t	*vp;

	request = request_local_alloc_external(ctx, &(request_init_args_t){
		.namespace = dict_radius
	});
	if (!request) return NULL;

	request->packet = fr_packet_alloc(request, false);
	request->reply = fr_packet_alloc(request, false);
	if (!request->packet || !request->reply) return NULL;

	request->packet->code = FR_RADIUS_CODE_ACCESS_REQUEST;
	request->packet->timestamp = fr_time();
	request->reply->code = 0;

	vp = fr_pair_afrom_da(request->request_ctx, attr_eap_message);
	if (!vp) return NULL;
	if (fr_pair_value_memdup(vp, frame->eap, frame->eap_len, false) < 0) return NULL;
	fr_pair_append(&request->request_pairs, vp);

	if (frame->chbind_len > 0) {
		vp = fr_pair_afrom_da_nested(request->request_ctx, &request->request_pairs,
					      attr_eap_channel_binding_message);
		if (!vp) return NULL;
		if (fr_pair_value_memdup(vp, frame->chbind, frame->chbind_len, false) < 0) return NULL;
	}

	if (state) {
		vp = fr_pair_copy(request->request_ctx, state);
		if (!vp) return NULL;
		fr_pair_append(&request->request_pairs, vp);
	}

	request->log.dst = talloc_zero(request, log_dst_t);
	if (!request->log.dst) return NULL;
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;
	request->log.dst->lvl = fr_debug_lvl;
	request->log.lvl = fr_debug_lvl;
	request->master_state = REQUEST_ACTIVE;

	request->async = talloc_zero(request, fr_async_t);
	if (!request->async) return NULL;
	request->async->request = request;

	if (unlang_call_push(NULL, request, server, UNLANG_TOP_FRAME) < 0) return NULL;

	return request;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	virtual_server_t const	*virtual_server;
	fr_dict_attr_t const	*attr_vendor_specific, *attr_ukerna;
	size_t			i;

	default_log.dst = L_DST_STDERR;
	default_log.fd = STDERR_FILENO;
	default_log.print_level = true;
	default_log.suppress_secrets = true;

	if (fuzzer_common_init(argc, argv, false) < 0) fr_exit_now(EXIT_FAILURE);

#ifdef WITH_TLS
	if (fr_openssl_init() < 0) goto error;
	if (fr_tls_dict_init() < 0) goto error;
#endif

	config = main_config_alloc(autofree);
	if (!config) goto error;

	main_config_name_set_default(config, "fuzzer_rlm_eap", false);
	main_config_confdir_set(config, "src/tests/fuzzer-rlm-eap");

	modules_init(config->lib_dir);
	if (request_global_init() < 0) goto error;
	if (main_loop_init() < 0) goto error;
	if (unlang_global_init() < 0) goto error;
	if (modules_rlm_init() < 0) goto error;
	if (virtual_servers_init() < 0) goto error;
	if (main_config_init(config) < 0) goto error;
	if (server_init(config->root_cs, config->confdir, dict) < 0) goto error;

	for (i = 0; i < NUM_ELEMENTS(server_names); i++) {
		virtual_server = virtual_server_find(server_names[i]);
		if (!virtual_server) goto error;
		server_cs[i] = virtual_server_cs(virtual_server);
	}

	el = main_loop_event_list();
	if (!el) goto error;

	thread_ctx = talloc_new(autofree);
	if (!thread_ctx) goto error;

	fr_schedule_worker_id_set(0);
	if (fr_thread_instantiate(thread_ctx, el) < 0) goto error;

	dict_radius = fr_dict_by_protocol_name("radius");
	if (!dict_radius) goto error;
	attr_eap_message = fr_dict_attr_by_name(NULL, fr_dict_root(dict_radius), "EAP-Message");
	if (!attr_eap_message) goto error;
	attr_vendor_specific = fr_dict_attr_by_name(NULL, fr_dict_root(dict_radius), "Vendor-Specific");
	if (!attr_vendor_specific) goto error;
	attr_ukerna = fr_dict_vendor_da_by_num(attr_vendor_specific, 25622);
	if (!attr_ukerna) goto error;
	attr_eap_channel_binding_message = fr_dict_attr_child_by_num(attr_ukerna, 135);
	if (!attr_eap_channel_binding_message) goto error;
	attr_state = fr_dict_attr_by_name(NULL, fr_dict_root(dict_radius), "State");
	if (!attr_state) goto error;

	default_log.dst = L_DST_NULL;

	if (atexit(fuzzer_rlm_eap_free)) goto error;

	return 0;

error:
	fr_perror("fuzzer_rlm_eap: failed initializing server");
	fr_exit_now(EXIT_FAILURE);
}

int LLVMFuzzerTestOneInput(uint8_t const *buf, size_t len)
{
	TALLOC_CTX		*ctx;
	request_t		*request;
	fr_pair_t		*state = NULL;
	uint8_t const		*frame, *next, *end;
	CONF_SECTION		*server;
	eap_frame_t		eap_frame;

	if (!attr_eap_message) LLVMFuzzerInitialize(NULL, NULL);
	if (len < 2) return 0;

	ctx = talloc_init_const("fuzzer_rlm_eap");
	if (!ctx) return 0;

	server = server_cs[buf[0] % NUM_ELEMENTS(server_cs)];
	frame = buf + 1;
	end = buf + len;
	while (frame < end) {
		next = memmem(frame, end - frame, frame_delimiter, sizeof(frame_delimiter) - 1);
		eap_frame_parse(&eap_frame, frame, next ? (size_t)(next - frame) : (size_t)(end - frame));

		request = request_alloc(ctx, server, &eap_frame, state);
		talloc_free(state);
		state = NULL;

		if (request) {
			if (fr_timer_in(request, el->tl, &request->timeout, fr_time_delta_from_msec(10),
					false, cancel_request, request) < 0) {
				talloc_free(request);
				goto next_frame;
			}

			unlang_interpret_synchronous(el, request);
			state = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_state);
			if (state) state = fr_pair_copy(ctx, state);
			FR_TIMER_DISARM(request->timeout);
		}

		talloc_free(request);

	next_frame:
		if (!next) break;
		frame = next + sizeof(frame_delimiter) - 1;
	}

	talloc_free(ctx);
	fr_strerror_clear();

	return 0;
}
