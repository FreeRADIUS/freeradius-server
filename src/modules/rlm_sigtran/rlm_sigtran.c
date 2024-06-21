/*
 * @copyright (c) 2016, Network RADIUS SAS (license@networkradius.com)
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Network RADIUS SAS nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * $Id$
 * @file rlm_sigtran/rlm_sigtran.c
 * @brief Implement a SCTP/M3UA/SCCP/TCAP/MAP stack
 *
 * @copyright 2016 Network RADIUS SAS (license@networkradius.com)
 */
RCSID("$Id$")

#define LOG_PREFIX_ARGS mctx->mi->name

#include <osmocom/core/linuxlist.h>

#include "libosmo-m3ua/include/bsc_data.h"
#include "libosmo-m3ua/include/sctp_m3ua.h"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>

#include "sigtran.h"
#include "attrs.h"

#include <assert.h>
#include <limits.h>

#if !defined(PIPE_BUF) && defined(_POSIX_PIPE_BUF)
#  define PIPE_BUF _POSIX_PIPE_BUF
#endif

#ifdef PIPE_BUF
static_assert(sizeof(void *) < PIPE_BUF, "PIPE_BUF must be large enough to accommodate a pointer");
#endif

static uint32_t	sigtran_instances = 0;

unsigned int __hack_opc, __hack_dpc;

static fr_table_num_sorted_t const m3ua_traffic_mode_table[] = {
	{ L("broadcast"), 3 },
	{ L("loadshare"), 2 },
	{ L("override"),  1 }
};
static size_t m3ua_traffic_mode_table_len = NUM_ELEMENTS(m3ua_traffic_mode_table);

static const conf_parser_t sctp_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("server", FR_TYPE_COMBO_IP_ADDR, 0, rlm_sigtran_t, conn_conf.sctp_dst_ipaddr) },
	{ FR_CONF_OFFSET("port", rlm_sigtran_t, conn_conf.sctp_dst_port), .dflt = "2905" },

	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, rlm_sigtran_t, conn_conf.sctp_src_ipaddr ) },
	{ FR_CONF_OFFSET("src_port", rlm_sigtran_t, conn_conf.sctp_src_port), .dflt = "0" },

	{ FR_CONF_OFFSET("timeout", rlm_sigtran_t, conn_conf.sctp_timeout), .dflt = "5" },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t m3ua_route[] = {
	{ FR_CONF_OFFSET_IS_SET("dpc", FR_TYPE_UINT32, 0, sigtran_m3ua_route_t, dpc) },
	{ FR_CONF_OFFSET_FLAGS("opc" , CONF_FLAG_MULTI, sigtran_m3ua_route_t, opc) },
	{ FR_CONF_OFFSET_FLAGS("si" , CONF_FLAG_MULTI, sigtran_m3ua_route_t, si) },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t m3ua_config[] = {
	{ FR_CONF_OFFSET("link_index", rlm_sigtran_t, conn_conf.m3ua_link_index) },
	{ FR_CONF_OFFSET("routing_ctx", rlm_sigtran_t, conn_conf.m3ua_routing_context) },
	{ FR_CONF_OFFSET("traffic_mode", rlm_sigtran_t, conn_conf.m3ua_traffic_mode_str), .dflt = "loadshare" },
	{ FR_CONF_OFFSET("ack_timeout", rlm_sigtran_t, conn_conf.m3ua_ack_timeout), .dflt = "2" },
	{ FR_CONF_OFFSET("beat_interval", rlm_sigtran_t, conn_conf.m3ua_beat_interval), .dflt = "0" },

	{ FR_CONF_OFFSET_IS_SET("route", 0, CONF_FLAG_SUBSECTION, rlm_sigtran_t, conn_conf.m3ua_routes), .subcs = (void const *) m3ua_route },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t mtp3_config[] = {
	{ FR_CONF_OFFSET_FLAGS("dpc", CONF_FLAG_REQUIRED, rlm_sigtran_t, conn_conf.mtp3_dpc) },
	{ FR_CONF_OFFSET_FLAGS("opc", CONF_FLAG_REQUIRED, rlm_sigtran_t, conn_conf.mtp3_opc) },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t sccp_global_title[] = {
	{ FR_CONF_OFFSET("address", sigtran_sccp_global_title_t, address) },
	{ FR_CONF_OFFSET_IS_SET("tt", FR_TYPE_UINT8, 0, sigtran_sccp_global_title_t, tt) },
	{ FR_CONF_OFFSET_IS_SET("nai", FR_TYPE_UINT8, 0, sigtran_sccp_global_title_t, nai) },
	{ FR_CONF_OFFSET_IS_SET("np", FR_TYPE_UINT8, 0, sigtran_sccp_global_title_t, np) },
	{ FR_CONF_OFFSET_IS_SET("es", FR_TYPE_UINT8, 0, sigtran_sccp_global_title_t, es) },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t sccp_address[] = {
	{ FR_CONF_OFFSET_IS_SET("pc", FR_TYPE_UINT32, 0, sigtran_sccp_address_t, pc) },
	{ FR_CONF_OFFSET_IS_SET("ssn", FR_TYPE_UINT8, 0, sigtran_sccp_address_t, ssn) },
	{ FR_CONF_OFFSET_IS_SET("gt", 0, CONF_FLAG_SUBSECTION, sigtran_sccp_address_t, gt), .subcs = (void const *) sccp_global_title },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t sccp_config[] = {
	{ FR_CONF_OFFSET("ai8", rlm_sigtran_t, conn_conf.sccp_ai8) },
	{ FR_CONF_OFFSET("route_on_ssn", rlm_sigtran_t, conn_conf.sccp_route_on_ssn) },

	{ FR_CONF_OFFSET_SUBSECTION("called", 0, rlm_sigtran_t, conn_conf.sccp_called, sccp_address) },
	{ FR_CONF_OFFSET_SUBSECTION("calling", 0, rlm_sigtran_t, conn_conf.sccp_calling, sccp_address) },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t map_config[] = {
	{ FR_CONF_OFFSET("version", rlm_sigtran_t, conn_conf.map_version), .dflt = "2", .quote = T_BARE_WORD},

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_POINTER("sctp", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) sctp_config },
	{ FR_CONF_POINTER("m3ua", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) m3ua_config },
	{ FR_CONF_POINTER("mtp3", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) mtp3_config },
	{ FR_CONF_POINTER("sccp", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) sccp_config },
	{ FR_CONF_POINTER("map", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) map_config },

	{ FR_CONF_OFFSET_FLAGS("imsi", CONF_FLAG_REQUIRED, rlm_sigtran_t, imsi) },

	CONF_PARSER_TERMINATOR
};

fr_dict_t const *dict_eap_aka_sim;

/*
 *	UMTS vector
 */
fr_dict_attr_t const *attr_eap_aka_sim_autn;
fr_dict_attr_t const *attr_eap_aka_sim_ck;
fr_dict_attr_t const *attr_eap_aka_sim_ik;
fr_dict_attr_t const *attr_eap_aka_sim_xres;

/*
 *	GSM vector
 */
fr_dict_attr_t const *attr_eap_aka_sim_kc;
fr_dict_attr_t const *attr_eap_aka_sim_sres;

/*
 *	Shared
 */
fr_dict_attr_t const *attr_eap_aka_sim_rand;

extern fr_dict_autoload_t rlm_sigtran_dict[];
fr_dict_autoload_t rlm_sigtran_dict[] = {
	{ .out = &dict_eap_aka_sim, .base_dir = "eap/aka-sim", .proto = "eap-aka-sim" },
	{ NULL }
};

fr_dict_attr_t const *attr_auth_type;

extern fr_dict_attr_autoload_t rlm_sigtran_dict_attr[];
fr_dict_attr_autoload_t rlm_sigtran_dict_attr[] = {
	{ .out = &attr_eap_aka_sim_autn, .name = "AUTN", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_ck, .name = "CK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_ik, .name = "IK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_kc, .name = "KC", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_rand, .name = "RAND", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_sres, .name = "SRES", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },
	{ .out = &attr_eap_aka_sim_xres, .name = "XRES", .type = FR_TYPE_OCTETS, .dict = &dict_eap_aka_sim },

	{ NULL }
};

static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sigtran_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_sigtran_t);
	rlm_sigtran_thread_t const	*t = talloc_get_type_abort_const(mctx->thread, rlm_sigtran_thread_t);

	return sigtran_client_map_send_auth_info(p_result, inst, request, inst->conn, t->fd);
}

/** Convert our sccp address config structure into sockaddr_sccp
 *
 * @param ctx to allocated address in.
 * @param out Where to write the parsed data.
 * @param conf to parse.
 * @param cs specifying sccp address.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int sigtran_sccp_sockaddr_from_conf(TALLOC_CTX *ctx,
					   struct sockaddr_sccp *out,
					   sigtran_sccp_address_t *conf, CONF_SECTION *cs)
{
	/*
	 *	Fixme should be conf->gt_is_set
	 */
	if (!conf->ssn_is_set && !conf->pc_is_set && !conf->gt.address) {
		cf_log_err(cs, "At least one of 'pc', 'ssn', or 'gt', must be set");
		return -1;
	}

	if (conf->ssn_is_set) out->ssn = conf->ssn;
	if (conf->pc_is_set) {
		if (conf->pc > 16777215) {
			cf_log_err(cs, "Invalid value \"%d\" for 'pc', must be between 0-"
				      STRINGIFY(16777215), conf->pc);
			return -1;
		}
		out->use_poi = 1;

		memcpy(&out->poi, &conf->pc, sizeof(out->poi));
	}

	/*
	 *	Fixme should be conf->gt_is_set && conf->gt.address
	 *	But we don't have subsection presence checks yet.
	 */
	if (conf->gt_is_set || conf->gt.address) {
		int	gti_ind = SCCP_TITLE_IND_NONE;
		size_t	i;
		size_t	len = talloc_array_length(conf->gt.address) - 1;

		if (conf->gt.nai_is_set && (conf->gt.nai & 0x80)) {
			cf_log_err(cs, "Global title 'nai' must be between 0-127");
			return -1;
		}

		if (conf->gt.tt_is_set) {
			if ((conf->gt.np_is_set && !conf->gt.es_is_set) ||
			    (!conf->gt.np_is_set && conf->gt.np_is_set)) {
				cf_log_err(cs, "Global title 'np' and 'es' must be "
					      "specified together");
				return -1;
			}

			if (conf->gt.np) {
				cf_log_err(cs, "Global title 'np' must be between 0-15");
				return -1;
			}

			if (conf->gt.es > 0x0f) {
				cf_log_err(cs, "Global title 'es' must be between 0-15");
				return -1;
			}

			if (conf->gt.np_is_set) {
				gti_ind = conf->gt.nai_is_set ? SCCP_TITLE_IND_TRANS_NUM_ENC_NATURE :
								SCCP_TITLE_IND_TRANS_NUM_ENC;
			} else {
				gti_ind = SCCP_TITLE_IND_TRANSLATION_ONLY;
			}
		} else if (conf->gt.nai_is_set) {
			gti_ind = SCCP_TITLE_IND_NATURE_ONLY;
		}

		for (i = 0; i < len; i++) {
			if (!is_char_tbcd[(uint8_t)conf->gt.address[i]]) {
				cf_log_err(cs, "Global title address contains invalid digit \"%c\".  "
					      "Valid digits are [0-9#*a-c]", conf->gt.address[i]);
				return -1;
			}
		}

		if (sigtran_sccp_global_title(ctx, &out->gti_data, gti_ind, conf->gt.address,
					      conf->gt.tt, conf->gt.np, conf->gt.es, conf->gt.nai) < 0) return -1;
		out->gti_len = talloc_array_length(out->gti_data);
		out->gti_ind = gti_ind;
		out->national = 1;

		/*
		 *	Print out the constructed global title blob.
		 */
		DEBUG4("gt_ind: 0x%x", out->gti_ind);
		DEBUG4("digits: 0x%pH (%i)", fr_box_octets(out->gti_data, out->gti_len), out->gti_len);
	}
	return 0;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_sigtran_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_sigtran_thread_t);
	int			fd;

	fd = sigtran_client_thread_register(mctx->el);
	if (fd < 0) {
		ERROR("Failed registering thread with multiplexer");
		return -1;
	}

	t->fd = fd;

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_sigtran_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_sigtran_thread_t);

	sigtran_client_thread_unregister(mctx->el, t->fd);	/* Also closes our side */

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_sigtran_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_sigtran_t);
	CONF_SECTION const *conf = mctx->mi->conf;

	/*
	 *	Translate traffic mode string to integer
	 */
	inst->conn_conf.m3ua_traffic_mode = fr_table_value_by_str(m3ua_traffic_mode_table,
						       inst->conn_conf.m3ua_traffic_mode_str, -1);
	if (inst->conn_conf.m3ua_traffic_mode < 0) {
		cf_log_err(conf, "Invalid 'm3ua_traffic_mode' value \"%s\", expected 'override', "
			   "'loadshare' or 'broadcast'", inst->conn_conf.m3ua_traffic_mode_str);
		return -1;
	}

#define MTP3_PC_CHECK(_x) \
	do { \
		if (inst->conn_conf.mtp3_##_x > 16777215) { \
			cf_log_err(conf, "Invalid value \"%d\" for '#_x', must be between 0-16777215", \
				      inst->conn_conf.mtp3_##_x); \
			return -1; \
		} \
		__hack_##_x = inst->conn_conf.mtp3_##_x; \
	} while (0)

	MTP3_PC_CHECK(dpc);
	MTP3_PC_CHECK(opc);

	if (sigtran_sccp_sockaddr_from_conf(inst, &inst->conn_conf.sccp_called_sockaddr,
					    &inst->conn_conf.sccp_called, conf) < 0) return -1;
	if (sigtran_sccp_sockaddr_from_conf(inst, &inst->conn_conf.sccp_calling_sockaddr,
					    &inst->conn_conf.sccp_calling, conf) < 0) return -1;

	/*
	 *	Don't bother starting the sigtran thread if we're
	 *	just checking the config.
	 */
	if (check_config) return 0;

	/*
	 *	If this is the first instance of rlm_sigtran
	 *	We spawn a new thread to run all the libosmo-* I/O
	 *	and events.
	 *
	 *	We talk to the thread using the ctrl_pipe, with
	 *	each thread registering its own pipe via the ctrl_pipe.
	 *
	 *	This makes it really easy to collect and distribute
	 *	requests/responses, whilst using libosmo in a
	 *	threadsafe way.
	 */
	if (sigtran_instances == 0) sigtran_event_start();
 	sigtran_instances++;

	/*
	 *	Should bring the SCTP/M3UA/MTP3/SCCP link up.
	 */
	if (sigtran_client_link_up(&inst->conn, &inst->conn_conf) < 0) return -1;

	return 0;
}

/**
 * Cleanup internal state.
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_sigtran_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_sigtran_t);

	/*
	 *	If we're just checking the config we didn't start the
	 *	thread.
	 */
	if (check_config) return 0;

	sigtran_client_link_down(&inst->conn);

	if ((--sigtran_instances) == 0) sigtran_event_exit();

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_sigtran;
module_rlm_t rlm_sigtran = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "sigtran",
		.inst_size		= sizeof(rlm_sigtran_t),
		.thread_inst_size	= sizeof(rlm_sigtran_thread_t),
		.config			= module_config,
		.instantiate		= mod_instantiate,
		.detach			= mod_detach,
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_authorize },
			MODULE_BINDING_TERMINATOR
		}
	}
};
