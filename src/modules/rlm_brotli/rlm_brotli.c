/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_brotli.c
 * @brief Add support for brotli compression
 *
 * @copyright 2024 The FreeRADIUS server project
 * @copyright 2024 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->mi->name

#include <brotli/encode.h>
#include <brotli/decode.h>

#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/value.h>

#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/cf_parse.h>

#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/xlat_func.h>

static int quality_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int window_bits_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int block_bits_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

typedef struct {
	BrotliEncoderMode		mode;			//!< Default mode to use when compressing data.
	int				quality;		//!< Default quality to use when compressing data.
	int				window_bits;		//!< Default window bits to use when compressing data.
	int				block_bits;		//!< Default block bits to use when compressing data.
	bool				block_bits_is_set;	//!< Whether block_bits has been set.
} rlm_brotli_compress_t;

typedef struct {
	size_t				max_size;		//!< Maximum amount we attempt to decode
} rlm_brotli_decompress_t;

typedef struct {
	rlm_brotli_compress_t		compress;		//!< Compression settings
	rlm_brotli_decompress_t		decompress;		//!< Decompression settings
	bool				large_window;		//!< non-standard "large", window size.
} rlm_brotli_t;

static fr_table_num_sorted_t const brotli_mode[] = {
	{ L("font"),		BROTLI_MODE_FONT	},	//!< Probably not useful?
	{ L("generic"),		BROTLI_MODE_GENERIC	},
	{ L("text"),		BROTLI_MODE_TEXT	},
};
static size_t brotli_mode_len = NUM_ELEMENTS(brotli_mode);

static const conf_parser_t module_compress_config[] = {
	{ FR_CONF_OFFSET("mode", rlm_brotli_compress_t, mode), .dflt = "generic",
			 .func = cf_table_parse_int, .uctx = &(cf_table_parse_ctx_t){ .table = brotli_mode, .len = &brotli_mode_len } },
	{ FR_CONF_OFFSET("quality", rlm_brotli_compress_t, quality), .dflt = STRINGIFY(BROTLI_DEFAULT_QUALITY), .func = quality_parse },
	{ FR_CONF_OFFSET("window_bits", rlm_brotli_compress_t, window_bits), .dflt = STRINGIFY(BROTLI_DEFAULT_WINDOW), .func = window_bits_parse },
	{ FR_CONF_OFFSET_IS_SET("block_bits", FR_TYPE_INT32, 0, rlm_brotli_compress_t, block_bits), .dflt = STRINGIFY(BROTLI_MAX_INPUT_BLOCK_BITS), .func = block_bits_parse },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t module_decompress_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("max_size", FR_TYPE_SIZE, 0, rlm_brotli_decompress_t, max_size), .dflt = "10M" }, /* 10MB */
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("compress", 0, rlm_brotli_t, compress, module_compress_config) },
	{ FR_CONF_OFFSET_SUBSECTION("decompress", 0, rlm_brotli_t, decompress, module_decompress_config) },
	{ FR_CONF_OFFSET("large_window", rlm_brotli_t, large_window), .dflt = "no" },	/* For both compress and decompress */

	CONF_PARSER_TERMINATOR
};

static _Thread_local TALLOC_CTX	*brotli_pool;	//!< Thread-local pool for brotli state

static inline CC_HINT(always_inline)
TALLOC_CTX *brotli_pool_get(void)
{
	if (unlikely(brotli_pool == NULL)) {
		TALLOC_CTX *pool;

		MEM(pool = talloc_pool(NULL, 4096));
		fr_atexit_thread_local(brotli_pool, fr_atexit_talloc_free, pool);

	}
	return brotli_pool;
}

static void *brotli_talloc_alloc(void *uctx, size_t size)
{
	void *ptr = talloc_size(uctx, size);
	return ptr;
}

static void brotli_talloc_free(UNUSED void *uctx, void *to_free)
{
	talloc_free(to_free);
}

static int quality_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	int			ret;
	int			value;

	ret = cf_pair_parse_value(ctx, out, parent, ci, rule);
	if (ret < 0) return ret;

	value = *(int *) out;
	if ((value > BROTLI_MAX_QUALITY) || (value < BROTLI_MIN_QUALITY)) {
		cf_log_err(ci, "Allowed values are between %d-%d, got %d", BROTLI_MIN_QUALITY, BROTLI_MAX_QUALITY, value);
		return -1;
	}

	return 0;
}

static int window_bits_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	int			ret;
	int			value;

	ret = cf_pair_parse_value(ctx, out, parent, ci, rule);
	if (ret < 0) return ret;

	value = *(int *) out;
	if ((value > BROTLI_MAX_WINDOW_BITS) || (value < BROTLI_MIN_WINDOW_BITS)) {
		cf_log_err(ci, "Allowed values are between %d-%d, got %d", BROTLI_MIN_WINDOW_BITS, BROTLI_MAX_WINDOW_BITS, value);
		return -1;
	}

	return 0;
}

static int block_bits_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	int			ret;
	int			value;

	ret = cf_pair_parse_value(ctx, out, parent, ci, rule);
	if (ret < 0) return ret;

	value = *(int *) out;
	if ((value > BROTLI_MAX_INPUT_BLOCK_BITS) || (value < BROTLI_MIN_INPUT_BLOCK_BITS)) {
		cf_log_err(ci, "Allowed values are between %d-%d, got %d", BROTLI_MIN_INPUT_BLOCK_BITS, BROTLI_MAX_INPUT_BLOCK_BITS, value);
		return -1;
	}

	return 0;
}

static xlat_arg_parser_t const brotli_xlat_compress_args[] = {
	{ .required = true, .type = FR_TYPE_OCTETS },			/* Input converted to raw binary data.  All inputs will be added to the same stream */
	XLAT_ARG_PARSER_TERMINATOR
};

/** Produce a brotli compressed string
 *
 * Example:
@verbatim
%brotli.compress(<input>) == <compressed data>
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t brotli_xlat_compress(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 	  xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *args)
{
	rlm_brotli_t const		*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_brotli_t);
	fr_value_box_t const		*data_vb;

	BrotliEncoderState		*state;
	TALLOC_CTX			*pool;

	size_t				available_out = 0, total_out = 0, total_in = 0;
	fr_value_box_t			*out_vb;
	uint8_t				*out_buff;

	xlat_action_t			ret = XLAT_ACTION_DONE;

	XLAT_ARGS(args, &data_vb);

	fr_assert(fr_type_is_group(data_vb->type));

	/*
	 *	Calculate the maximum size of our output buffer
	 *	and pre-allocate that.  We'll shrink it later.
	 */
	fr_value_box_list_foreach(&data_vb->vb_group, vb) {
		total_in += vb->vb_length;
		available_out += BrotliEncoderMaxCompressedSize(vb->vb_length);
	}

	MEM(out_vb = fr_value_box_alloc(ctx, FR_TYPE_OCTETS, NULL));
	MEM(fr_value_box_mem_alloc(out_vb, &out_buff, out_vb, NULL, available_out, false) == 0);

	pool = brotli_pool_get();
	MEM(state = BrotliEncoderCreateInstance(brotli_talloc_alloc, brotli_talloc_free, pool));

	BrotliEncoderSetParameter(state, BROTLI_PARAM_MODE, inst->compress.mode);
	BrotliEncoderSetParameter(state, BROTLI_PARAM_QUALITY, inst->compress.quality);
	BrotliEncoderSetParameter(state, BROTLI_PARAM_LGWIN, inst->compress.window_bits);
	if (inst->compress.block_bits_is_set) BrotliEncoderSetParameter(state, BROTLI_PARAM_LGBLOCK, inst->compress.block_bits);
	BrotliEncoderSetParameter(state, BROTLI_PARAM_LARGE_WINDOW, inst->large_window ? BROTLI_TRUE : BROTLI_FALSE);
	BrotliEncoderSetParameter(state, BROTLI_PARAM_SIZE_HINT, total_in);
	/*
	 *	Loop over all the input data and ingest it into brotli
	 *	which will add it to an internal buffer (hopefully
	 *	allocated, in our thread local pool).
	 */
	{
		fr_value_box_list_foreach(&data_vb->vb_group, vb) {
			size_t available_in = vb->vb_length;
			const uint8_t *next_in = vb->vb_octets;
			bool more = fr_value_box_list_next(&data_vb->vb_group, vb) != NULL;

			/*
			 *	In reality this loop is probably unnecessary,
			 *	but the brotli docs state:
			 *
			 *	"client should repeat BROTLI_OPERATION_FINISH operation until available_in becomes 0,
			 *	 and BrotliEncoderHasMoreOutput returns BROTLI_FALSE"
			 */
			do {
				BROTLI_BOOL bret;

				bret = BrotliEncoderCompressStream(state,
								   more ? BROTLI_OPERATION_PROCESS : BROTLI_OPERATION_FINISH,
								   &available_in, &next_in, &available_out, &out_buff, &total_out);
				if (bret == BROTLI_FALSE) {
					fr_assert_msg(0, "BrotliEncoderCompressStream returned false, this shouldn't happen");
					RERROR("BrotliEncoderCompressStream failed");
					ret = XLAT_ACTION_FAIL;
					goto finish;
				}
			} while (more && (available_in > 0) && (BrotliEncoderHasMoreOutput(state) == BROTLI_FALSE));

			/*
			 *	There's no reason brotli wouldn't consume the complete
			 *	buffer on BROTLI_OPERATION_PROCESS.
			 */
			fr_assert(available_in == 0);
		}
	}

	/*
	 *	Realloc to the correct size if necessary
	 */
	if (available_out != 0) MEM(fr_value_box_mem_realloc(out_vb, NULL, out_vb, total_out) == 0);

	fr_dcursor_insert(out, out_vb);

finish:
	BrotliEncoderDestroyInstance(state);
	talloc_free_children(pool);

	return ret;
}

static xlat_arg_parser_t const brotli_xlat_decompress_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_OCTETS },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Decompress a brotli string
 *
 * Example:
@verbatim
%brotli.decompress(<input>) == <decompressed data>
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t brotli_xlat_decompress(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 	    xlat_ctx_t const *xctx,
					    request_t *request, fr_value_box_list_t *args)
{
	rlm_brotli_t const		*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_brotli_t);
	fr_value_box_t const		*data_vb;

	BrotliDecoderState		*state;
	TALLOC_CTX			*pool;

	fr_value_box_t			*out_vb;

	size_t				total_in;
	size_t				available_out;
	size_t				total_out = 0;

	uint8_t	const			*in_buff;
	uint8_t				*out_buff;

	xlat_action_t			ret = XLAT_ACTION_DONE;

	XLAT_ARGS(args, &data_vb);

	pool = brotli_pool_get();
	MEM(state = BrotliDecoderCreateInstance(brotli_talloc_alloc, brotli_talloc_free, pool));

	MEM(out_vb = fr_value_box_alloc(ctx, FR_TYPE_OCTETS, NULL));
	total_in = data_vb->vb_length;
	in_buff = data_vb->vb_octets;
	available_out = (data_vb->vb_length * 2);

	MEM(fr_value_box_mem_alloc(out_vb, &out_buff, out_vb, NULL, available_out, false) == 0);
	pool = brotli_pool_get();
	MEM(state = BrotliDecoderCreateInstance(brotli_talloc_alloc, brotli_talloc_free, pool));

	BrotliDecoderSetParameter(state, BROTLI_DECODER_PARAM_LARGE_WINDOW, inst->large_window ? BROTLI_TRUE : BROTLI_FALSE);

	for (;;) {
		switch (BrotliDecoderDecompressStream(state, &total_in, &in_buff, &available_out, &out_buff, &total_out)) {
		default:
		case BROTLI_DECODER_RESULT_ERROR:
		{
			BrotliDecoderErrorCode error = BrotliDecoderGetErrorCode(state);
			REDEBUG("Decompressing brotli data failed - %s", BrotliDecoderErrorString(error));
			ret = XLAT_ACTION_FAIL;
			goto finish;
		}

		case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
			REDEBUG("Incomplete or truncated brotli data provided.  Decompressor wants more input...");
			ret = XLAT_ACTION_FAIL;
			goto finish;

		case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
		{
			size_t extra = out_vb->vb_length;

			/*
			 *	Stop runaway brotli decodings...
			 */
			if ((out_vb->vb_length + extra) > inst->decompress.max_size) {
				RERROR("Decompressed data exceeds maximum size of %zu", inst->decompress.max_size);
				ret = XLAT_ACTION_FAIL;
				goto finish;
			}

			MEM(fr_value_box_mem_realloc(out_vb, &out_buff, out_vb, out_vb->vb_length + extra) == 0);
			available_out += extra;
		}
			continue;	/* Again! */

		case BROTLI_DECODER_RESULT_SUCCESS:
			if (BrotliDecoderIsFinished(state) == BROTLI_TRUE) {
				MEM(fr_value_box_mem_realloc(out_vb, &out_buff, out_vb, total_out) == 0);
				fr_dcursor_insert(out, out_vb);
				goto finish;
			}
			continue;	/* Again! */
		}
	}

finish:
	BrotliDecoderDestroyInstance(state);
	talloc_free_children(pool);

	return ret;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t	*xlat;

	if (unlikely((xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "compress", brotli_xlat_compress,
						       FR_TYPE_OCTETS)) == NULL)) return -1;
	xlat_func_args_set(xlat, brotli_xlat_compress_args);

	if (unlikely((xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "decompress", brotli_xlat_decompress,
						       FR_TYPE_OCTETS)) == NULL)) return -1;
	xlat_func_args_set(xlat, brotli_xlat_decompress_args);

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
extern module_rlm_t rlm_brotli;
module_rlm_t rlm_brotli = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "brotli",
		.inst_size		= sizeof(rlm_brotli_t),
		.bootstrap		= mod_bootstrap,
		.config			= module_config
	}
};
