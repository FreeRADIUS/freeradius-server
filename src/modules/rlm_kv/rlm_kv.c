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
 *
 */

/**
 * $Id$
 * @file rlm_kv.c
 * @brief Provide an ephemeral, in-memory kv store.
 *
 *  This module will use infinite memory if asked, as it doesn't track
 *  or expire old entries.
 *
 *  This module uses cross-thread mutex locks, so if used a lot, it
 *  will cause all threads to synchronise, and will kill performance.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradus.com)
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->mi->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/unlang/xlat_func.h>

#include <freeradius-devel/util/htrie.h>

typedef struct rlm_kv_data_s rlm_kv_data_t;

FR_DLIST_TYPES(rlm_kv_list)
FR_DLIST_TYPEDEFS(rlm_kv_list, rlm_kv_list_t, rlm_kv_entry_t)

/** KV structure
 *
 *  The "key" field MUST be first, so that we can do lookups by giving
 *  the htrie code a "fr_value_box_t*", which is the key.
 */
struct rlm_kv_data_s {
	fr_value_box_t		key;		//!< indexed key
	fr_value_box_t		value;		//!< value to store
	rlm_kv_entry_t		entry;		//!< for expiration
};

FR_DLIST_FUNCS(rlm_kv_list, rlm_kv_data_t, entry)

/** Mutable data structure which is shared across all threads.
 *
 */
typedef struct {
	fr_htrie_t	*tree;		//!< for kv stores.
	rlm_kv_list_t	list;		//!< for expiring old entries
	pthread_mutex_t mutex;		//!< for thread locking.
} rlm_kv_mutable_t;

typedef struct {
	uint32_t		max_entries;
	fr_htrie_type_t		htype;
	char const		*key_type;	//!< data type of the key
	fr_type_t		type;
	rlm_kv_mutable_t	*mutable;
} rlm_kv_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("key_type", rlm_kv_t, key_type), .dflt = "string" },

	{ FR_CONF_OFFSET("max_entries", rlm_kv_t, max_entries), .dflt = "8192" },

	CONF_PARSER_TERMINATOR
};

static xlat_arg_parser_t const kv_write_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_VOID },
	{ .required = true, .single = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_arg_parser_t const kv_read_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_VOID },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Write an entry to the KV
 *
 *  %kv.write(key, value)
 */
static xlat_action_t kv_write_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				   xlat_ctx_t const *xctx,
				   UNUSED request_t *request, fr_value_box_list_t *args)
{
	rlm_kv_t const		*in = talloc_get_type_abort(xctx->mctx->mi->data, rlm_kv_t);
	rlm_kv_mutable_t	*inst = talloc_get_type_abort(in->mutable, rlm_kv_mutable_t);
	fr_value_box_t		*key, *value;
	rlm_kv_data_t		*data, *old = NULL;

	XLAT_ARGS(args, &key, &value);

	if (key->type != in->type) {
		RWDEBUG("Invalid key data type %s - expected %s",
			fr_type_to_str(key->type), fr_type_to_str(in->type));
		return XLAT_ACTION_FAIL;
	}

	MEM(data = talloc_zero(inst, rlm_kv_data_t));
	if (fr_value_box_copy(data, &data->key, key) < 0) {
		talloc_free(data);
		return XLAT_ACTION_FAIL;
	}
	if (fr_value_box_copy(data, &data->value, value) < 0) {
		talloc_free(data);
		return XLAT_ACTION_FAIL;
	}

	pthread_mutex_lock(&inst->mutex);

	if (fr_htrie_replace((void **) &old, inst->tree, data) < 0) {
		pthread_mutex_unlock(&inst->mutex);
		talloc_free(data);
		REDEBUG("Failed inserting (key=%pV, value=%pV)", key, value);
		return XLAT_ACTION_DONE;
	}

	/*
	 *	This is now the newest entry, as it has been recently written.
	 */
	(void) rlm_kv_list_insert_head(&inst->list, data);

	/*
	 *	We've removed the old box from the tree.  Unlink it.
	 *	And since we removed an old box, we don't have to
	 *	worry about the htrie being too full.
	 */
	if (old) {
		(void) rlm_kv_list_remove(&inst->list, old);
		talloc_free(old);

		/*
		 *	We've inserted a brand new entry.  If the list
		 *	is full, delete an old entry.
		 */
	} else if (rlm_kv_list_num_elements(&inst->list) >= in->max_entries) {
		old = rlm_kv_list_pop_tail(&inst->list);
		fr_assert(old != NULL);

		talloc_free(old);
	}

	pthread_mutex_unlock(&inst->mutex);

	return XLAT_ACTION_DONE;

}

/** Read an entry from the KV
 *
 *  %kv.read(key)
 */
static xlat_action_t kv_read_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				  xlat_ctx_t const *xctx,
				  UNUSED request_t *request, fr_value_box_list_t *args)
{
	rlm_kv_t const		*in = talloc_get_type_abort(xctx->mctx->mi->data, rlm_kv_t);
	rlm_kv_mutable_t	*inst = talloc_get_type_abort(in->mutable, rlm_kv_mutable_t);
	fr_value_box_t		*key, *dst;
	rlm_kv_data_t		*data;

	XLAT_ARGS(args, &key);

	if (key->type != in->type) {
		RWDEBUG("Invalid key data type %s - expected %s",
			fr_type_to_str(key->type), fr_type_to_str(in->type));
		return XLAT_ACTION_FAIL;
	}

	pthread_mutex_lock(&inst->mutex);
	data = fr_htrie_find(inst->tree, key);
	if (!data) {
		pthread_mutex_unlock(&inst->mutex);
		RDEBUG("Failed to find entry for key %pV", key);
		return XLAT_ACTION_DONE;
	}

	MEM(dst = fr_value_box_acopy(ctx, &data->value));

	/*
	 *	This item was recently accessed.  It's therefore now
	 *	the newest entry.
	 */
	(void) rlm_kv_list_remove(&inst->list, data);
	(void) rlm_kv_list_insert_head(&inst->list, data);

	pthread_mutex_unlock(&inst->mutex);
	
	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;

}

/** Delete an entry from the KV
 *
 *  Returns the deleted entry, if one exists.  Otherwise returns nothing.
 *
 *  %kv.delete(key)
 */
static xlat_action_t kv_delete_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				    xlat_ctx_t const *xctx,
				    UNUSED request_t *request, fr_value_box_list_t *args)
{
	rlm_kv_t const		*in = talloc_get_type_abort(xctx->mctx->mi->data, rlm_kv_t);
	rlm_kv_mutable_t	*inst = talloc_get_type_abort(in->mutable, rlm_kv_mutable_t);
	fr_value_box_t		*key, *dst;
	rlm_kv_data_t		*data;

	XLAT_ARGS(args, &key);

	if (key->type != in->type) {
		RWDEBUG("Invalid key data type %s - expected %s",
			fr_type_to_str(key->type), fr_type_to_str(in->type));
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	@todo - if the key is a string, allow wildcards in the
	 *	deletion path.  In which case we need to be able to
	 *	walk over the entire htrie.  And the htrie API doesn't
	 *	support that yet.
	 */

	pthread_mutex_lock(&inst->mutex);
	data = fr_htrie_remove(inst->tree, key);
	if (!data) {
		pthread_mutex_unlock(&inst->mutex);
		return XLAT_ACTION_DONE;
	}
	(void) rlm_kv_list_remove(&inst->list, data);

	pthread_mutex_unlock(&inst->mutex);

	MEM(dst = fr_value_box_acopy(ctx, &data->value));
	fr_dcursor_append(out, dst);

	talloc_free(data);

	return XLAT_ACTION_DONE;

}

static int mod_mutable_free(rlm_kv_mutable_t *mutable)
{
	pthread_mutex_destroy(&mutable->mutex);
	return 0;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_kv_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_kv_t);

	return talloc_free(inst->mutable);
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_kv_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_kv_t);
	
	/*
	 *	Get the data type, and convert it to an htrie type.
	 */
	inst->type = fr_type_from_str(inst->key_type);
	if (inst->type == FR_TYPE_NULL) {
		cf_log_err(mctx->mi->conf, "Unknown data type '%s'", inst->key_type);
		return -1;
	}

	inst->htype = fr_htrie_hint(inst->type);
	if (inst->htype == FR_HTRIE_INVALID) {
		cf_log_err(mctx->mi->conf, "Invalid data type '%s' for KV store", inst->key_type);
		return -1;
	}

	MEM(inst->mutable = talloc_zero(NULL, rlm_kv_mutable_t));

	inst->mutable->tree = fr_htrie_alloc(inst->mutable, inst->htype,
					     (fr_hash_t) fr_value_box_hash,
					     (fr_cmp_t) fr_value_box_cmp,
					     (fr_trie_key_t) fr_value_box_to_key, NULL);
	if (!inst->mutable->tree) return -1;

	pthread_mutex_init(&inst->mutable->mutex, NULL);
	talloc_set_destructor(inst->mutable, mod_mutable_free);

	rlm_kv_list_init(&inst->mutable->list);

	FR_INTEGER_BOUND_CHECK("max_entries", inst->max_entries, >=, 1024);
	FR_INTEGER_BOUND_CHECK("max_entries", inst->max_entries, <, (1 << 22)); /* 4M should be enough */

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t		*xlat;

	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "write", kv_write_xlat, FR_TYPE_NULL);
	xlat_func_args_set(xlat, kv_write_xlat_args); /* path, value */

	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "read", kv_read_xlat, FR_TYPE_VOID);
	xlat_func_args_set(xlat, kv_read_xlat_args); /* path */

	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "delete", kv_delete_xlat, FR_TYPE_VOID);
	xlat_func_args_set(xlat, kv_read_xlat_args); /* path */

	return 0;
}

extern module_rlm_t rlm_kv;
module_rlm_t rlm_kv = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "kv",
		.inst_size	= sizeof(rlm_kv_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
		.detach		= mod_detach,
	},
};
