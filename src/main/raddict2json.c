/*
 * raddict2json.c   Dump parsed FreeRADIUS v3 dictionaries as JSON.
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
 * Copyright (C) 2026 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#include <json-c/json.h>

/*
 *	JSON_C_TO_STRING_NOSLASHESCAPE arrived in json-c 0.13.  CentOS 7
 *	ships 0.11; map to a no-op there so the call site stays uniform.
 *	The only effect is "/" coming out as "\/" - still valid JSON.
 */
#ifndef JSON_C_TO_STRING_NOSLASHESCAPE
#  define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

/*
 *	Pretty-print a PW_TYPE as a stable name string.  Vendors, internal
 *	flags like array/encrypt etc. are emitted as separate JSON fields,
 *	not folded into the type string.
 */
static char const *type_name(PW_TYPE type)
{
	static char const * const names[PW_TYPE_MAX] = {
		[PW_TYPE_INVALID]         = "invalid",
		[PW_TYPE_STRING]          = "string",
		[PW_TYPE_INTEGER]         = "uint32",
		[PW_TYPE_IPV4_ADDR]       = "ipv4_addr",
		[PW_TYPE_DATE]            = "date",
		[PW_TYPE_ABINARY]         = "abinary",
		[PW_TYPE_OCTETS]          = "octets",
		[PW_TYPE_IFID]            = "ifid",
		[PW_TYPE_IPV6_ADDR]       = "ipv6_addr",
		[PW_TYPE_IPV6_PREFIX]     = "ipv6_prefix",
		[PW_TYPE_BYTE]            = "uint8",
		[PW_TYPE_SHORT]           = "uint16",
		[PW_TYPE_ETHERNET]        = "ether",
		[PW_TYPE_SIGNED]          = "int32",
		[PW_TYPE_COMBO_IP_ADDR]   = "combo_ip_addr",
		[PW_TYPE_TLV]             = "tlv",
		[PW_TYPE_EXTENDED]        = "extended",
		[PW_TYPE_LONG_EXTENDED]   = "long_extended",
		[PW_TYPE_EVS]             = "evs",
		[PW_TYPE_INTEGER64]       = "uint64",
		[PW_TYPE_IPV4_PREFIX]     = "ipv4_prefix",
		[PW_TYPE_VSA]             = "vsa",
		[PW_TYPE_TIMEVAL]         = "time_delta",
		[PW_TYPE_BOOLEAN]         = "bool",
		[PW_TYPE_COMBO_IP_PREFIX] = "combo_ip_prefix",
	};

	if ((unsigned int)type < PW_TYPE_MAX && names[type]) return names[type];
	return "unknown";
}

/*
 *	Per-attribute view: each attribute carries its enum values inline
 *	(`enum: [...]`) so consumers don't have to cross-reference a
 *	separate values list.  Look-up tables key on (vendor, attr-number)
 *	so the value walker can find the right attribute JSON object to
 *	append into.
 */
typedef struct {
	struct json_object *rfc_attrs;
	struct json_object *by_vendor;	      //!< vendor number (string) -> bucket
	struct json_object *attr_index;	       //!< "vendor:attr" -> attribute JSON object
} walk_ctx_t;

static void attr_index_put(walk_ctx_t *wctx, unsigned int vendor, unsigned int attr, struct json_object *o)
{
	char		    key[32];
	struct json_object *existing;

	/*
	 *	v3 allows multiple ATTRIBUTE entries to share an attr
	 *	number as aliases (e.g. Service-Type / User-Service-Type
	 *	both attr=6 in the standard space).  dict_walk iterates
	 *	all of them; we only want the *first* one in the index so
	 *	value_walker drops enum values onto the canonical entry
	 *	instead of the last alias.
	 */
	snprintf(key, sizeof(key), "%u:%u", vendor, attr);
	if (json_object_object_get_ex(wctx->attr_index, key, &existing)) return;
	json_object_object_add(wctx->attr_index, key, json_object_get(o));
}

static struct json_object *attr_index_get(walk_ctx_t *wctx, unsigned int vendor, unsigned int attr)
{
	char		    key[32];
	struct json_object *o;
	snprintf(key, sizeof(key), "%u:%u", vendor, attr);
	return json_object_object_get_ex(wctx->attr_index, key, &o) ? o : NULL;
}

static struct json_object *vendor_bucket(walk_ctx_t *wctx, unsigned int vendor)
{
	char		    key[16];
	struct json_object *bucket;

	snprintf(key, sizeof(key), "%u", vendor);
	if (json_object_object_get_ex(wctx->by_vendor, key, &bucket)) return bucket;

	bucket = json_object_new_object();
	{
		DICT_VENDOR *dv	  = dict_vendorbyvalue(vendor);
		char const  *name = dv ? dv->name : NULL;

		json_object_object_add(bucket, "name", name ? json_object_new_string(name) : NULL);
		json_object_object_add(bucket, "number", json_object_new_int64(vendor));
		json_object_object_add(bucket, "attributes", json_object_new_array());
	}

	json_object_object_add(wctx->by_vendor, key, bucket);
	return bucket;
}

static int attr_walker(void *ctx, void *data)
{
	walk_ctx_t	   *wctx = ctx;
	DICT_ATTR const	   *da	 = data;
	DICT_ATTR const	   *canonical;
	unsigned int	    vendor;
	struct json_object *o = json_object_new_object();
	struct json_object *target;

	/*
	 *	v3 packs TLV/EVS parent-attribute information into the top
	 *	byte of `vendor`.  Real IANA vendor numbers occupy the low
	 *	24 bits (FR_MAX_VENDOR is 1 << 24).  Strip the parent bits
	 *	so nested attributes land in their actual vendor bucket
	 *	instead of generating ghost vendors keyed on the encoded
	 *	parent number.
	 */
	vendor = da->vendor & (FR_MAX_VENDOR - 1);

	json_object_object_add(o, "name", json_object_new_string(da->name));
	json_object_object_add(o, "number", json_object_new_int64(da->attr));
	json_object_object_add(o, "type", json_object_new_string(type_name(da->type)));
	/*
	 *	`enum` stays absent until the value walker discovers this
	 *	attribute has VALUEs.  Saves emitting empty arrays on the
	 *	common case (most attributes have no enum values).
	 */

	if (vendor == 0) {
		target = wctx->rfc_attrs;
	} else {
		struct json_object *bucket = vendor_bucket(wctx, vendor);
		json_object_object_get_ex(bucket, "attributes", &target);
	}
	json_object_array_add(target, o);

	/*
	 *	v3 allows multiple ATTRIBUTE entries on the same number as
	 *	aliases (Service-Type / User-Service-Type both = 6).  Only
	 *	the canonical entry (the one dict_attrbyvalue returns) gets
	 *	the inline enum values - aliases stay slim.  Use the raw
	 *	(unmasked) vendor when keying the index since dict_value_walk
	 *	reports the same encoded vendor for child VALUEs.
	 */
	canonical = dict_attrbyvalue(da->attr, da->vendor);
	if (canonical == da) attr_index_put(wctx, da->vendor, da->attr, o);
	return 0;
}

static int value_walker(void *ctx, void *data)
{
	walk_ctx_t	   *wctx     = ctx;
	DICT_VALUE const   *dv	     = data;
	struct json_object *attr_obj = attr_index_get(wctx, dv->vendor, dv->attr);
	struct json_object *enums;
	struct json_object *v;

	if (!attr_obj) return 0; /* shouldn't happen, but be safe */

	if (!json_object_object_get_ex(attr_obj, "enum", &enums) || !enums ||
	    json_object_is_type(enums, json_type_null)) {
		enums = json_object_new_array();
		json_object_object_add(attr_obj, "enum", enums);
	}

	v = json_object_new_object();
	json_object_object_add(v, "name", json_object_new_string(dv->name));
	json_object_object_add(v, "number", json_object_new_int64(dv->value));
	json_object_array_add(enums, v);
	return 0;
}

static NEVER_RETURNS void usage(int rcode)
{
	FILE *fp = (rcode == 0) ? stdout : stderr;

	fprintf(fp,
		"Usage: raddict2json [options]\n"
		"  -D <dict>     Dictionary directory (default %s).\n"
		"  -n <name>     Read <name> as the entry-point dictionary (default 'dictionary').\n"
		"  -o <file>     Write JSON to <file> (default stdout).\n"
		"  -x            Enable debug output.\n"
		"  -h            This help.\n",
		DICTDIR);
	exit(rcode);
}

int main(int argc, char *argv[])
{
	int		    argval;
	int		    rcode	= EXIT_SUCCESS;
	char const	   *dict_dir	= DICTDIR;
	char const	   *dict_name	= "dictionary";
	char const	   *output_file = NULL;
	struct json_object *root;
	walk_ctx_t	    wctx;

	fr_debug_lvl = 0;
	fr_log_fp    = stderr;

	while ((argval = getopt(argc, argv, "D:hn:o:x")) != EOF) {
		switch (argval) {
		case 'D':
			dict_dir = optarg;
			break;
		case 'h':
			usage(0);
		case 'n':
			dict_name = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'x':
			fr_debug_lvl++;
			break;
		default:
			usage(1);
		}
	}

	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("raddict2json");
		exit(EXIT_FAILURE);
	}

	if (dict_init(dict_dir, dict_name) < 0) {
		fr_perror("raddict2json");
		exit(EXIT_FAILURE);
	}

	root		= json_object_new_object();
	wctx.rfc_attrs	= json_object_new_array();
	wctx.by_vendor	= json_object_new_object();
	wctx.attr_index = json_object_new_object();

	dict_walk(attr_walker, &wctx);
	dict_value_walk(value_walker, &wctx);

	json_object_object_add(root, "attributes", wctx.rfc_attrs);
	json_object_put(wctx.attr_index); /* only needed during the walk */

	/*
	 *	Flatten the by-vendor map into an ordered array under
	 *	"vendor-specific".  Lowest vendor number first so the
	 *	output diffs cleanly across raddb changes.
	 *
	 *	IANA assigns 7-digit vendor numbers, so iterating
	 *	1..max would burn CPU walking millions of empty slots.
	 *	Collect the keys that actually exist and sort them.
	 */
	{
		struct json_object *vendors = json_object_new_array();
		unsigned int	   *keys    = NULL;
		size_t		    n_keys = 0, cap = 0;

		json_object_object_foreach(wctx.by_vendor, k, _val)
		{
			(void)_val;
			if (n_keys == cap) {
				cap  = cap ? cap * 2 : 64;
				keys = realloc(keys, cap * sizeof(*keys));
			}
			keys[n_keys++] = (unsigned int)strtoul(k, NULL, 10);
		}

		/*
		 *	Insertion sort - vendor counts are in the
		 *	low hundreds, so this is fine and avoids
		 *	pulling in qsort()'s comparator boilerplate.
		 */
		for (size_t i = 1; i < n_keys; i++) {
			unsigned int x = keys[i];
			size_t	     j = i;
			while (j > 0 && keys[j - 1] > x) {
				keys[j] = keys[j - 1];
				j--;
			}
			keys[j] = x;
		}

		for (size_t i = 0; i < n_keys; i++) {
			char		    key[16];
			struct json_object *bucket;

			snprintf(key, sizeof(key), "%u", keys[i]);
			if (!json_object_object_get_ex(wctx.by_vendor, key, &bucket)) continue;
			json_object_get(bucket); /* +ref before transfer */
			json_object_array_add(vendors, bucket);
		}

		free(keys);
		json_object_object_add(root, "vendor-specific", vendors);
		json_object_put(wctx.by_vendor);
	}

	{
		char const *json_str =
			json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);

		if (output_file) {
			FILE *out = fopen(output_file, "w");
			if (!out) {
				fprintf(stderr, "Failed opening %s: %s\n", output_file, fr_syserror(errno));
				exit(EXIT_FAILURE);
			}
			fputs(json_str, out);
			fputc('\n', out);
			fclose(out);
		} else {
			fputs(json_str, stdout);
			fputc('\n', stdout);
		}
	}

	json_object_put(root);
	dict_free();
	return rcode;
}
