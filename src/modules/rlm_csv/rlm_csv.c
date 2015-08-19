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
 * @file rlm_csv.c
 * @brief Read and map CSV files
 *
 * @copyright 2015 The FreeRADIUS server project
 * @copyright 2015 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include	<freeradius-devel/map_proc.h>

static rlm_rcode_t mod_map_proc(void *mod_inst, UNUSED void *proc_inst, REQUEST *request,
				char const *key, vp_map_t const *maps);

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_csv_t {
	char const	*name;
	char const	*filename;
	char const	*delimiter;
	char const	*header;
	char const	*key;

	int		num_fields;
	int		used_fields;
	int		key_field;

	char const     	**field_names;
	int		*field_offsets; /* field X from the file maps to array entry Y here */
	rbtree_t	*tree;
} rlm_csv_t;

typedef struct rlm_csv_entry_t {
	struct rlm_csv_entry_t *next;
	char const *key;
	char *data[];
} rlm_csv_entry_t;

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT | PW_TYPE_REQUIRED | PW_TYPE_NOT_EMPTY, rlm_csv_t, filename), NULL },
	{ "delimiter", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_NOT_EMPTY, rlm_csv_t, delimiter), "," },
	{ "header", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_NOT_EMPTY, rlm_csv_t, header), NULL },
	{ "key_field", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_NOT_EMPTY, rlm_csv_t, key), NULL },
	CONF_PARSER_TERMINATOR
};

static int csv_entry_cmp(void const *one, void const *two)
{
	rlm_csv_entry_t const *a = one;
	rlm_csv_entry_t const *b = two;

	return strcmp(a->key, b->key);
}

/*
 *	Allow for quotation marks.
 */
static bool buf2entry(rlm_csv_t *inst, char *buf, char **out)
{
	char *p, *q;

	if (*buf != '"') {
		*out = strchr(buf + 1, *inst->delimiter);

		if (!*out) {	/* mash CR / LF */
			for (p = buf + 1; *p != '\0'; p++) {
				if (*p < ' ') {
					*p = '\0';
					break;
				}
			}
		}

		return true;
	}

	p = buf + 1;
	q = buf;

	while (*p) {
		if (*p < ' ') {
			*q = '\0';
			*out = NULL;
			return true;
		}

		/*
		 *	Double quotes to single quotes.
		 */
		if ((*p == '"') && (p[1] == '"')) {
			*(q++) = '"';
			p += 2;
			continue;
		}

		/*
		 *	Double quotes and EOL mean we're done.
		 */
		if ((*p == '"') && (p[1] < ' ')) {
			*(q++) = '\0';

			*out = NULL;
			return true;
		}

		/*
		 *	Double quotes and delimiter: point to the delimiter.
		 */
		if ((*p == '"') && (p[1] == *inst->delimiter)) {
			*(q++) = '\0';

			*out = p + 1;
			return true;
		}

		/*
		 *	Everything else gets copied over verbatim
		 */
		*(q++) = *(p++);
		*q = '\0';
	}

	return false;
}

/*
 *	Convert a buffer to a CSV entry
 */
static rlm_csv_entry_t *file2csv(CONF_SECTION *conf, rlm_csv_t *inst, int lineno, char *buffer)
{
	rlm_csv_entry_t *e;
	int i;
	char *p, *q;

	e = (rlm_csv_entry_t *) talloc_zero_array(inst->tree, uint8_t, sizeof(*e) + inst->used_fields + sizeof(e->data[0]));
	if (!e) {
		cf_log_err_cs(conf, "Out of memory");
		return NULL;
	}

	for (p = buffer, i = 0; p != NULL; p = q, i++) {
		if (!buf2entry(inst, p, &q)) {
			cf_log_err_cs(conf, "Malformed entry in file %s line %d", inst->filename, lineno);
			return NULL;
		}

		if (q) *(q++) = '\0';

		if (i >= inst->num_fields) {
			cf_log_err_cs(conf, "Too many fields at file %s line %d", inst->filename, lineno);
			return NULL;
		}

		/*
		 *	This is the key field.
		 */
		if (i == inst->key_field) {
			e->key = talloc_strdup(e, p);
			continue;
		}

		/*
		 *	This field is unused.  Ignore it.
		 */
		if (inst->field_offsets[i] < 0) continue;

		e->data[inst->field_offsets[i]] = talloc_strdup(e, p);
	}

	if (i < inst->num_fields) {
		cf_log_err_cs(conf, "Too few fields at file %s line %d (%d < %d)", inst->filename, lineno, i, inst->num_fields);
		return NULL;
	}

	/*
	 *	FIXME: Allow duplicate keys later.
	 */
	if (!rbtree_insert(inst->tree, e)) {
		cf_log_err_cs(conf, "Failed inserting entry for filename %s line %d: duplicate entry",
			      inst->filename, lineno);
		return NULL;
	}

	return e;
}


static int fieldname2offset(rlm_csv_t *inst, char const *field_name)
{
	int i;

	/*
	 *	Find out which field the RHS maps to.
	 *
	 *	For maps of less than 32 entries or so, an
	 *	array is faster than more complex solutions.
	 */
	for (i = 0; i < inst->num_fields; i++) {
		if (strcmp(field_name, inst->field_names[i]) == 0) {
			return inst->field_offsets[i];
		}
	}

	return -1;
}


/*
 *	Verify the result of the map.
 */
static int csv_map_verify(UNUSED void *proc_inst, void *mod_inst, UNUSED vp_tmpl_t const *src, vp_map_t const *maps)
{
	rlm_csv_t *inst = mod_inst;
	vp_map_t const *map;

	for (map = maps;
	     map != NULL;
	     map = map->next) {
		if (map->rhs->type != TMPL_TYPE_UNPARSED) continue;

		if (fieldname2offset(inst, map->rhs->name) < 0) {
			cf_log_err(map->ci, "Unknown field '%s'", map->rhs->name);
			return -1;
		}
	}

	return 0;
}


/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_csv_t *inst = instance;
	int i;
	char const *p;
	char *q;
	char *header;
	FILE *fp;
	int lineno;
	char buffer[8192];

	inst->name = cf_section_name2(conf);
	if (!inst->name) {
		inst->name = cf_section_name1(conf);
	}

	if (inst->delimiter[1]) {
		cf_log_err_cs(conf, "'delimiter' must be one character long");
		return -1;
	}

	for (p = inst->header; p != NULL; p = strchr(p + 1, *inst->delimiter)) {
		inst->num_fields++;
	}

	if (inst->num_fields < 2) {
		cf_log_err_cs(conf, "Must have at least a key field and data field");
		return -1;
	}

	inst->field_names = talloc_array(inst, const char *, inst->num_fields);
	if (!inst->field_names) {
	oom:
		cf_log_err_cs(conf, "Out of memory");
		return -1;
	}

	inst->field_offsets = talloc_array(inst, int, inst->num_fields);
	if (!inst->field_offsets) goto oom;

	for (i = 0; i < inst->num_fields; i++) {
		inst->field_offsets[i] = -1; /* unused */
	}

	/*
	 *	Get a writeable copy of the header
	 */
	header = talloc_strdup(inst, inst->header);
	if (!header) goto oom;

	/*
	 *	Mark up the field names.  Note that they can be empty,
	 *	in which case they don't map to anything.
	 */
	inst->key_field = -1;

	/*
	 *	FIXME: remove whitespace from field names, if we care.
	 */
	for (p = header, i = 0; p != NULL; p = q, i++) {
		q = strchr(p, *inst->delimiter);

		/*
		 *	Fields 0..N-1
		 */
		if (q) {
			*q = '\0';

			if (q > (p + 1)) {
					if (strcmp(p, inst->key) == 0) {
					inst->key_field = i;
				} else {
					inst->field_offsets[i] = inst->used_fields++;
				}
			}
			q++;

		} else {	/* field N */
			if (*p) {
				if (strcmp(p, inst->key) == 0) {
					inst->key_field = i;
				} else {
					inst->field_offsets[i] = inst->used_fields++;
				}
			}
		}

		/*
		 *	Save the field names, even when they're not used.
		 */
		inst->field_names[i] = p;
	}

	if (inst->key_field < 0) {
		cf_log_err_cs(conf, "Key field '%s' does not appear in header", inst->key);
		return -1;
	}

	inst->tree = rbtree_create(inst, csv_entry_cmp, NULL, 0);
	if (!inst->tree) goto oom;

	/*
	 *	Read the file line by line.
	 */
	fp = fopen(inst->filename, "r");
	if (!fp) {
		cf_log_err_cs(conf, "Error opening filename %s: %s", inst->filename, strerror(errno));
		return -1;
	}

	lineno = 1;
	while (fgets(buffer, sizeof(buffer), fp)) {
		rlm_csv_entry_t *e;

		e = file2csv(conf, inst, lineno, buffer);
		if (!e) {
			fclose(fp);
			return -1;
		}

		lineno++;
	}

	fclose(fp);

	/*
	 *	And register the map function.
	 */
	map_proc_register(inst, inst->name, mod_map_proc, NULL, csv_map_verify, 0);

	return 0;
}

/*
 *	Convert field X to a VP.
 */
static int csv_map_getvalue(TALLOC_CTX *ctx, VALUE_PAIR **out, REQUEST *request, vp_map_t const *map, void *uctx)
{
	char const *str = uctx;
	VALUE_PAIR *head = NULL, *vp;
	vp_cursor_t cursor;
	DICT_ATTR const *da;

	rad_assert(ctx != NULL);
	fr_cursor_init(&cursor, &head);

	/*
	 *	FIXME: allow multiple entries.
	 */
	if (map->lhs->type == TMPL_TYPE_ATTR) {
		da = map->lhs->tmpl_da;

	} else {
		char *attr;

		if (tmpl_aexpand(ctx, &attr, request, map->lhs, NULL, NULL) <= 0) {
			RWDEBUG("Failed expanding string");
			return -1;
		}

		da = dict_attrbyname(attr);
		if (!da) {
			RWDEBUG("No such attribute '%s'", attr);
			return -1;
		}

		talloc_free(attr);
	}

	vp = fr_pair_afrom_da(ctx, da);
	rad_assert(vp);

	if (fr_pair_value_from_str(vp, str, talloc_array_length(str) - 1) < 0) {
		char *escaped;

		escaped = fr_aprints(vp, str, talloc_array_length(str) - 1, '\'');
		RWDEBUG("Failed parsing value \"%s\" for attribute %s: %s", escaped,
			map->lhs->tmpl_da->name, fr_strerror());

		talloc_free(vp); /* also frees escaped */
		return -1;
	}

	vp->op = map->op;
	fr_cursor_merge(&cursor, vp);

	*out = head;
	return 0;
}



/** Perform a search and map the result of the search to server attributes
 *
 * @param[in] mod_inst #rlm_csv_t
 * @param[in] proc_inst mapping map entries to field numbers.
 * @param[in,out] request The current request.
 * @param[in] key key to look for
 * @param[in] maps Head of the map list.
 * @return
 *	- #RLM_MODULE_NOOP no rows were returned.
 *	- #RLM_MODULE_UPDATED if one or more #VALUE_PAIR were added to the #REQUEST.
 *	- #RLM_MODULE_FAIL if an error occurred.
 */
static rlm_rcode_t mod_map_proc(void *mod_inst, UNUSED void *proc_inst, REQUEST *request,
				char const *key, vp_map_t const *maps)
{
	rlm_csv_t		*inst = mod_inst;
	rlm_csv_entry_t		*e, my_entry;
	vp_map_t const		*map;

	my_entry.key = key;

	e = rbtree_finddata(inst->tree, &my_entry);
	if (!e) return RLM_MODULE_NOOP;

	RINDENT();
	for (map = maps;
	     map != NULL;
	     map = map->next) {
		int field;
		char *field_name;

		/*
		 *	Avoid memory allocations if possible.
		 */
		if (map->rhs->type != TMPL_TYPE_UNPARSED) {
			if (tmpl_aexpand(request, &field_name, request, map->rhs, NULL, NULL) < 0) {
				RDEBUG("Failed expanding RHS at %s", map->lhs->name);
				return RLM_MODULE_FAIL;
			}
		} else {
			memcpy(&field_name, &map->rhs->name, sizeof(field_name)); /* const */
		}

		field = fieldname2offset(inst, field_name);

		if (field_name != map->rhs->name) talloc_free(field_name);

		if (field < 0) {
			RDEBUG("No such field name %s", map->rhs->name);
			return RLM_MODULE_FAIL;
		}

		/*
		 *	Pass the raw data to the callback, which will
		 *	create the VP and add it to the map.
		 */
		if (map_to_request(request, map, csv_map_getvalue, e->data[field]) < 0) {
			return RLM_MODULE_FAIL;
		}
	}

	return RLM_MODULE_UPDATED;
}

extern module_t rlm_csv;
module_t rlm_csv = {
	.magic		= RLM_MODULE_INIT,
	.name		= "csv",
	.type		= 0,
	.inst_size	= sizeof(rlm_csv_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
};
