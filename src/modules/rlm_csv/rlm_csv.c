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
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/server/map_proc.h>

static rlm_rcode_t mod_map_proc(void *mod_inst, UNUSED void *proc_inst, request_t *request,
				fr_value_box_t **key, map_t const *maps);

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	char const	*name;
	char const	*filename;
	char const	*delimiter;
	char const	*fields;
	char const	*index_field_name;

	bool		header;
	bool		allow_multiple_keys;
	bool		multiple_index_fields;

	int		num_fields;
	int		used_fields;
	int		index_field;

	char const     	**field_names;
	int		*field_offsets; /* field X from the file maps to array entry Y here */
	fr_type_t	*field_types;
	rbtree_t	*tree;
	fr_trie_t	*trie;

	tmpl_t		*key;
	fr_type_t	key_data_type;

	map_t	*map;		//!< if there is an "update" section in the configuration.
} rlm_csv_t;

typedef struct rlm_csv_entry_s rlm_csv_entry_t;
struct rlm_csv_entry_s {
	rlm_csv_entry_t *next;
	fr_value_box_t *key;
	char *data[];
};

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, rlm_csv_t, filename) },
	{ FR_CONF_OFFSET("delimiter", FR_TYPE_STRING | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, rlm_csv_t, delimiter), .dflt = "," },
	{ FR_CONF_OFFSET("fields", FR_TYPE_STRING , rlm_csv_t, fields) },
	{ FR_CONF_OFFSET("header", FR_TYPE_BOOL, rlm_csv_t, header) },
	{ FR_CONF_OFFSET("allow_multiple_keys", FR_TYPE_BOOL, rlm_csv_t, allow_multiple_keys) },
	{ FR_CONF_OFFSET("index_field", FR_TYPE_STRING | FR_TYPE_REQUIRED | FR_TYPE_NOT_EMPTY, rlm_csv_t, index_field_name) },
	{ FR_CONF_OFFSET("key", FR_TYPE_TMPL, rlm_csv_t, key) },
	CONF_PARSER_TERMINATOR
};

static int csv_entry_cmp(void const *one, void const *two)
{
	rlm_csv_entry_t const *a = one;
	rlm_csv_entry_t const *b = two;

	return fr_value_box_cmp(a->key, b->key);
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
			for (p = buf; *p != '\0'; p++) {
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

static rlm_csv_entry_t *find_entry(rlm_csv_t const *inst, fr_value_box_t const *key)
{
	rlm_csv_entry_t my_e;

	if ((inst->key_data_type == FR_TYPE_IPV4_ADDR) || (inst->key_data_type == FR_TYPE_IPV4_PREFIX)) {
		return fr_trie_lookup(inst->trie, &key->vb_ip.addr.v4.s_addr, key->vb_ip.prefix);

	}

	if ((inst->key_data_type == FR_TYPE_IPV6_ADDR) || (inst->key_data_type == FR_TYPE_IPV6_PREFIX)) {
		return fr_trie_lookup(inst->trie, &key->vb_ip.addr.v6.s6_addr, key->vb_ip.prefix);
	}

	memcpy(&my_e.key, &key, sizeof(key)); /* const issues */

	return rbtree_finddata(inst->tree, &my_e);
}

static bool insert_entry(CONF_SECTION *conf, rlm_csv_t *inst, rlm_csv_entry_t *e, int lineno)
{
	rlm_csv_entry_t *old;

	fr_assert(e != NULL);

	old = find_entry(inst, e->key);
	if (old) {
		if (!inst->allow_multiple_keys && !inst->multiple_index_fields) {
			cf_log_err(conf, "%s[%d]: Multiple entries are disallowed", inst->filename, lineno);
			goto fail;
		}

		/*
		 *	Save this entry at the tail of the matching
		 *	entries.
		 */
		while (old->next) old = old->next;
		old->next = e;
		return true;
	}

	if ((inst->key_data_type == FR_TYPE_IPV4_ADDR) || (inst->key_data_type == FR_TYPE_IPV4_PREFIX)) {
		if (fr_trie_insert(inst->trie, &e->key->vb_ip.addr.v4.s_addr, e->key->vb_ip.prefix, e) < 0) {
			cf_log_err(conf, "Failed inserting entry for file %s line %d: %s",
				   inst->filename, lineno, fr_strerror());
		fail:
			talloc_free(e);
			return false;
		}

	} else if ((inst->key_data_type == FR_TYPE_IPV6_ADDR) || (inst->key_data_type == FR_TYPE_IPV6_PREFIX)) {
		if (fr_trie_insert(inst->trie, &e->key->vb_ip.addr.v6.s6_addr, e->key->vb_ip.prefix, e) < 0) {
			cf_log_err(conf, "Failed inserting entry for file %s line %d: %s",
				   inst->filename, lineno, fr_strerror());
			goto fail;
		}

	} else if (!rbtree_insert(inst->tree, e)) {
		cf_log_err(conf, "Failed inserting entry for file %s line %d: duplicate entry",
			      inst->filename, lineno);
		goto fail;
	}

	return true;
}


static bool duplicate_entry(CONF_SECTION *conf, rlm_csv_t *inst, rlm_csv_entry_t *old, char *p, int lineno)
{
	int i;
	fr_type_t type = inst->key_data_type;
	rlm_csv_entry_t *e;

	MEM(e = (rlm_csv_entry_t *)talloc_zero_array(inst, uint8_t,
						     sizeof(*e) + (inst->used_fields * sizeof(e->data[0]))));
	talloc_set_type(e, rlm_csv_entry_t);

	e->key = talloc_zero(e, fr_value_box_t);
	if (fr_value_box_from_str(e->key, e->key, &type, NULL, p, -1, 0, false) < 0) {
		cf_log_err(conf, "Failed parsing key field in file %s line %d - %s", inst->filename, lineno,
			   fr_strerror());
		return false;
	}

	/*
	 *	Copy the other fields;
	 */
	for (i = 0; i < inst->used_fields; i++) {
		if (old->data[i]) e->data[i] = old->data[i]; /* no need to dup it, it's never freed... */
	}

	return insert_entry(conf, inst, e, lineno);
}

/*
 *	Convert a buffer to a CSV entry
 */
static bool file2csv(CONF_SECTION *conf, rlm_csv_t *inst, int lineno, char *buffer)
{
	rlm_csv_entry_t *e;
	int i;
	char *p, *q;

	MEM(e = (rlm_csv_entry_t *)talloc_zero_array(inst, uint8_t,
						     sizeof(*e) + (inst->used_fields * sizeof(e->data[0]))));
	talloc_set_type(e, rlm_csv_entry_t);

	for (p = buffer, i = 0; p != NULL; p = q, i++) {
		if (!buf2entry(inst, p, &q)) {
			cf_log_err(conf, "Malformed entry in file %s line %d", inst->filename, lineno);
			return false;
		}

		if (q) *(q++) = '\0';

		if (i >= inst->num_fields) {
			cf_log_err(conf, "Too many fields at file %s line %d", inst->filename, lineno);
			return false;
		}

		/*
		 *	This is the key field.
		 */
		if (i == inst->index_field) {
			fr_type_t type = inst->key_data_type;

			/*
			 *	Check for /etc/group style keys.
			 */
			if (inst->multiple_index_fields) {
				char *l;

				/*
				 *	Silently omit empty entries.
				 */
				if (!*p) {
					talloc_free(e);
					return true;
				}

				/*
				 *	Check & smash ','.  duplicate
				 *	'e', and insert it into the
				 *	hash table / trie.
				 */
				l = strchr(p, ',');
				while (l) {
					*l = '\0';

					if (!duplicate_entry(conf, inst, e, p, lineno)) goto fail;

					if (!l) break;
					p = l + 1;
					l = strchr(p, ',');
				}
			}

			/*
			 *	Set the last entry to use 'e'
			 */
			e->key = talloc_zero(e, fr_value_box_t);
			if (fr_value_box_from_str(e->key, e->key, &type, NULL, p, -1, 0, false) < 0) {
				cf_log_err(conf, "Failed parsing key field in file %s line %d - %s", inst->filename, lineno,
					   fr_strerror());
			fail:
				talloc_free(e);
				return false;
			}
			continue;
		}

		/*
		 *	This field is unused.  Ignore it.
		 */
		if (inst->field_offsets[i] < 0) continue;

		/*
		 *	Try to parse fields as data types if the data type is defined.
		 */
		if (inst->field_types[i] != FR_TYPE_INVALID) {
			fr_value_box_t box;
			fr_type_t type = inst->field_types[i];

			if (fr_value_box_from_str(e, &box, &type, NULL, p, -1, 0, false) < 0) {
				cf_log_err(conf, "Failed parsing field '%s' in file %s line %d - %s", inst->field_names[i],
					   inst->filename, lineno, fr_strerror());
				goto fail;
			}

			fr_value_box_clear(&box);
		}

		MEM(e->data[inst->field_offsets[i]] = talloc_typed_strdup(e, p));
	}

	if (i < inst->num_fields) {
		cf_log_err(conf, "Too few fields in file %s at line %d (%d < %d)", inst->filename, lineno, i, inst->num_fields);
		goto fail;
	}

	return insert_entry(conf, inst, e, lineno);
}


static int fieldname2offset(rlm_csv_t const *inst, char const *field_name, int *array_offset)
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
			if (array_offset) *array_offset = i;
			return inst->field_offsets[i];
		}
	}

	return -1;
}

#define CSV_MAX_ATTRMAP (128)

/*
 *	Verify one map entry.
 */
static int csv_map_verify(map_t *map, void *instance)
{
	rlm_csv_t *inst = instance;
	int offset;
	fr_type_t type = FR_TYPE_INVALID;

	/*
	 *	Destinations where we can put the fr_pair_ts we
	 *	create using CSV values.
	 */
	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
		type = tmpl_da(map->lhs)->type;
		break;

	case TMPL_TYPE_LIST:
		break;

	case TMPL_TYPE_ATTR_UNRESOLVED:
		cf_log_err(map->ci, "Unknown attribute %s", tmpl_attr_unresolved(map->lhs));
		return -1;

	default:
		cf_log_err(map->ci, "Left hand side of map must be an attribute or list, not a %s",
			   fr_table_str_by_value(tmpl_type_table, map->lhs->type, "<INVALID>"));
		return -1;
	}

	/*
	 *	Sources we can use to get the name of the attribute
	 *	we're retrieving from LDAP.
	 */
	switch (map->rhs->type) {
	case TMPL_TYPE_UNRESOLVED:
		offset = -1;
		if (fieldname2offset(inst, map->rhs->name, &offset) < 0) {
			cf_log_err(map->ci, "Unknown field '%s'", map->rhs->name);
			return -1;
		}

		if ((type == FR_TYPE_INVALID) || (offset < 0)) break;

		/*
		 *	Try to set the data type of the field.  But if
		 *	they map the same field to two different data
		 *	types, that's an error.
		 */
		if (inst->field_types[offset] == FR_TYPE_INVALID) {
			inst->field_types[offset] = type;
			break;
		}

		if (inst->field_types[offset] != type) {
			cf_log_err(map->ci, "Field '%s' maps to two different data types, making it impossible to parse it.", map->rhs->name);
			return -1;
		}

		break;

	case TMPL_TYPE_ATTR_UNRESOLVED:
		cf_log_err(map->ci, "Unknown attribute %s", tmpl_attr_unresolved(map->rhs));
		return -1;

	default:
		cf_log_err(map->ci, "Right hand side of map must be a field name, not a %s",
			   fr_table_str_by_value(tmpl_type_table, map->rhs->type, "<INVALID>"));
		return -1;
	}

	/*
	 *	Only some operators are allowed.
	 */
	switch (map->op) {
	case T_OP_SET:
	case T_OP_EQ:
	case T_OP_SUB:
	case T_OP_ADD:
	case T_OP_LT:
	case T_OP_GT:
	case T_OP_LE:
	case T_OP_GE:
		break;

	default:
		cf_log_err(map->ci, "Operator \"%s\" not allowed for CSV mappings",
			   fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
		return -1;
	}

	return 0;
}

/*
 *	Verify the result of the map.
 */
static int csv_maps_verify(CONF_SECTION *cs, void *mod_inst, UNUSED void *proc_inst,
			  tmpl_t const *src, map_t const *maps)
{
	map_t const *map;

	if (!src) {
		cf_log_err(cs, "Missing key expansion");

		return -1;
	}

	for (map = maps;
	     map != NULL;
	     map = map->next) {
		map_t *unconst_map;

		memcpy(&unconst_map, &map, sizeof(map));

		/*
		 *	This function doesn't change the map, so it's OK.
		 */
		if (csv_map_verify(unconst_map, mod_inst) < 0) return -1;
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
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_csv_t *inst = instance;
	int i;
	char const *p;
	char *q;
	char *fields;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	if (inst->delimiter[1]) {
		cf_log_err(conf, "'delimiter' must be one character long");
		return -1;
	}

	if (inst->key) {
		inst->key_data_type = tmpl_expanded_type(inst->key);
		switch (inst->key_data_type) {
		case FR_TYPE_VALUE:
			break;

		case FR_TYPE_INVALID:
			cf_log_err(conf, "Can't determine key data_type. 'key' must be an expression of type "
				   "xlat, attr, or data");
			return -1;

		default:
			cf_log_err(conf, "Invalid key data type '%s'",
				   fr_table_str_by_value(fr_value_box_type_table, inst->key_data_type, "<INVALID>"));
			return -1;
		}
	} else {
		inst->key_data_type = FR_TYPE_STRING;
	}

	/*
	 *	IP addresses go into tries.  Everything else into binary tries.
	 */
	if ((inst->key_data_type == FR_TYPE_IPV4_ADDR) || (inst->key_data_type == FR_TYPE_IPV4_PREFIX) ||
	    (inst->key_data_type == FR_TYPE_IPV6_ADDR) || (inst->key_data_type == FR_TYPE_IPV6_PREFIX)) {
		MEM(inst->trie = fr_trie_alloc(inst));
	} else {
		MEM(inst->tree = rbtree_talloc_alloc(inst, csv_entry_cmp, rlm_csv_entry_t, NULL, 0));
	}

	if ((*inst->index_field_name == ',') || (*inst->index_field_name == *inst->delimiter)) {
		cf_log_err(conf, "Field names cannot begin with the '%c' character", *inst->index_field_name);
		return -1;
	}

	if (inst->delimiter[1] != '\0') {
		cf_log_err(conf, "The 'delimiter' field MUST be one character long");
		return -1;
	}

	/*
	 *	If there is a header in the file, then read that first.
	 */
	if (inst->header) {
		FILE *fp;
		char buffer[8192];

		fp = fopen(inst->filename, "r");
		if (!fp) {
			cf_log_err(conf, "Error opening filename %s: %s", inst->filename, fr_syserror(errno));
			return -1;
		}

		p = fgets(buffer, sizeof(buffer), fp);
		if (!p) {
		error_eof:
			cf_log_err(conf, "Error reading filename %s: Unexpected EOF", inst->filename);
			fclose(fp);
			return -1;
		}

		q = strchr(buffer, '\n');
		if (!q) goto error_eof;

		*q = '\0';

		/*
		 *	Over-write whatever is in the config with the
		 *	header from the file.
		 */
		inst->fields = talloc_strdup(inst, buffer);
		fclose(fp);
	}

	/*
	 *	Parse the field names AFTER opening the file.  Because
	 *	the field names might be taken from the header.
	 */
	for (p = inst->fields; p != NULL; p = strchr(p + 1, *inst->delimiter)) {
		inst->num_fields++;
	}

	if (inst->num_fields < 2) {
		cf_log_err(conf, "The CSV file MUST have at least a key field and data field");
		return -1;
	}

	MEM(inst->field_names = talloc_zero_array(inst, const char *, inst->num_fields));
	MEM(inst->field_offsets = talloc_array(inst, int, inst->num_fields));
	MEM(inst->field_types = talloc_array(inst, fr_type_t, inst->num_fields));

	for (i = 0; i < inst->num_fields; i++) {
		inst->field_offsets[i] = -1; /* unused */
		inst->field_types[i] = FR_TYPE_INVALID;
	}

	/*
	 *	Get a writable copy of the fields definition
	 */
	MEM(fields = talloc_typed_strdup(inst, inst->fields));

	/*
	 *	Mark up the field names.  Note that they can be empty,
	 *	in which case they don't map to anything.
	 */
	inst->index_field = -1;

	/*
	 *	Parse the field names
	 */
	i = 0;
	p = q = fields;
	while (*q) {
		bool last_field;

		/*
		 *	Skip the field name
		 */
		while (*q && (*q != *inst->delimiter)) {
			if ((*q == '\'') || (*q == '"')) {
				cf_log_err(conf, "Field %d name cannot have quotation marks.",
					   i + 1);
				return -1;
			}

			if (*q < ' ') {
				*q = '\0';
				break;
			}

			if (isspace((int) *q)) {
				cf_log_err(conf, "Field %d name cannot have spaces.",
					   i + 1);
				return -1;
			}

			q++;
		}

		/*
		 *	Check for the last field.
		 */
		if (!*q) {
			last_field = true;
		} else {
			*q = '\0';
			last_field = false;
		}

		/*
		 *	Track which field is the key, and which fields
		 *	map to which entries.
		 *
		 *	Some fields are unused, so there isn't a 1-1
		 *	mapping betweeen CSV file fields, and fields
		 *	in the map.
		 */
		if (last_field && (*p == ',') && (strcmp(p + 1, inst->index_field_name) == 0)) {
			inst->index_field = i;
			p++;

			inst->multiple_index_fields = true;

		} else if (strcmp(p, inst->index_field_name) == 0) {
			inst->index_field = i;

		} else if ((*p == ',') || (*p == *inst->delimiter)) {
			cf_log_err(conf, "Field names MUST NOT begin with the '%c' character", *p);
			return -1;

		} else {
			inst->field_offsets[i] = inst->used_fields++;
		}

		/*
		 *	Save the field names, even when the field names are empty.
		 */
		inst->field_names[i] = p;

		if (last_field) break;

		q++;
		i++;
		p = q;
	}

	if (inst->index_field < 0) {
		cf_log_err(conf, "index_field '%s' does not appear in the list of field names",
			   inst->index_field_name);
		return -1;
	}

	/*
	 *	Set the data type of the index field.
	 */
	inst->field_types[inst->index_field] = inst->key_data_type;

	/*
	 *	And register the `map csv <key> { ... }` function.
	 */
	map_proc_register(inst, inst->name, mod_map_proc, csv_maps_verify, 0);

	return 0;
}


/** Instantiate the module
 *
 * Creates a new instance of the module reading parameters from a configuration section.
 *
 * @param conf to parse.
 * @param instance configuration data.
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_csv_t *inst = instance;
	CONF_SECTION *cs;
	int lineno;
	FILE *fp;
	tmpl_rules_t	parse_rules = {
		.allow_foreign = true	/* Because we don't know where we'll be called */
	};
	char buffer[8192];

	/*
	 *	"update" without "key" is invalid, as we can't run the
	 *	module.
	 *
	 *	"key" without "update" means we just ignore the key.
	 */
	cs = cf_section_find(conf, "update", CF_IDENT_ANY);
	if (cs) {
		if (!inst->key) {
			cf_log_err(conf, "There is no 'key' defined for the 'update' section");
			return -1;
		}

		/*
		 *	Parse the "update" section.  This parsing includes
		 *	setting inst->field_types[], base on the attribute
		 *	mappings.
		 */
		if (map_afrom_cs(inst, &inst->map, cs,
				 &parse_rules, &parse_rules, csv_map_verify, inst,
				 CSV_MAX_ATTRMAP) < 0) {
			return -1;
		}
	} else if (inst->key) {
		cf_log_warn(conf, "Ignoring 'key', as no 'update' section has been defined.");
	}

	/*
	 *	Re-open the file and read it all.
	 */
	fp = fopen(inst->filename, "r");
	if (!fp) {
		cf_log_err(conf, "Error opening filename %s: %s", inst->filename, fr_syserror(errno));
		return -1;
	}
	lineno = 1;

	/*
	 *	If there is a header in the file, then read that first.
	 *	This time we just ignore it.
	 */
	if (inst->header) {
		char *p = fgets(buffer, sizeof(buffer), fp);
		if (!p) {
			cf_log_err(conf, "Error reading filename %s: Unexpected EOF", inst->filename);
			fclose(fp);
			return -1;
		}
		lineno++;
	}

	/*
	 *	Read the rest of the file.
	 */
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (!file2csv(conf, inst, lineno, buffer)) {
			fclose(fp);
			return -1;
		}

		lineno++;
	}
	fclose(fp);

	return 0;
}


/*
 *	Convert field X to a VP.
 */
static int csv_map_getvalue(TALLOC_CTX *ctx, fr_pair_t **out, request_t *request, map_t const *map, void *uctx)
{
	char const		*str = uctx;
	fr_pair_list_t		head;
	fr_pair_t		*vp;
	fr_cursor_t		cursor;
	fr_dict_attr_t		const *da;

	fr_assert(ctx != NULL);
	fr_pair_list_init(&head);
	fr_cursor_init(&cursor, &head);

	if (tmpl_is_attr(map->lhs)) {
		da = tmpl_da(map->lhs);

	} else {
		char *attr;

		if (tmpl_aexpand(ctx, &attr, request, map->lhs, NULL, NULL) <= 0) {
			RWDEBUG("Failed expanding string");
			return -1;
		}


		da = fr_dict_attr_by_name(NULL, fr_dict_root(request->dict), attr);
		if (!da) {
			RWDEBUG("No such attribute '%s'", attr);
			return -1;
		}

		talloc_free(attr);
	}

	vp = fr_pair_afrom_da(ctx, da);
	fr_assert(vp);

	if (fr_pair_value_from_str(vp, str, talloc_array_length(str) - 1, '\0', true) < 0) {
		RPWDEBUG("Failed parsing value \"%pV\" for attribute %s", fr_box_strvalue_buffer(str),
			tmpl_da(map->lhs)->name);
		talloc_free(vp);

		return -1;
	}

	vp->op = map->op;
	fr_cursor_append(&cursor, vp);

	*out = head;
	return 0;
}


/** Perform a search and map the result of the search to server attributes
 *
 * @param[in] inst	#rlm_csv_t.
 * @param[in,out]	request The current request.
 * @param[in] key	key to look for
 * @param[in] maps	Head of the map list.
 * @return
 *	- #RLM_MODULE_NOOP no rows were returned.
 *	- #RLM_MODULE_UPDATED if one or more #fr_pair_t were added to the #request_t.
 *	- #RLM_MODULE_FAIL if an error occurred.
 */
static rlm_rcode_t mod_map_apply(rlm_csv_t const *inst, request_t *request,
				fr_value_box_t const *key, map_t const *maps)
{
	rlm_rcode_t		rcode = RLM_MODULE_UPDATED;
	rlm_csv_entry_t		*e;
	map_t const		*map;

	e = find_entry(inst, key);
	if (!e) {
		rcode = RLM_MODULE_NOOP;
		goto finish;
	}

redo:
	RINDENT();
	for (map = maps;
	     map != NULL;
	     map = map->next) {
		int field;
		char *field_name;

		/*
		 *	Avoid memory allocations if possible.
		 */
		if (!tmpl_is_unresolved(map->rhs)) {
			if (tmpl_aexpand(request, &field_name, request, map->rhs, NULL, NULL) < 0) {
				REXDENT();
				REDEBUG("Failed expanding RHS at %s", map->lhs->name);
				rcode = RLM_MODULE_FAIL;
				goto finish;
			}
		} else {
			memcpy(&field_name, &map->rhs->name, sizeof(field_name)); /* const */
		}

		field = fieldname2offset(inst, field_name, NULL);

		if (field_name != map->rhs->name) talloc_free(field_name);

		if (field < 0) {
			REXDENT();
			REDEBUG("No such field name %s", map->rhs->name);
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}

		/*
		 *	Pass the raw data to the callback, which will
		 *	create the VP and add it to the map.
		 */
		if (map_to_request(request, map, csv_map_getvalue, e->data[field]) < 0) {
			REXDENT();
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}
	}

	REXDENT();

	if (e->next) {
		e = e->next;
		goto redo;
	}

finish:
	return rcode;
}


/** Perform a search and map the result of the search to server attributes
 *
 * @param[in] mod_inst	#rlm_csv_t.
 * @param[in] proc_inst	mapping map entries to field numbers.
 * @param[in,out]	request The current request.
 * @param[in] key	key to look for
 * @param[in] maps	Head of the map list.
 * @return
 *	- #RLM_MODULE_NOOP no rows were returned.
 *	- #RLM_MODULE_UPDATED if one or more #fr_pair_t were added to the #request_t.
 *	- #RLM_MODULE_FAIL if an error occurred.
 */
static rlm_rcode_t mod_map_proc(void *mod_inst, UNUSED void *proc_inst, request_t *request,
				fr_value_box_t **key, map_t const *maps)
{
	rlm_csv_t		*inst = talloc_get_type_abort(mod_inst, rlm_csv_t);

	if (!*key) {
		REDEBUG("CSV key cannot be (null)");
		return RLM_MODULE_FAIL;
	}

	if ((inst->key_data_type == FR_TYPE_OCTETS) || (inst->key_data_type == FR_TYPE_STRING)) {
		if (fr_value_box_list_concat(request, *key, key, inst->key_data_type, true) < 0) {
			REDEBUG("Failed parsing key");
			return RLM_MODULE_FAIL;
		}
	}

	return mod_map_apply(inst, request, *key, maps);
}


static unlang_action_t CC_HINT(nonnull) mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_csv_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_csv_t);
	rlm_rcode_t rcode;
	ssize_t slen;
	fr_value_box_t *key;

	if (!inst->map || !inst->key) RETURN_MODULE_NOOP;

	/*
	 *	Expand the key to whatever it is.  For attributes,
	 *	this usually just means copying the value box.
	 */
	slen = tmpl_aexpand_type(request, &key, FR_TYPE_VALUE_BOX, request, inst->key, NULL, NULL);
	if (slen < 0) {
		DEBUG("Failed expanding key '%s'", inst->key->name);
		RETURN_MODULE_FAIL;
	}

	/*
	 *	If the output data was string and we wanted non-string
	 *	data, convert it now.
	 */
	if (key->type != inst->key_data_type) {
		fr_value_box_t tmp;

		fr_value_box_copy(request, &tmp, key);

		slen = fr_value_box_cast(request, key, inst->key_data_type, NULL, &tmp);
		fr_value_box_clear(&tmp);
		if (slen < 0) {
			talloc_free(key);
			DEBUG("Failed casting %pV to data type '%s'",
			      &key, fr_table_str_by_value(tmpl_type_table, inst->key_data_type, "<INVALID>"));
			RETURN_MODULE_FAIL;
		}
	}

	RDEBUG2("Processing CVS map with key %pV", key);
	RINDENT();
	rcode = mod_map_apply(inst, request, key, inst->map);
	REXDENT();

	talloc_free(key);
	RETURN_MODULE_RCODE(rcode);
}

extern module_t rlm_csv;
module_t rlm_csv = {
	.magic		= RLM_MODULE_INIT,
	.name		= "csv",
	.type		= 0,
	.inst_size	= sizeof(rlm_csv_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,

	.method_names = (module_method_names_t[]){
		{ CF_IDENT_ANY, CF_IDENT_ANY,	mod_process },

		MODULE_NAME_TERMINATOR
	}
};
