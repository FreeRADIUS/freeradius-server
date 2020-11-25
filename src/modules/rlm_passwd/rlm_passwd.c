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
 * @file rlm_passwd.c
 * @brief Enables authentication against unix passwd files.
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_passwd - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/debug.h>

struct mypasswd {
	struct mypasswd *next;
	char *listflag;
	char *field[1];
};

struct hashtable {
	int tablesize;
	int key_field;
	int num_fields;
	int islist;
	int ignorenis;
	char * filename;
	struct mypasswd **table;
	char buffer[1024];
	FILE *fp;
	char delimiter;
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_passwd_dict[];
fr_dict_autoload_t rlm_passwd_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

#ifdef TEST

void printpw(struct mypasswd *pw, int num_fields){
	int i;
	if (pw) {
		for( i = 0; i < num_fields; i++ ) printf("%s:", pw->field[i]);
		printf("\n");
	}
	else printf ("Not found\n");
	fflush(stdout);
}
#endif


static struct mypasswd *mypasswd_alloc(char const* buffer, int num_fields, size_t* len)
{
	struct mypasswd *t;
	/* reserve memory for (struct mypasswd) + listflag (num_fields * sizeof (char*)) +
	** fields (num_fields * sizeof (char)) + strlen (inst->format) + 1 */

	*len = sizeof(struct mypasswd) + num_fields * sizeof (char*) + num_fields * sizeof (char ) + strlen(buffer) + 1;
	MEM(t = (struct mypasswd *)talloc_zero_array(NULL, uint8_t, *len));

	return t;
}

static int string_to_entry(char const* string, int num_fields, char delimiter,
			   struct mypasswd *passwd, size_t bufferlen)
{
	char *str;
	size_t len, i;
	int fn=0;
	char *data_beg;


	len = strlen(string);
	if(!len) return 0;
	if (string[len-1] == '\n') len--;
	if(!len) return 0;
	if (string[len-1] == '\r') len--;
	if(!len) return 0;
	if (!passwd ||
	    bufferlen < (len + num_fields * sizeof (char*) + num_fields * sizeof (char) + sizeof (struct mypasswd) + 1) ) return 0;
	passwd->next = NULL;
	data_beg=(char *)passwd + sizeof(struct mypasswd);
	str = data_beg + num_fields * sizeof (char) + num_fields * sizeof (char*);
	memcpy (str, string, len);
	str[len] = 0;
	passwd->field[fn++] = str;
	passwd->listflag = data_beg + num_fields * sizeof (char *);
	for(i=0; i < len; i++){
		if (str[i] == delimiter) {
			str[i] = 0;
			passwd->field[fn++] = str + i + 1;
			if (fn == num_fields) break;
		}
	}
	for (; fn < num_fields; fn++) passwd->field[fn] = NULL;
	return len + num_fields * sizeof (char) + num_fields * sizeof (char*) + sizeof (struct mypasswd) + 1;
}


static void destroy_password (struct mypasswd * pass)
{
	struct mypasswd *p;

	while ((p = pass) != NULL) {
		pass = pass->next;
		talloc_free(p);
	}
}


static unsigned int hash(char const * username, unsigned int tablesize)
{
	uint64_t h = 1;

	while (*username) h = fr_multiply_mod(h, (7907 + *username++), tablesize);

	return (unsigned int)h;
}

static void release_hash_table(struct hashtable * ht){
	int i;

	if (!ht) return;
	for (i = 0; i < ht->tablesize; i++)
		if (ht->table[i])
			destroy_password(ht->table[i]);
	if (ht->fp) {
		fclose(ht->fp);
		ht->fp = NULL;
	}
	ht->tablesize = 0;
}

static void release_ht(struct hashtable * ht){
	if (!ht) return;
	release_hash_table(ht);
	talloc_free(ht);
}

static struct hashtable * build_hash_table (char const * file, int num_fields,
					    int key_field, int islist, int tablesize, int ignorenis, char delimiter)
{
	struct hashtable* ht;
	size_t len;
	unsigned int h;
	struct mypasswd *hashentry, *hashentry1;
	char *list;
	char *nextlist=0;
	int i;
	char buffer[1024];

	MEM(ht = talloc_zero(NULL, struct hashtable));
	MEM(ht->filename = talloc_typed_strdup(ht, file));

	ht->tablesize = tablesize;
	ht->num_fields = num_fields;
	ht->key_field = key_field;
	ht->islist = islist;
	ht->ignorenis = ignorenis;

	if (delimiter) ht->delimiter = delimiter;
	else ht->delimiter = ':';
	if(!tablesize) return ht;
	if(!(ht->fp = fopen(file,"r"))) {
		talloc_free(ht);
		return NULL;
	}

	/*
	 *	@todo: This code is SHIT.  It's badly formatted.  It's
	 *	hard to understand.  It re-implements tons of things
	 *	which are already in the server core.
	 */
	memset(ht->buffer, 0, 1024);
	MEM(ht->table = talloc_zero_array(ht, struct mypasswd *, tablesize));
	while (fgets(buffer, 1024, ht->fp)) {
		if(*buffer && *buffer!='\n' && (!ignorenis || (*buffer != '+' && *buffer != '-')) ){
			hashentry = mypasswd_alloc(buffer, num_fields, &len);
			if (!hashentry){
				release_hash_table(ht);
				return ht;
			}

			len = string_to_entry(buffer, num_fields, ht->delimiter, hashentry, len);
			if (!hashentry->field[key_field] || *hashentry->field[key_field] == '\0') {
				talloc_free(hashentry);
				continue;
			}

			if (islist) {
				list = hashentry->field[key_field];
				for (nextlist = list; *nextlist && *nextlist!=','; nextlist++);
				if (*nextlist) *nextlist++ = 0;
				else nextlist = 0;
			}
			h = hash(hashentry->field[key_field], tablesize);
			hashentry->next = ht->table[h];
			ht->table[h] = hashentry;
			if (islist) {
				for (list=nextlist; nextlist; list = nextlist){
					for (nextlist = list; *nextlist && *nextlist!=','; nextlist++);
					if (*nextlist) *nextlist++ = 0;
					else nextlist = 0;
					if(!(hashentry1 = mypasswd_alloc("", num_fields, &len))){
						release_hash_table(ht);
						return ht;
					}
					for (i=0; i<num_fields; i++) hashentry1->field[i] = hashentry->field[i];
					hashentry1->field[key_field] = list;
					h = hash(list, tablesize);
					hashentry1->next = ht->table[h];
					ht->table[h] = hashentry1;
				}
			}
		}
	}
	fclose(ht->fp);
	ht->fp = NULL;
	return ht;
#undef passwd
}

static struct mypasswd * get_next(char *name, struct hashtable *ht,
				  struct mypasswd **last_found)
{
	struct mypasswd * passwd;
	struct mypasswd * hashentry;
	char buffer[1024];
	char *list, *nextlist;

	if (ht->tablesize > 0) {
		/* get saved address of next item to check from buffer */
		hashentry = *last_found;
		for (; hashentry; hashentry = hashentry->next) {
			if (!strcmp(hashentry->field[ht->key_field], name)) {
				/* save new address */
				*last_found = hashentry->next;
				return hashentry;
			}
		}
		return NULL;
	}
	/*	printf("try to find in file\n"); */
	if (!ht->fp) return NULL;

	passwd = (struct mypasswd *) ht->buffer;

	while (fgets(buffer, 1024,ht->fp)) {
		if(*buffer && *buffer!='\n' && string_to_entry(buffer, ht->num_fields, ht->delimiter, passwd, sizeof(ht->buffer)-1) &&
		   (!ht->ignorenis || (*buffer !='-' && *buffer != '+') ) ){
			if(!ht->islist) {
				if(!strcmp(passwd->field[ht->key_field], name))
					return passwd;
			}
			else {
				for (list = passwd->field[ht->key_field], nextlist = list; nextlist; list = nextlist) {
					for(nextlist = list; *nextlist && *nextlist!=','; nextlist++);
					if(!*nextlist) {
						nextlist = 0;
					} else {
						*nextlist++ = 0;
					}
					if (!strcmp(list, name)) {
						return passwd;
					}
				}
			}

		}
	}
	fclose(ht->fp);
	ht->fp = NULL;
	return NULL;
}

static struct mypasswd * get_pw_nam(char * name, struct hashtable* ht,
				    struct mypasswd **last_found)
{
	int h;
	struct mypasswd * hashentry;

	if (!ht || !name || (*name == '\0')) return NULL;
	*last_found = NULL;
	if (ht->tablesize > 0) {
		h = hash (name, ht->tablesize);
		for (hashentry = ht->table[h]; hashentry; hashentry = hashentry->next) {
			if (!strcmp(hashentry->field[ht->key_field], name)){
				/* save address of next item to check into buffer */
				*last_found=hashentry->next;
				return hashentry;
			}
		}

		return NULL;
	}
	if (ht->fp) {
		fclose(ht->fp);
		ht->fp = NULL;
	}
	if (!(ht->fp=fopen(ht->filename, "r"))) return NULL;
	return get_next(name, ht, last_found);
}

#ifdef TEST

#define MALLOC_CHECK_ 1

int main(void){
	struct hashtable *ht;
	char *buffer;
	struct mypasswd* pw, *last_found;
	int i;

	ht = build_hash_table("/etc/group", 4, 3, 1, 100, 0, ":");
	if(!ht) {
		printf("Hash table not built\n");
		return -1;
	}
	for (i = 0; i < ht->tablesize; i++) {
		if (ht->table[i]) {
			printf("%d:\n", i);
			for (pw = ht->table[i]; pw; pw = pw->next) {
				printpw(pw, 4);
			}
		}
	}

	while(fgets(buffer, 1024, stdin)){
		buffer[strlen(buffer)-1] = 0;
		pw = get_pw_nam(buffer, ht, &last_found);
		printpw(pw,4);
		while ((pw = get_next(buffer, ht, &last_found))) printpw(pw,4);
	}
	release_ht(ht);
}

#else  /* TEST */
typedef struct {
	struct hashtable	*ht;
	struct mypasswd		*pwd_fmt;
	char const		*filename;
	char const		*format;
	char const		*delimiter;
	bool			allow_multiple;
	bool			ignore_nislike;
	uint32_t		hash_size;
	uint32_t		num_fields;
	uint32_t		key_field;
	uint32_t		listable;
	fr_dict_attr_t const		*keyattr;
	bool			ignore_empty;
} rlm_passwd_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_passwd_t, filename) },
	{ FR_CONF_OFFSET("format", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_passwd_t, format) },
	{ FR_CONF_OFFSET("delimiter", FR_TYPE_STRING, rlm_passwd_t, delimiter), .dflt = ":" },

	{ FR_CONF_OFFSET("ignore_nislike", FR_TYPE_BOOL, rlm_passwd_t, ignore_nislike), .dflt = "yes" },

	{ FR_CONF_OFFSET("ignore_empty", FR_TYPE_BOOL, rlm_passwd_t, ignore_empty), .dflt = "yes" },

	{ FR_CONF_OFFSET("allow_multiple_keys", FR_TYPE_BOOL, rlm_passwd_t, allow_multiple), .dflt = "no" },

	{ FR_CONF_OFFSET("hash_size", FR_TYPE_UINT32, rlm_passwd_t, hash_size), .dflt = "100" },
	CONF_PARSER_TERMINATOR
};

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	int			num_fields = 0, key_field = -1, listable = 0;
	char const		*s;
	char			*lf = NULL; /* destination list flags temporary */
	size_t			len;
	int			i;
	fr_dict_attr_t const	*da;
	rlm_passwd_t		*inst = instance;

	fr_assert(inst->filename && *inst->filename);
	fr_assert(inst->format && *inst->format);

	if (inst->hash_size == 0) {
		cf_log_err(conf, "Invalid value '0' for hash_size");
		return -1;
	}

	lf = talloc_typed_strdup(inst, inst->format);
	if (!lf) {
		ERROR("Memory allocation failed for lf");
		return -1;
	}
	memset(lf, 0, strlen(inst->format));

	s = inst->format - 1;
	do {
		if(s == inst->format - 1 || *s == ':'){
			if(*(s+1) == '*'){
				key_field = num_fields;
				s++;
			}
			if(*(s+1) == ','){
				listable = 1;
				s++;
			}
			if(*(s+1) == '='){
				lf[num_fields]=1;
				s++;
			}
			if(*(s+1) == '~'){
				lf[num_fields]=2;
				s++;
			}
			num_fields++;
		}
		s++;
	} while(*s);

	if(key_field < 0) {
		cf_log_err(conf, "no field marked as key in format: %s",
			      inst->format);
		return -1;
	}

	inst->ht = build_hash_table(inst->filename, num_fields, key_field, listable,
				    inst->hash_size, inst->ignore_nislike, *inst->delimiter);
	if (!inst->ht){
		ERROR("Can't build hashtable from passwd file");
		return -1;
	}

	inst->pwd_fmt = mypasswd_alloc(inst->format, num_fields, &len);
	if (!inst->pwd_fmt){
		ERROR("Memory allocation failed");
		release_ht(inst->ht);
		inst->ht = NULL;
		return -1;
	}
	if (!string_to_entry(inst->format, num_fields, ':', inst->pwd_fmt , len)) {
		ERROR("Unable to convert format entry");
		release_ht(inst->ht);
		inst->ht = NULL;
		return -1;
	}

	memcpy(inst->pwd_fmt->listflag, lf, num_fields);

	talloc_free(lf);
	for (i=0; i<num_fields; i++) {
		if (*inst->pwd_fmt->field[i] == '*') inst->pwd_fmt->field[i]++;
		if (*inst->pwd_fmt->field[i] == ',') inst->pwd_fmt->field[i]++;
		if (*inst->pwd_fmt->field[i] == '=') inst->pwd_fmt->field[i]++;
		if (*inst->pwd_fmt->field[i] == '~') inst->pwd_fmt->field[i]++;
	}
	if (!*inst->pwd_fmt->field[key_field]) {
		cf_log_err(conf, "key field is empty");
		release_ht(inst->ht);
		inst->ht = NULL;
		return -1;
	}

	da = fr_dict_attr_by_qualified_oid(NULL, dict_freeradius,
					   inst->pwd_fmt->field[key_field], true);
	if (!da) {
		PERROR("Unable to resolve attribute");
		release_ht(inst->ht);
		inst->ht = NULL;
		return -1;
	}

	inst->keyattr = da;
	inst->num_fields = num_fields;
	inst->key_field = key_field;
	inst->listable = listable;

	DEBUG3("num_fields: %d key_field %d(%s) listable: %s", num_fields, key_field,
	       inst->pwd_fmt->field[key_field], listable ? "yes" : "no");

	return 0;

#undef inst
}

static int mod_detach (void *instance) {
#define inst ((rlm_passwd_t *)instance)
	if(inst->ht) {
		release_ht(inst->ht);
		inst->ht = NULL;
	}
	talloc_free(inst->pwd_fmt);
	return 0;
#undef inst
}

static void result_add(TALLOC_CTX *ctx, rlm_passwd_t const *inst, request_t *request,
		       fr_pair_t **vps, struct mypasswd * pw, char when, char const *listname)
{
	uint32_t i;
	fr_pair_t *vp;

	for (i = 0; i < inst->num_fields; i++) {
		if (inst->pwd_fmt->field[i] && *inst->pwd_fmt->field[i] && pw->field[i] &&
		    (i != inst->key_field) && inst->pwd_fmt->listflag[i] == when) {
			if (!inst->ignore_empty || pw->field[i][0] != 0 ) { /* if value in key/value pair is not empty */
				vp = fr_pair_make(ctx, request->dict,
						  vps, inst->pwd_fmt->field[i], pw->field[i], T_OP_EQ);
				if (vp) {
					RDEBUG2("Added %s: '%s' to %s ", inst->pwd_fmt->field[i], pw->field[i], listname);
				}
			} else
				RDEBUG2("NOOP %s: '%s' to %s ", inst->pwd_fmt->field[i], pw->field[i], listname);
		}
	}
}

static unlang_action_t CC_HINT(nonnull) mod_passwd_map(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_passwd_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_passwd_t);

	char			buffer[1024];
	fr_pair_t		*key, *i;
	struct mypasswd		*pw, *last_found;
	fr_cursor_t		cursor;
	int			found = 0;

	key = fr_pair_find_by_da(&request->request_pairs, inst->keyattr);
	if (!key) RETURN_MODULE_NOTFOUND;

	for (i = fr_cursor_iter_by_da_init(&cursor, &key, inst->keyattr);
	     i;
	     i = fr_cursor_next(&cursor)) {
		/*
		 *	Ensure we have the string form of the attribute
		 */
#ifdef __clang_analyzer__
		/*
		 *	clang scan misses that fr_pair_print_value_quoted
		 *	always terminates the buffer.
		 */
		buffer[0] = '\0';
#endif
		fr_pair_print_value_quoted(&FR_SBUFF_OUT(buffer, sizeof(buffer)), i, T_BARE_WORD);
		pw = get_pw_nam(buffer, inst->ht, &last_found);
		if (!pw) continue;

		do {
			result_add(request, inst, request, &request->control_pairs, pw, 0, "config");
			result_add(request->reply, inst, request, &request->reply_pairs, pw, 1, "reply_items");
			result_add(request->packet, inst, request, &request->request_pairs, pw, 2, "request_items");
		} while ((pw = get_next(buffer, inst->ht, &last_found)));

		found++;

		if (!inst->allow_multiple) break;
	}

	if (!found) RETURN_MODULE_NOTFOUND;

	RETURN_MODULE_OK;
}

extern module_t rlm_passwd;
module_t rlm_passwd = {
	.magic		= RLM_MODULE_INIT,
	.name		= "passwd",
	.inst_size	= sizeof(rlm_passwd_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHORIZE]		= mod_passwd_map,
		[MOD_ACCOUNTING]	= mod_passwd_map,
		[MOD_POST_AUTH]		= mod_passwd_map,
	},
};
#endif /* TEST */
