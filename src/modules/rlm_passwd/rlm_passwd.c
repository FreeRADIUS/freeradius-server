/*
 * rlm_passwd.c
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
 * Copyright 2000,2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

struct mypasswd {
	struct mypasswd *next;
	char *listflag;
	char *field[1];
};

struct hashtable {
	int tablesize;
	int keyfield;
	int nfields;
	int islist;
	int ignorenis;
	char * filename;
	struct mypasswd **table;
	struct mypasswd *last_found;
	char buffer[1024];
	FILE *fp;
	char delimiter;
};


#ifdef TEST

#define rad_malloc(s) malloc(s)

void printpw(struct mypasswd *pw, int nfields){
  int i;
  if (pw) {
  	for( i = 0; i < nfields; i++ ) printf("%s:", pw->field[i]);
  	printf("\n");
  }
  else printf ("Not found\n");
  fflush(stdout);
}
#endif


static struct mypasswd * mypasswd_malloc(const char* buffer, int nfields, size_t* len)
{
	struct mypasswd *t;
	/* reserve memory for (struct mypasswd) + listflag (nfields * sizeof (char*)) +
	** fields (nfields * sizeof (char)) + strlen (inst->format) + 1 */

  	*len=sizeof (struct mypasswd) + nfields * sizeof (char*) + nfields * sizeof (char ) + strlen(buffer) + 1;
	t = (struct mypasswd *) rad_malloc(*len);
	if (t) memset(t, 0, *len);
  	return (t);
}

static int string_to_entry(const char* string, int nfields, char delimiter,
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
	if (!len || !passwd ||
	    bufferlen < (len + nfields * sizeof (char*) + nfields * sizeof (char) + sizeof (struct mypasswd) + 1) ) return 0;
	passwd->next = NULL;
	data_beg=(char *)passwd + sizeof(struct mypasswd);
	str = data_beg + nfields * sizeof (char) + nfields * sizeof (char*);
	memcpy (str, string, len);
	str[len] = 0;
	passwd->field[fn++] = str;
	passwd->listflag = data_beg + nfields * sizeof (char *);
	for(i=0; i < len; i++){
		if (str[i] == delimiter) {
			str[i] = 0;
			passwd->field[fn++] = str + i + 1;
			if (fn == nfields) break;
		}
	}
	for (; fn < nfields; fn++) passwd->field[fn] = NULL;
	return len + nfields * sizeof (char) + nfields * sizeof (char*) + sizeof (struct mypasswd) + 1;
}


static void destroy_password (struct mypasswd * pass)
{
	struct mypasswd *p;
	while ((p=pass)!=NULL) {
		pass = pass->next;
		free(p);
	}
}


static unsigned int hash(const char * username, unsigned int tablesize)
{
	int h=1;
	while (*username) {
		h = h * 7907 + *username++;
	}
	return h%tablesize;
}

static void release_hash_table(struct hashtable * ht){
	int i;

	if (ht == NULL) return;
	for (i = 0; i < ht->tablesize; i++)
 		if (ht->table[i])
 			destroy_password(ht->table[i]);
	if (ht->table) {
		free(ht->table);
		ht->table = NULL;
	}
	if (ht->fp) {
		fclose(ht->fp);
		ht->fp = NULL;
	}
	ht->tablesize = 0;
}

static void release_ht(struct hashtable * ht){
	if (!ht) return;
	release_hash_table(ht);
	if (ht->filename) free(ht->filename);
	free(ht);
}

static struct hashtable * build_hash_table (const char * file, int nfields,
	int keyfield, int islist, int tablesize, int ignorenis, char delimiter)
{
#define passwd ((struct mypasswd *) ht->buffer)
	char buffer[1024];
	struct hashtable* ht;
	size_t len;
	unsigned int h;
	struct mypasswd *hashentry, *hashentry1;
	char *list;
	char *nextlist=0;
	int i;

	ht = (struct hashtable *) rad_malloc(sizeof(struct hashtable));
	if(!ht) {
		return NULL;
	}
	memset(ht, 0, sizeof(struct hashtable));
	ht->filename = strdup(file);
	if(!ht->filename) {
		free(ht);
		return NULL;
	}
	ht->tablesize = tablesize;
	ht->nfields = nfields;
	ht->keyfield = keyfield;
	ht->islist = islist;
	ht->ignorenis = ignorenis;
	if (delimiter) ht->delimiter = delimiter;
	else ht->delimiter = ':';
	if(!tablesize) return ht;
	if(!(ht->fp = fopen(file,"r"))) {
		free(ht->filename);
		free(ht);
		               return NULL;
	}
	memset(ht->buffer, 0, 1024);
	ht->table = (struct mypasswd **) rad_malloc (tablesize * sizeof(struct mypasswd *));
	if (!ht->table) {
		/*
		 * Unable allocate memory for hash table
		 * Still work without it
		 */
		ht->tablesize = 0;
		return ht;
	}
	memset(ht->table, 0, tablesize * sizeof(struct mypasswd *));
	while (fgets(buffer, 1024, ht->fp)) {
		if(*buffer && *buffer!='\n' && (!ignorenis || (*buffer != '+' && *buffer != '-')) ){
			if(!(hashentry = mypasswd_malloc(buffer, nfields, &len))){
				release_hash_table(ht);
				return ht;
			}
			len = string_to_entry(buffer, nfields, ht->delimiter, hashentry, len);
			if(!hashentry->field[keyfield] || *hashentry->field[keyfield] == '\0') {
				free(hashentry);
				continue;
			}

			if (islist) {
				list = hashentry->field[keyfield];
				for (nextlist = list; *nextlist && *nextlist!=','; nextlist++);
				if (*nextlist) *nextlist++ = 0;
				else nextlist = 0;
			}
			h = hash(hashentry->field[keyfield], tablesize);
			hashentry->next = ht->table[h];
			ht->table[h] = hashentry;
			if (islist) {
				for(list=nextlist; nextlist; list = nextlist){
					for (nextlist = list; *nextlist && *nextlist!=','; nextlist++);
					if (*nextlist) *nextlist++ = 0;
					else nextlist = 0;
					if(!(hashentry1 = mypasswd_malloc("", nfields, &len))){
						release_hash_table(ht);
						return ht;
					}
					for (i=0; i<nfields; i++) hashentry1->field[i] = hashentry->field[i];
					hashentry1->field[keyfield] = list;
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

static struct mypasswd * get_next(char *name, struct hashtable *ht)
{
#define passwd ((struct mypasswd *) ht->buffer)
	struct mypasswd * hashentry;
	char buffer[1024];
	int len;
	char *list, *nextlist;

	if (ht->tablesize > 0) {
		/* get saved address of next item to check from buffer */
		hashentry = ht->last_found;
		for (; hashentry; hashentry = hashentry->next) {
			if (!strcmp(hashentry->field[ht->keyfield], name)) {
				/* save new address */
				ht->last_found = hashentry->next;
				return hashentry;
			}
		}
		return NULL;
	}
	/*	printf("try to find in file\n"); */
	if (!ht->fp) return NULL;
	while (fgets(buffer, 1024,ht->fp)) {
		if(*buffer && *buffer!='\n' && (len = string_to_entry(buffer, ht->nfields, ht->delimiter, passwd, sizeof(ht->buffer)-1)) &&
			(!ht->ignorenis || (*buffer !='-' && *buffer != '+') ) ){
			if(!ht->islist) {
				if(!strcmp(passwd->field[ht->keyfield], name))
					return passwd;
			}
			else {
				for (list = passwd->field[ht->keyfield], nextlist = list; nextlist; list = nextlist) {
					for(nextlist = list; *nextlist && *nextlist!=','; nextlist++);
					if(!*nextlist)nextlist = 0;
					else *nextlist++ = 0;
					if(!strcmp(list, name)) return passwd;
				}
			}

		}
	}
	fclose(ht->fp);
	ht->fp = NULL;
	return NULL;
#undef passwd
}

static struct mypasswd * get_pw_nam(char * name, struct hashtable* ht)
{
	int h;
	struct mypasswd * hashentry;

	if (!ht || !name || *name == '\0') return NULL;
	ht->last_found = NULL;
	if (ht->tablesize > 0) {
		h = hash (name, ht->tablesize);
		for (hashentry = ht->table[h]; hashentry; hashentry = hashentry->next)
			if (!strcmp(hashentry->field[ht->keyfield], name)){
				/* save address of next item to check into buffer */
				ht->last_found=hashentry->next;
				return hashentry;
			}
		return NULL;
	}
	if (ht->fp) {
		fclose(ht->fp);
		ht->fp = NULL;
	}
	if (!(ht->fp=fopen(ht->filename, "r"))) return NULL;
	return get_next(name, ht);
}

#ifdef TEST

#define MALLOC_CHECK_ 1

int main(void){
 struct hashtable *ht;
 char *buffer;
 struct mypasswd* pw;
 int i;

 ht = build_hash_table("/etc/group", 4, 3, 1, 100, 0, ":");
 if(!ht) {
 	printf("Hash table not built\n");
 	return -1;
 }
 for (i=0; i<ht->tablesize; i++) if (ht->table[i]) {
  printf("%d:\n", i);
  for(pw=ht->table[i]; pw; pw=pw->next) printpw(pw, 4);
 }

 while(fgets(buffer, 1024, stdin)){
  buffer[strlen(buffer)-1] = 0;
  pw = get_pw_nam(buffer, ht);
  printpw(pw,4);
  while (pw = get_next(buffer, ht)) printpw(pw,4);
 }
 release_ht(ht);
}

#else  /* TEST */
struct passwd_instance {
	struct hashtable *ht;
	struct mypasswd *pwdfmt;
	char *filename;
	char *format;
	char * delimiter;
	int allowmultiple;
	int ignorenislike;
	int hashsize;
	int nfields;
	int keyfield;
	int listable;
	int keyattr;
	int keyattrtype;
	int ignoreempty;
};

static const CONF_PARSER module_config[] = {
	{ "filename",   PW_TYPE_FILENAME,
	   offsetof(struct passwd_instance, filename), NULL,  NULL },
	{ "format",   PW_TYPE_STRING_PTR,
	   offsetof(struct passwd_instance, format), NULL,  NULL },
	{ "delimiter",   PW_TYPE_STRING_PTR,
	   offsetof(struct passwd_instance, delimiter), NULL,  ":" },
	{ "ignorenislike",   PW_TYPE_BOOLEAN,
	   offsetof(struct passwd_instance, ignorenislike), NULL,  "yes" },
	{ "ignoreempty",   PW_TYPE_BOOLEAN,
	   offsetof(struct passwd_instance, ignoreempty), NULL,  "yes" },
	{ "allowmultiplekeys",   PW_TYPE_BOOLEAN,
	   offsetof(struct passwd_instance, allowmultiple), NULL,  "no" },
	{ "hashsize",   PW_TYPE_INTEGER,
	   offsetof(struct passwd_instance, hashsize), NULL,  "100" },
	{ NULL, -1, 0, NULL, NULL }
};

static int passwd_instantiate(CONF_SECTION *conf, void **instance)
{
#define inst ((struct passwd_instance *)*instance)
	int nfields=0, keyfield=-1, listable=0;
	char *s;
	char *lf=NULL; /* destination list flags temporary */
	size_t len;
	int i;
	DICT_ATTR * da;

	*instance = rad_malloc(sizeof(struct passwd_instance));
	if ( !*instance) {
		radlog(L_ERR, "rlm_passwd: cann't alloc instance");
		return -1;
	}
	memset(*instance, 0, sizeof(struct passwd_instance));
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		radlog(L_ERR, "rlm_passwd: cann't parse configuration");
		return -1;
	}
	if(!inst->filename || *inst->filename == '\0' || !inst->format || *inst->format == '\0') {
		radlog(L_ERR, "rlm_passwd: cann't find passwd file and/or format in configuration");
		return -1;
	}
	lf=strdup(inst->format);
	if ( lf == NULL) {
		radlog(L_ERR, "rlm_passwd: memory allocation failed for lf");
		return -1;
	}
	memset(lf, 0, strlen(inst->format));
	s = inst->format - 1;
	do {
		if(s == inst->format - 1 || *s == ':'){
			if(*(s+1) == '*'){
				keyfield = nfields;
				s++;
			}
			if(*(s+1) == ','){
				listable = 1;
				s++;
			}
			if(*(s+1) == '='){
				lf[nfields]=1;
				s++;
			}
			if(*(s+1) == '~'){
				lf[nfields]=2;
				s++;
			}
			nfields++;
		}
		s++;
	}while(*s);
	if(keyfield < 0) {
		radlog(L_ERR, "rlm_passwd: no field market as key in format: %s", inst->format);
		free(lf);
		return -1;
	}
	if (! (inst->ht = build_hash_table (inst->filename, nfields, keyfield, listable, inst->hashsize, inst->ignorenislike, *inst->delimiter)) ){
		radlog(L_ERR, "rlm_passwd: can't build hashtable from passwd file");
		free(lf);
		return -1;
	}
	if (! (inst->pwdfmt = mypasswd_malloc(inst->format, nfields, &len)) ){
		radlog(L_ERR, "rlm_passwd: memory allocation failed");
		release_ht(inst->ht);
		free(lf);
		return -1;
	}
	if (!string_to_entry(inst->format, nfields, ':', inst->pwdfmt , len)) {
		radlog(L_ERR, "rlm_passwd: unable to convert format entry");
		release_ht(inst->ht);
		free(lf);
		return -1;
	}

	memcpy(inst->pwdfmt->listflag, lf, nfields);

	free(lf);
	for (i=0; i<nfields; i++) {
		if (*inst->pwdfmt->field[i] == '*') inst->pwdfmt->field[i]++;
		if (*inst->pwdfmt->field[i] == ',') inst->pwdfmt->field[i]++;
		if (*inst->pwdfmt->field[i] == '=') inst->pwdfmt->field[i]++;
		if (*inst->pwdfmt->field[i] == '~') inst->pwdfmt->field[i]++;
	}
	if (!*inst->pwdfmt->field[keyfield]) {
		radlog(L_ERR, "rlm_passwd: key field is empty");
		release_ht(inst->ht);
		return -1;
	}
	if (! (da = dict_attrbyname (inst->pwdfmt->field[keyfield])) ) {
		radlog(L_ERR, "rlm_passwd: unable to resolve attribute: %s", inst->pwdfmt->field[keyfield]);
		release_ht(inst->ht);
		return -1;
	}
	inst->keyattr = da->attr;
	inst->keyattrtype = da->type;
	inst->nfields = nfields;
	inst->keyfield = keyfield;
	inst->listable = listable;
	DEBUG("rlm_passwd: nfields: %d keyfield %d(%s) listable: %s", nfields, keyfield, inst->pwdfmt->field[keyfield], listable?"yes":"no");
	return 0;

#undef inst
}

static int passwd_detach (void *instance) {
#define inst ((struct passwd_instance *)instance)
	if(inst->ht) release_ht(inst->ht);
	free(instance);
	return 0;
#undef inst
}

static void addresult (struct passwd_instance * inst, REQUEST *request, VALUE_PAIR ** vp, struct mypasswd * pw, char when, const char *listname)
{
	int i;
	VALUE_PAIR *newpair;

	for (i=0; i<inst->nfields; i++) {
		if (inst->pwdfmt->field[i] && *inst->pwdfmt->field[i] && pw->field[i] && i != inst->keyfield  && inst->pwdfmt->listflag[i] == when) {
			if ( !inst->ignoreempty || pw->field[i][0] != 0 ) { /* if value in key/value pair is not empty */
				if (! (newpair = pairmake (inst->pwdfmt->field[i], pw->field[i], T_OP_EQ))) {
					radlog(L_AUTH, "rlm_passwd: Unable to create %s: %s", inst->pwdfmt->field[i], pw->field[i]);
					return;
				}
				RDEBUG("Added %s: '%s' to %s ", inst->pwdfmt->field[i], pw->field[i], listname);
				pairadd (vp, newpair);
			} else
				RDEBUG("NOOP %s: '%s' to %s ", inst->pwdfmt->field[i], pw->field[i], listname);
		}
	}
}

static int passwd_map(void *instance, REQUEST *request)
{
#define inst ((struct passwd_instance *)instance)
	char * name;
	char buffer[1024];
	VALUE_PAIR * key;
	struct mypasswd * pw;
	int found = 0;

	for (key = request->packet->vps;
	 key && (key = pairfind (key, inst->keyattr));
	  key = key->next ){
		switch (inst->keyattrtype) {
			case PW_TYPE_INTEGER:
				snprintf(buffer, 1024, "%u", key->vp_integer);
				name = buffer;
				break;
			case PW_TYPE_ETHERNET:
				vp_prints_value(buffer, sizeof(buffer),
						key, 0);
				name = buffer;
				break;
			default:
				name = key->vp_strvalue;
		}
		if (! (pw = get_pw_nam(name, inst->ht)) ) {
			continue;
		}
		do {
			addresult(inst, request, &request->config_items, pw, 0, "config_items");
			addresult(inst, request, &request->reply->vps, pw, 1, "reply_items");
			addresult(inst, request, &request->packet->vps, 	pw, 2, "request_items");
		} while ( (pw = get_next(name, inst->ht)) );
		found++;
		if (!inst->allowmultiple) break;
	}
	if(!found) {
		return RLM_MODULE_NOTFOUND;
	}
	return RLM_MODULE_OK;

#undef inst
}

module_t rlm_passwd = {
	RLM_MODULE_INIT,
	"passwd",
	RLM_TYPE_CHECK_CONFIG_SAFE | RLM_TYPE_HUP_SAFE,   	/* type */
	passwd_instantiate,		/* instantiation */
	passwd_detach,			/* detach */
	{
		NULL,			/* authentication */
		passwd_map,		/* authorization */
		NULL,			/* pre-accounting */
		passwd_map,		/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		passwd_map	       	/* post-auth */
	},
};
#endif /* TEST */
