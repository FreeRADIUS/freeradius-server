#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>

#include "radiusd.h"
#include "modules.h"

#define  BUFFERLEN  2048

static const char rcsid[] = "$Id$";

typedef struct unique_attr_list {
	int		attr;
	struct unique_attr_list *next;
} unique_attr_list;

typedef struct unique_config_t {
	char			*key;
	struct unique_attr_list *head;		
} unique_config_t;

static unique_config_t config;

static CONF_PARSER module_config[] = {
  { "key",  PW_TYPE_STRING_PTR, &config.key,  NULL },
  { NULL, -1, NULL, NULL }    /* end the list */
};

/*
 *	Add an attribute to the list.
 */
static void unique_add_attr(int dictattr) {
	struct unique_attr_list 	*new;		
	
	if((new = malloc(sizeof(struct unique_attr_list))) == NULL) {
		radlog(L_ERR, "rlm_acct_unique:  out of memory");
		exit(1);
	}
	memset((struct unique_attr_list *)new, 0, sizeof(unique_attr_list));

	/* Assign the attr to our new structure */
	new->attr = dictattr;	

	if (config.head) {
		new->next = config.head;
		config.head = new;
	} else {
		config.head = new;
	}
}

/*
 *	Parse a key.
 */
static int unique_parse_key(char *key) {
	char *ptr, *prev, *keyptr;
	DICT_ATTR *a;
	
	keyptr = key;
	ptr = key;
	prev = key;
	
	/* Let's remove spaces in the string */
	while(ptr && *ptr!='\0') {
		while(*ptr == ' ') 
			ptr++;
		*keyptr = *ptr;
		keyptr++;
		ptr++;
	}
	*keyptr = '\0';
	
	ptr = key;
	while(ptr) {
		switch(*ptr) {
		case ',':
			*ptr = '\0';
			if((a = dict_attrbyname(prev)) == NULL) {
				radlog(L_ERR, "rlm_acct_unique: Cannot find attribute '%s' in dictionary", prev);
				return -1;
			}
			*ptr = ',';
			prev = ptr+1;
			unique_add_attr(a->attr); 
			break;
		case '\0':
			if((a = dict_attrbyname(prev)) == NULL) {
				radlog(L_ERR, "rlm_acct_unique: Cannot find '%s' in dictionary", prev);
				return -1;
			}
			unique_add_attr(a->attr);
			return 0;
			break;
		case ' ':
			continue;
			break;
		}
		ptr++;	
	}	
	
	return 0;
}

static int unique_instantiate(CONF_SECTION *conf, void **instance) {

	struct unique_config_t *inst;

	/*
	 *  Set up a storage area for instance data
	 */
	if ((inst = malloc(sizeof(*inst))) == NULL) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));
	
	if (cf_section_parse(conf, module_config) < 0) {
		free(inst);
		return -1;
	}

	/*
	 *	Grab the key.
	 */
	inst->key = config.key;
	config.key = NULL;

	/* 
	 *	Check to see if 'key' has something in it 
	 */	
	if (!inst->key) {
		radlog(L_ERR,"rlm_acct_unique: Cannot find value for 'key' in configuration.");
		return -1;
	}

	/* 
	 * Go thru the list of keys and build attr_list;
	 */	
	if (unique_parse_key(inst->key) < 0) {
		return -1;
	};

	inst->head = config.head;
	*instance = inst;

 	return 0;
}

/*
 *  Create a (hopefully) unique Acct-Unique-Session-Id from
 *  attributes listed in 'key' from radiusd.conf
 */
static int unique_accounting(void *instance, REQUEST *request)
{
  char buffer[BUFFERLEN];
  u_char md5_buf[16];

  VALUE_PAIR *vp;
  char *p;
  int length, left;
  struct unique_config_t *inst = instance;
  struct unique_attr_list *cur;
  
  /* initialize variables */
  p = buffer;
  left = BUFFERLEN;
  length = 0;
  cur = inst->head;
  
  /* loop over items to create unique identifiers */
  while (cur) {
	  vp = pairfind(request->packet->vps, cur->attr);
	  length = vp_prints(p, left, vp);
	  left -= length + 1;	/* account for ',' in between elements */
	  p += length;
	  *(p++) = ',';		/* ensure seperation of elements */
	  cur = cur->next;
  }
  buffer[BUFFERLEN-left-1] = '\0';

  DEBUG2("rlm_acct_unique: Hashing '%s'", buffer);
  /* calculate a 'unique' string based on the above information */
  librad_md5_calc(md5_buf, (u_char *)buffer, (p - buffer));
  sprintf(buffer, "%02x%02x%02x%02x%02x%02x%02x%02x",
	  md5_buf[0], md5_buf[1], md5_buf[2], md5_buf[3],
	  md5_buf[4], md5_buf[5], md5_buf[6], md5_buf[7]);

  DEBUG2("rlm_acct_unique: Acct-Unique-Session-ID = \"%s\".", buffer);
  
  vp = pairmake("Acct-Unique-Session-Id", buffer, 0);
  if (!vp) {
	  radlog(L_ERR, "%s", librad_errstr);
	  return RLM_MODULE_FAIL;
  }

  /* add the (hopefully) unique session ID to the packet */
  pairadd(&request->packet->vps, vp);
  
  /* FIXME:  Uncomment here once we iron out module_accounting() */
  /*return RLM_MODULE_UPDATED;*/
  return RLM_MODULE_OK;
}

static int unique_detach(void *instance) {
	struct unique_config_t *inst = instance;
	struct unique_attr_list *next = inst->head;
	
	free(inst->key);
	while(inst->head) {
		next = inst->head->next;
		DEBUG("HERE:  %d", inst->head->attr);
		free(inst->head);
		inst->head = next;
	}
	free(inst);

	return 0;
}

/* FIXME: unique_accounting should probably be called from preacct */
/* globally exported name */
module_t rlm_acct_unique = {
  "Acct-Unique-Session-Id",
  0,				/* type: reserved */
  NULL,				/* initialization */
  unique_instantiate,		/* instantiation */
  NULL,				/* authorization */
  NULL,				/* authentication */
  NULL,				/* preaccounting */
  unique_accounting,		/* accounting */
  NULL,				/* checksimul */
  unique_detach,		/* detach */
  NULL,				/* destroy */
};
