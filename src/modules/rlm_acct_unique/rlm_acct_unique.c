/*
 * rlm_acct_unique.c
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

#include <ctype.h>

/*
 *  Room for at least 16 attributes.
 */
#define  BUFFERLEN  4096

typedef struct rlm_acct_unique_list_t {
	DICT_ATTR		      *dattr;
	struct rlm_acct_unique_list_t *next;
} rlm_acct_unique_list_t;

typedef struct rlm_acct_unique_t {
	char			*key;
	rlm_acct_unique_list_t *head;
} rlm_acct_unique_t;

static const CONF_PARSER module_config[] = {
  { "key",  PW_TYPE_STRING_PTR, offsetof(rlm_acct_unique_t,key), NULL,  NULL },
  { NULL, -1, 0, NULL, NULL }    /* end the list */
};

/*
 *	Add an attribute to the list.
 */
static void unique_add_attr(rlm_acct_unique_t *inst, DICT_ATTR *dattr)
{
	rlm_acct_unique_list_t 	*new;

	new = rad_malloc(sizeof(*new));
	memset(new, 0, sizeof(*new));

	/* Assign the attr to our new structure */
	new->dattr = dattr;

	new->next = inst->head;
	inst->head = new;
}

/*
 *	Parse a key.
 */
static int unique_parse_key(rlm_acct_unique_t *inst, char *key)
{
	char *ptr, *prev, *keyptr;
	DICT_ATTR *a;

	prev = key;
	keyptr = ptr = key;

	/* Let's remove spaces in the string */
	while (*keyptr) {
		if (isspace((int) *keyptr)) {
			keyptr++;
		} else {
			*(ptr++) = *(keyptr++);
		}
	}
	*ptr = '\0';


	keyptr = ptr = key;
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
			unique_add_attr(inst, a);
			break;
		case '\0':
			if((a = dict_attrbyname(prev)) == NULL) {
				radlog(L_ERR, "rlm_acct_unique: Cannot find attribute '%s' in dictionary", prev);
				return -1;
			}
			unique_add_attr(inst, a);
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

/*
 *	Needed before instantiate for cleanup.
 */
static int unique_detach(void *instance)
{
	rlm_acct_unique_t *inst = instance;
	rlm_acct_unique_list_t *this, *next;

	for (this = inst->head; this != NULL; this = next) {
		next = this->next;
		free(this);
	}
	free(inst);

	return 0;
}

static int unique_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_acct_unique_t *inst;

	/*
	 *  Set up a storage area for instance data
	 */
	inst = rad_malloc(sizeof(*inst));
	memset(inst, 0, sizeof(*inst));

	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	/*
	 *	Check to see if 'key' has something in it
	 */
	if (!inst->key) {
		radlog(L_ERR,"rlm_acct_unique: Cannot find value for 'key' in configuration.");
		free(inst);
		return -1;
	}

	/*
	 * Go thru the list of keys and build attr_list;
	 */
	if (unique_parse_key(inst, inst->key) < 0) {
		unique_detach(inst); /* clean up memory */
		return -1;
	};

	*instance = inst;

 	return 0;
}

/*
 *  Create a (hopefully) unique Acct-Unique-Session-Id from
 *  attributes listed in 'key' from radiusd.conf
 */
static int add_unique_id(void *instance, REQUEST *request)
{
	char buffer[BUFFERLEN];
	u_char md5_buf[16];

	VALUE_PAIR *vp;
	char *p;
	int length, left;
	rlm_acct_unique_t *inst = instance;
	rlm_acct_unique_list_t *cur;

	/* initialize variables */
	p = buffer;
	left = BUFFERLEN;
	length = 0;
	cur = inst->head;

	/*
	 *  A unique ID already exists: don't do anything.
	 */
	vp = pairfind(request->packet->vps, PW_ACCT_UNIQUE_SESSION_ID);
	if (vp) {
		return RLM_MODULE_NOOP;
	}

	/* loop over items to create unique identifiers */
	while (cur) {
		VALUE_PAIR hack;

		vp = pairfind(request->packet->vps, cur->dattr->attr);
		if (!vp) {
			/*
			 *	This was changed in 2.x, but it's still
			 *	useful.
			 */
			if ((cur->dattr->attr == PW_CLIENT_IP_ADDRESS) &&
			    (request->packet->src_ipaddr.af == AF_INET)) {
				memset(&hack, 0, sizeof(hack));
				hack.name = cur->dattr->name;
				hack.attribute = cur->dattr->attr;
				hack.type = cur->dattr->type;
				hack.operator = T_OP_EQ;
				hack.length = 4;
				hack.lvalue = request->packet->src_ipaddr.ipaddr.ip4addr.s_addr;
				vp = &hack;
			} else {
				RDEBUG2("WARNING: Attribute %s was not found in request, unique ID MAY be inconsistent", cur->dattr->name);
			}
		}
		length = vp_prints(p, left, vp);
		left -= length + 1;	/* account for ',' in between elements */
		p += length;
		*(p++) = ',';		/* ensure seperation of elements */
		cur = cur->next;
	}
	buffer[BUFFERLEN-left-1] = '\0';

	RDEBUG2("Hashing '%s'", buffer);
	/* calculate a 'unique' string based on the above information */
	fr_md5_calc(md5_buf, (u_char *)buffer, (p - buffer));
	sprintf(buffer, "%02x%02x%02x%02x%02x%02x%02x%02x",
		md5_buf[0], md5_buf[1], md5_buf[2], md5_buf[3],
		md5_buf[4], md5_buf[5], md5_buf[6], md5_buf[7]);

	RDEBUG2("Acct-Unique-Session-ID = \"%s\".", buffer);

	vp = pairmake("Acct-Unique-Session-Id", buffer, 0);
	if (!vp) {
		radlog(L_ERR, "%s", fr_strerror());
		return RLM_MODULE_FAIL;
	}

	/* add the (hopefully) unique session ID to the packet */
	pairadd(&request->packet->vps, vp);

	return RLM_MODULE_OK;
}

/* globally exported name */
module_t rlm_acct_unique = {
	RLM_MODULE_INIT,
	"Acct-Unique-Session-Id",
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	unique_instantiate,		/* instantiation */
	unique_detach,		/* detach */
	{
		NULL,			/* authentication */
		add_unique_id,	/* authorization */
		add_unique_id,	/* preaccounting */
		add_unique_id,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
