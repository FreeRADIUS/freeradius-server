/*
 * mapping.c	LDAP attribute to RADIUS attribute mappings
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
 *   Copyright 1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,
 *	       2009,2010,2011,1012 The FreeRADIUS Server Project.
 *
 *   Copyright 2012 Alan DeKok <aland@freeradius.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/modules.h>
#include	<freeradius-devel/rad_assert.h>

#include	"mapping.h"

#define GENERIC_ATTRIBUTE_ID "$GENERIC$"
#define MAX_ARGV 5

void rlm_ldap_map_free(TLDAP_RADIUS **map)
{
	TLDAP_RADIUS *t, *next;

	if (!map || !*map) return;

	for (t = *map; t != NULL; t = next) {
		next = t->next;
		free(t);
	}

	*map = NULL;
}

int rlm_ldap_map_read(const char *xlat_name,
		      const char *filename,
		      TLDAP_RADIUS **check_map,
		      TLDAP_RADIUS **reply_map,
		      int offset,
		      char *attrs[MAX_ATTRMAP])
{
	FILE *fp;
	int total;
	int lineno, argc;
	FR_TOKEN operator;
	TLDAP_RADIUS *pair;
	char *argv[MAX_ARGV];
	char *p, buffer[1024];

	fp = fopen(filename, "r");
	if (!fp) {
		radlog(L_ERR, "%s: Failed opening %s: %s",
		       xlat_name, filename, strerror(errno));
		return -1;
	}

	lineno = 0;
	total = offset;

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		size_t ldap_size, radius_size;

		lineno++;

		p = strchr(buffer, '#');
		if (p) *p = 0;

		argc = str2argv(buffer, argv, MAX_ARGV);
		if (argc == 0) continue;

		if ((argc < 3) || (argc > 4)) {
			radlog(L_ERR, "%s: Invalid format in file %s line %d",
			       xlat_name, filename, lineno);
		error:
			fclose(fp);
			rlm_ldap_map_free(check_map);
			rlm_ldap_map_free(reply_map);
			return -1;
		}

		if (argc == 3) {
			operator = T_OP_INVALID; /* use defaults */
		} else {
			operator = fr_str2int(fr_tokens, argv[3], T_OP_INVALID);
			if ((operator < T_OP_ADD) || (operator > T_OP_CMP_EQ)) {
				radlog(L_ERR, "%s: Invalid operator '%s' in file %s line %d",
				       xlat_name, argv[3],
				       filename, lineno);
				goto error;
			}
		}

		/*
		 *	Sanity check checkItem or replyItem
		 */
		if ((strcasecmp(argv[0], "checkItem") != 0) &&
		    (strcasecmp(argv[0], "replyItem") != 0)) {
			radlog(L_ERR, "%s: Entry does not have \"checkItem\" or \"replyItem\" in column 0 of file %s line %d",
			       xlat_name, filename, lineno);
			goto error;
		}

		/*
		 *	Sanity check RADIUS attribute.
		 *	Allow generic name, too.
		 */
		if ((strcmp(argv[1], GENERIC_ATTRIBUTE_ID) != 0) &&
		    !dict_attrbyname(argv[1])) {
			radlog(L_ERR, "%s: Unknown RADIUS attribute \"%s\" in file %s line %d",
			       xlat_name, argv[1], filename, lineno);
			goto error;
		}

		/* create new TLDAP_RADIUS list node */
		radius_size = strlen(argv[1]);
		ldap_size = strlen(argv[2]);

		/*
		 *	Doing tons of strcmp() at run-time is bad.
		 *	Instead, just set the radius field to be ""
		 */
		if (strcmp(argv[1], GENERIC_ATTRIBUTE_ID) == 0) {
			argv[1] += radius_size;
			radius_size = 0;
		}

		pair = rad_malloc(sizeof(*pair) + radius_size + ldap_size + 2);
		pair->ldap_attr = ((char *) pair) + sizeof(*pair);
		pair->radius_attr = pair->ldap_attr + ldap_size + 1;

		memcpy(pair->radius_attr, argv[1], radius_size + 1);
		memcpy(pair->ldap_attr, argv[2], ldap_size + 1);
		pair->operator = operator;

		/*
		 *	Place it in the correct list.
		 */
		if (*argv[0] == 'c') {
			pair->next = *check_map;
			*check_map = pair;
		} else {
			pair->next = *reply_map;
			*reply_map = pair;
		}

		attrs[total++] = pair->ldap_attr;

		if (total >= MAX_ATTRMAP) {
			radlog(L_ERR, "%s: ERROR Too many entries (%d) in %s",
			       xlat_name, total, filename);
			goto error;
		}

		DEBUG("       %s: %s --> %s",
		      xlat_name, pair->ldap_attr,
		      *pair->radius_attr ? pair->radius_attr : GENERIC_ATTRIBUTE_ID);
	}

	fclose(fp);

	attrs[total] = NULL;
	return 0; /* success */
}

static VALUE_PAIR *ldap2vp(const char *xlat_name, TLDAP_RADIUS *pair,
			   const char *value, int is_check)
{
	int do_xlat;
	const char *p;
	VALUE_PAIR *vp;
	FR_TOKEN    token, operator;
	char buffer[1024];

	p = value;

	if (!*pair->radius_attr) {
		FR_TOKEN eol;

		vp = pairread(&p, &eol);
		goto done;	/* I hate indentation */
	}

	/*
	 *	This is a one-to-one-mapped attribute
	 */
	operator = gettoken(&p, buffer, sizeof(buffer));
	if (operator < T_EQSTART || operator > T_EQEND) {
		if (pair->operator != T_OP_INVALID) {
			operator = pair->operator;
		} else if (is_check) {
			operator = T_OP_CMP_EQ;
		} else { 
			operator = T_OP_EQ;
		}
	} else {		/* skip the operator */
		value = p;
	}

	if (!*value) {
	empty_string:
		DEBUG("  [%s] FAILED parsing %s -> empty string",
		      xlat_name, pair->ldap_attr);
		return NULL;
	}
	
	p = value;
	token = gettoken(&p, buffer, sizeof(buffer));
	switch (token) {
	case T_BARE_WORD:
	case T_SINGLE_QUOTED_STRING:
	case T_DOUBLE_QUOTED_STRING:
		do_xlat = FALSE;
		break;
			
		/* the value will be xlat'ed later */
	case T_BACK_QUOTED_STRING:
		do_xlat = TRUE;
		break;

	case T_OP_INVALID:
	default:
		DEBUG("  [%s] FAILED Parsing %s -> %s",
		      xlat_name, pair->ldap_attr, value);
		return NULL;

	}

	if (!*buffer) goto empty_string;

	/*
	 *	Create the pair.
	 */
	if (do_xlat) {
		vp = pairmake_xlat(pair->radius_attr, buffer, operator);
	} else {
		vp = pairmake(pair->radius_attr, buffer, operator);
	}

done:
	if (!vp) {
		DEBUG("  [%s] FAILED parsing %s -> %s",
		      xlat_name, pair->ldap_attr, value);
		return NULL;
	}
	
	if (fr_debug_flag) {
		vp_prints(buffer, sizeof(buffer), vp);
		DEBUG("  [%s] %s -> %s",
		      xlat_name, pair->ldap_attr, buffer);
	}
	
	return vp;
}

/*****************************************************************************
 *	Get RADIUS attributes from LDAP object
 *	( according to draft-adoba-radius-05.txt
 *	  <http://www.ietf.org/internet-drafts/draft-adoba-radius-05.txt> )
 *
 *****************************************************************************/
VALUE_PAIR *rlm_ldap_pairget(const char *xlat_name,
			     LDAP *ld, LDAPMessage *entry,
			     TLDAP_RADIUS *map,
			     VALUE_PAIR **vps, int is_check)
{
	char          **vals;
	int             count;
	int             i;
	TLDAP_RADIUS   *pair;
	VALUE_PAIR     *head, **tail;

	head = NULL;
	tail = &head;

	/*
	 *	check if there is a mapping from this LDAP attribute
	 *	to a RADIUS attribute
	 */
	for (pair = map; pair != NULL; pair = pair->next) {
		/*
		 *	No mapping found, skip it.
		 */
		vals = ldap_get_values(ld, entry, pair->ldap_attr);
		if (!vals) continue;

		/*
		 *	Find out how many values there are for the
		 *	attribute and extract all of them.
		 */
		count = ldap_count_values(vals);

		/*
		 *	FIXME: The old code DELETES all references
		 *	to pair->radius_attr from the vps list.
		 *	Why?
		 */

		for (i = 0; i < count; i++) {
			VALUE_PAIR *vp;

			vp = ldap2vp(xlat_name, pair, vals[i], is_check);
			if (!vp) continue;

			/*
			 *	FIXME: if i==0, delete from vps?
			 */

			*tail = vp;
			tail = &vp->next;
		}

		ldap_value_free(vals);
	}

	return head;
}
