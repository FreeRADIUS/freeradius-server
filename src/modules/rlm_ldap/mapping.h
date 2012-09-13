/*
 * mapping.h	LDAP attribute to RADIUS attribute mappings
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

#include	<lber.h>
#include        <ldap.h>

/* linked list of mappings between RADIUS attributes and LDAP attributes */
typedef struct TLDAP_RADIUS TLDAP_RADIUS;

struct TLDAP_RADIUS {
	char		*ldap_attr;
	char		*radius_attr;
	FR_TOKEN	operator;
	int		is_check;
	TLDAP_RADIUS	*next;
};

#define MAX_ATTRMAP (256)

int rlm_ldap_map_read(const char *xlat_name,
		      const char *filename,
		      TLDAP_RADIUS **check_map,
		      TLDAP_RADIUS **reply_map,
		      int offset,
		      char *attrs[MAX_ATTRMAP]);
void rlm_ldap_map_free(TLDAP_RADIUS **map);

VALUE_PAIR *rlm_ldap_pairget(const char *xlat_name,
			     LDAP *ld, LDAPMessage *entry,
			     TLDAP_RADIUS *map,
			     VALUE_PAIR **vps, int is_check);
