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
 * @file lib/ldap/referral.c
 * @brief Functions to handle ldap referrals
 *
 * @author Nick Porter <nick.porter@networkradius.com>
 * @copyright 2021 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#include <freeradius-devel/ldap/base.h>


/** Clear up a fr_ldap_referral_t
 *
 * If there is a parsed referral_url, that must be freed using libldap's ldap_free_urldesc
 */
static int _fr_ldap_referral_free(fr_ldap_referral_t *referral)
{
        if (referral->referral_url) ldap_free_urldesc(referral->referral_url);
        return 0;
}

/** Allocate a new structure to handle an LDAP referral, setting the destructor
 *
 * @param[in] ctx	to allocate the referral in
 * @return
 *	- a new referral structure on success
 *	- NULL on failure
 */
fr_ldap_referral_t *fr_ldap_referral_alloc(TALLOC_CTX *ctx)
{
	fr_ldap_referral_t	*referral;

	referral = talloc_zero(ctx, fr_ldap_referral_t);
	if (!referral) {
		PERROR("Failed to allocate LDAP referral container");
		return NULL;
	}
	talloc_set_destructor(referral, _fr_ldap_referral_free);

	return referral;
}

