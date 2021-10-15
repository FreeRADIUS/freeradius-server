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
fr_ldap_referral_t *fr_ldap_referral_alloc(TALLOC_CTX *ctx, request_t *request)
{
	fr_ldap_referral_t	*referral;

	referral = talloc_zero(ctx, fr_ldap_referral_t);
	if (!referral) {
		PERROR("Failed to allocate LDAP referral container");
		return NULL;
	}
	referral->request = request;
	talloc_set_destructor(referral, _fr_ldap_referral_free);

	return referral;
}

/** Callback to send LDAP referral queries when a trunk becomes active
 *
 */
static void _ldap_referral_send(UNUSED fr_trunk_t *trunk, UNUSED fr_trunk_state_t prev,
			        UNUSED fr_trunk_state_t state, void *uctx)
{
	fr_ldap_referral_t	*referral = talloc_get_type_abort(uctx, fr_ldap_referral_t);
	fr_ldap_query_t		*query = referral->query;

	/*
	 *	If referral is set, then another LDAP trunk has gone active first and sent the referral
	 */
	if (query->referral) return;

	/*
	 *	Enqueue referral query on active trunk connection
	 */
	query->referral = referral;
	query->treq = fr_trunk_request_alloc(referral->ttrunk->trunk, referral->request);
	fr_trunk_request_enqueue(&query->treq, referral->ttrunk->trunk, NULL, query, NULL);

	DEBUG3("Pending LDAP referral query queued on active trunk");
}


/** Follow an LDAP referral
 *
 * The returned list of LDAP referrals should already be in query->referrals.
 * We check all the possible referrals and look for one where there already
 * is an active trunk connection.
 *
 * @param query	whose result was one or more referral URLs
 * @return
 * 	- 0 on success.
 * 	- < 0 on failure.
 */
int fr_ldap_referral_follow(fr_ldap_thread_t *t, request_t *request, fr_ldap_query_t *query)
{
	fr_ldap_config_t	*config = t->config;
	fr_ldap_thread_trunk_t	*ttrunk = NULL;
	int			referral_no = -1;
	fr_ldap_referral_t	*referral;

	/*
	 *	In following a referral, firstly remove the query from the
	 *	tree of pending queries clear the message id.
	 */
	fr_rb_remove(query->ldap_conn->queries, query);
	query->msgid = 0;
	fr_trunk_request_signal_complete(query->treq);
	query->treq = NULL;

	if (query->referral_depth > 1) {
	/*
	 *	If we've already parsed a referral, clear the existing list of followers.
	 */
		fr_dlist_talloc_free(&query->referrals);
		query->referral = NULL;
	} else {
	/*
	 *	Otherwise initialise the list header for followers.
	 */
		fr_dlist_talloc_init(&query->referrals, fr_ldap_referral_t, entry);
	}

	while (query->referral_urls[++referral_no]) {
		if (!ldap_is_ldap_url(query->referral_urls[referral_no])) {
			ROPTIONAL(RERROR, ERROR, "Referral %s does not look like an LDAP URL",
				  query->referral_urls[referral_no]);
			continue;
		}

		referral = fr_ldap_referral_alloc(query, request);
		if (!referral) continue;

		referral->query = query;

		if (ldap_url_parse(query->referral_urls[referral_no], &referral->referral_url)) {
			ROPTIONAL(RERROR, ERROR,
				  "Failed parsing referral LDAP URL %s", query->referral_urls[referral_no]);
		free_referral:
			talloc_free(referral);
			continue;
		}

		referral->host_uri = talloc_asprintf(referral, "%s://%s:%d", referral->referral_url->lud_scheme,
						     referral->referral_url->lud_host, referral->referral_url->lud_port);

		if (config->use_referral_credentials) {
			char	**ext;

			/*
			 *	If there are no extensions, OpenLDAP doesn't
			 *	bother allocating an array.
			 */
			for (ext = referral->referral_url->lud_exts; ext && *ext; ext++) {
				char const *p;
				bool critical = false;

				p = *ext;

				if (*p == '!') {
					critical = true;
					p++;
				}

				/*
				 *	LDAP Parse URL unescapes the extensions for us
				 */
				switch (fr_table_value_by_substr(fr_ldap_supported_extensions, p, -1, LDAP_EXT_UNSUPPORTED)) {
				case LDAP_EXT_BINDNAME:
					p = strchr(p, '=');
					if (!p) {
					bad_ext:
						ROPTIONAL(RERROR, ERROR,
							  "Failed parsing extension \"%s\": "
							  "No attribute/value delimiter '='", *ext);
						goto free_referral;
					}
					referral->identity = p + 1;
					break;

				case LDAP_EXT_BINDPW:
					p = strchr(p, '=');
					if (!p) goto bad_ext;
					referral->password = p + 1;
					break;

				default:
					if (critical) {
						ROPTIONAL(RERROR, ERROR,
							  "Failed parsing critical extension \"%s\": "
							  "Not supported by FreeRADIUS", *ext);
						goto free_referral;
					}
					ROPTIONAL(RDEBUG2, DEBUG2, "Skipping unsupported extension \"%s\"", *ext);
					continue;
				}
			}
		} else {
			if (config->rebind) {
				referral->identity = config->admin_identity;
				referral->password = config->admin_password;
			}
		}

		fr_dlist_insert_tail(&query->referrals, referral);
		if (fr_thread_ldap_trunk_state(t, referral->host_uri,
					       referral->identity) != FR_TRUNK_STATE_ACTIVE) {
			ROPTIONAL(RDEBUG3, DEBUG3,
				  "No active LDAP trunk for URI %s, bind DN %s",
				  referral->host_uri, referral->identity);
			continue;
		}

		ttrunk = fr_thread_ldap_trunk_get(t, referral->host_uri, referral->identity,
						  referral->password, request, config);

		if (!ttrunk) {
			ROPTIONAL(RERROR, ERROR, "Unable to connect to LDAP referral URL");
			fr_dlist_talloc_free_item(&query->referrals, referral);
			continue;
		}

		/*
		 *	We have an active trunk enqueue the request
		 */
		query->referral = referral;
		query->treq = fr_trunk_request_alloc(ttrunk->trunk, request);
		fr_trunk_request_enqueue(&query->treq, ttrunk->trunk, request, query, NULL);
		return 0;
	}

	/*
	 *	None of the referrals parsed successfully
	 */
	if (fr_dlist_num_elements(&query->referrals) == 0) {
		ROPTIONAL(RERROR, ERROR, "No valid LDAP referrals to follow");
		return -1;
	}

	/*
	 *	We have parsed referrals, but none of them matched an existing active connection.
	 *	Launch new trunks with callbacks so the first to become active will run the query.
	 */
	referral = NULL;
	while ((referral = fr_dlist_next(&query->referrals, referral))) {
		ttrunk = fr_thread_ldap_trunk_get(t, referral->host_uri, referral->identity,
						  referral->password, request, config);
		if (!ttrunk) {
			fr_dlist_talloc_free_item(&query->referrals, referral);
			continue;
		}
		referral->ttrunk = ttrunk;
		fr_trunk_add_watch(ttrunk->trunk, FR_TRUNK_STATE_ACTIVE, _ldap_referral_send, true, referral);
		ROPTIONAL(RDEBUG4, DEBUG4, "Watch inserted to send referral query on active trunk");
	}

	return 0;
}

/** Follow an alternative LDAP referral
 *
 * If an initial chase of an LDAP referral results in an error being returned
 * this function can be used to attempt one of the other referral URLs given
 * in the initial query results.
 *
 * The initial use of fr_ldap_referral_follow may have launched trunks for
 * any referral URLs which parsed successfully, so this starts by looking
 * for the first which has an active state and sends the query that way.
 *
 * If no active trunks match the remaining servers listed in referrals then
 * new trunks are launched with watchers to send the query on the first
 * active trunk.
 *
 * @param query whose referrals are being chased
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
int fr_ldap_referral_next(fr_ldap_thread_t *t, request_t *request, fr_ldap_query_t *query)
{
	fr_ldap_config_t	*config = t->config;
	fr_ldap_referral_t	*referral = NULL;
	fr_ldap_thread_trunk_t	*ttrunk;

	while ((referral = fr_dlist_next(&query->referrals, referral))) {
		if (fr_thread_ldap_trunk_state(t, referral->host_uri,
					       referral->identity) != FR_TRUNK_STATE_ACTIVE) {
			ROPTIONAL(RDEBUG3, DEBUG3, "No active LDAP trunk for URI %s, bind DN %s",
				  referral->host_uri, referral->identity);
			continue;
		}

		ttrunk = fr_thread_ldap_trunk_get(t, referral->host_uri, referral->identity,
						  referral->password, request, config);

		if (!ttrunk) {
			ROPTIONAL(RERROR, ERROR, "Unable to connect to LDAP referral URL");
			fr_dlist_talloc_free_item(&query->referrals, referral);
		        continue;
		}

		/*
		 *	We have an active trunk enqueue the request
		 */
		query->referral = referral;
		query->treq = fr_trunk_request_alloc(ttrunk->trunk, request);
		fr_trunk_request_enqueue(&query->treq, ttrunk->trunk, request, query, NULL);
		return 0;
	}

	/*
	 *	None of the referrals parsed successfully
	 */
	if (fr_dlist_num_elements(&query->referrals) == 0) {
		ROPTIONAL(RERROR, ERROR, "No valid LDAP referrals to follow");
		return -1;
	}

	/*
	 *	None of the remaining referrals have an active trunk.
	 *	Launch new trunks with callbacks so the first to become active will run the query.
	 */
	referral = NULL;
	while ((referral = fr_dlist_next(&query->referrals, referral))) {
		ttrunk = fr_thread_ldap_trunk_get(t, referral->host_uri, referral->identity,
						  referral->password, request, config);
		if (!ttrunk) {
			fr_dlist_talloc_free_item(&query->referrals, referral);
			continue;
		}
		referral->ttrunk = ttrunk;
		fr_trunk_add_watch(ttrunk->trunk, FR_TRUNK_STATE_ACTIVE, _ldap_referral_send, true, referral);
		ROPTIONAL(RDEBUG4, DEBUG4, "Watch inserted to send referral query on active trunk");
	}

	return 0;
}
