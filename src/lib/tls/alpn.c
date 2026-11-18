/*
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
 */

/**
 * $Id$
 *
 * @file lib/tls/alpn.c
 * @brief Set up Application Layer Protocol Negotiation (ALPN)
 *
 * ALPN allows TLS connections to signal what protocol they are carrying.  This lets applications use multiple
 * different protocols on the same UDP or TCP port.
 *
 * The client sends a list of ALPN strings that it accepts.  The server either chooses one and sends it back,
 * or else sends back nothing to indicate that none have been chosen.  Either end can allow no ALPN, or
 * require that some ALPN string was negotiated.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#ifdef WITH_TLS
#define LOG_PREFIX "tls"

#define _TLS_PRIVATE 1

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/pair.h>

#include <freeradius-devel/protocol/tls/freeradius.h>

#include "attrs.h"
#include "base.h"
#include "log.h"

/** Validate the ALPN list.
 *
 * The client has not necessarily been authenticated, so we don't trust the data that they sent.
 *
 * The list is in wire format:
 * - one octet length (1..255)
 * - 'length' octets data.
 *
 * Bounded by 'size'.  There is no terminator.
 *
 * @param[in] alpn	list to check.
 * @param[in] len	length of the list.
 * @return
 *	- true if the list is well formed.
 *	- false if the list is empty, holds an empty name, or does not end
 *	  where `len` says it ends.
 */
static bool tls_alpn_valid(unsigned char const *alpn, size_t len)
{
	size_t i = 0;

	if (len == 0) return false;

	while (i < len) {
		if (alpn[i] == 0) return false;

		i += alpn[i] + 1;
	}

	return i == len;
}

/** Return the identity of the TLS connection.
 *
 * Both the connection code and EAP store the identity in #FR_TLS_EX_INDEX_IDENTITY.
 *
 * @param[in] ssl	to get the name of.
 * @return
 *	- the name which the application gave the connection.
 *	- "(unknown)" if no name was stored, or the name is not set.
 */
static char const *tls_alpn_identity(SSL const *ssl)
{
	char const * const *identity = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_IDENTITY);

	if (!identity || !*identity) return "(unknown)";

	return *identity;
}

/** Find an ALPN table entry by name
 *
 * @param[in] conf	holding the ids.
 * @param[in] name	to find, with no length octet.
 * @param[in] len	length of `name`.
 * @return
 *	- the entry on the list with that name.
 *	- NULL if the list has no such entry, or the application set `alpn` itself.
 */
static fr_tls_alpn_t const *tls_alpn_entry_by_name(fr_tls_conf_t const *conf, unsigned char const *name, size_t len)
{
	size_t i;

	for (i = 0; i < conf->alpn_num; i++) {
		bool found = true;
		size_t j;
		fr_tls_alpn_t const *entry = &conf->alpn_table[conf->alpn_ids[i] - 1];

		/*
		 *	Check the name we got from OpenSSL against the configured list of names.
		 */
		for (j = 0; entry->name[j] != '\0'; j++) {
			if ((j >= len) ||
			    ((uint8_t) entry->name[j] != (uint8_t) name[j])) {
				found = false;
				break;
			}
		}

		if (found && (j == len)) return entry;
	}

	return NULL;
}

/** Find the default ALPN ID when the TLS session doesn't use ALPN.
 *
 * @param[in] conf	holding the ids.
 * @return
 *	- the entry which has #FR_TLS_ALPN_DEFAULT set.
 *	- NULL if no entry on the list has the flag.
 */
static fr_tls_alpn_t const *tls_alpn_default(fr_tls_conf_t const *conf)
{
	size_t i;

	for (i = 0; i < conf->alpn_num; i++) {
		fr_tls_alpn_t const *entry = &conf->alpn_table[conf->alpn_ids[i] - 1];

		if ((entry->flags & FR_TLS_ALPN_DEFAULT) != 0) return entry;
	}

	return NULL;
}

/** Convert internal ALPN structures to the format needed by TLS.
 *
 * The order of `ids` is the order of preference, highest first.  The function writes the fields `alpn`,
 * `sizeof_alpn` and `alpn_required`, and saves `table` and `ids`.  `alpn_required` is true when no entry has
 * #FR_TLS_ALPN_DEFAULT set, because then a peer which uses no ALPN has nothing to be assumed to speak.
 *
 * The entries of `table` must have the ids 1, 2, 3 and so on, in that order, so that the entry with a given
 * `id` is `table[id - 1]`.
 *
 * @param[in] ctx	for list allocation.  Must live as long as `conf`.
 * @param[in] conf	to update.
 * @param[in] table	the application's table.  Must outlive `conf`.
 * @param[in] ids	ids of the entries of `table` to offer, in the order of preference.
 * @param[in] num	number of ids.
 * @return
 *	- 0 on success.
 *	- -1 if the list is empty, or an id is not in the table, or an entry has an invalid name or id.
 */
int fr_tls_alpn_set(TALLOC_CTX *ctx, fr_tls_conf_t *conf, fr_tls_alpn_t const *table,
		    int const *ids, size_t num)
{
	size_t			i, table_len = 0, total = 0;
	unsigned char		*alpn, *p;
	int			*alpn_ids;
	bool			default_found = false;
	fr_tls_alpn_t const	*entry;

	if (num == 0) {
		ERROR("ALPN list cannot be empty");
		return -1;
	}

	/*
	 *	Find the length of the table, and sanity check the IDs.
	 */
	for (entry = table; entry->name; entry++) {
		if (entry->id != (int) (table_len + 1)) {
			ERROR("ALPN name \"%s\" has id %d, but the id of table entry %zu must be %zu",
			      entry->name, entry->id, table_len, table_len + 1);
			return -1;
		}
		table_len++;
	}

	/*
	 *	Walk over the list of IDs which have been taken from the configuration file.  Double-check
	 *	them, and figure out how much memory we need for the wire format of the ALPN string.
	 */
	for (i = 0; i < num; i++) {
		size_t len;

		if ((ids[i] < 1) || ((size_t) ids[i] > table_len)) {
			ERROR("ALPN id %d is not in the table", ids[i]);
			return -1;
		}

		entry = &table[ids[i] - 1];

		len = strlen(entry->name);
		if ((len == 0) || (len > UINT8_MAX)) {
			ERROR("ALPN name \"%s\" length must be between 1 and 255 octets", entry->name);
			return -1;
		}

		total += len + 1;
		if (entry->flags & FR_TLS_ALPN_DEFAULT) default_found = true;
	}

	MEM(alpn = talloc_array(ctx, unsigned char, total));
	MEM(alpn_ids = talloc_array(ctx, int, num));

	/*
	 *	Build the wire-format string from the list of the IDs, in the order that the IDs are given in.
	 */
	for (i = 0, p = alpn; i < num; i++) {
		size_t len;

		entry = &table[ids[i] - 1];

		len = strlen(entry->name);
		*p++ = (unsigned char) len;
		memcpy(p, entry->name, len);
		p += len;

		alpn_ids[i] = ids[i];
	}

	conf->alpn = alpn;
	conf->sizeof_alpn = total;
	conf->alpn_table = table;
	conf->alpn_ids = alpn_ids;
	conf->alpn_num = num;
	conf->alpn_required = !default_found;

	return 0;
}

/** Parse an `alpn` section into the ALPN list of a configuration
 *
 * The application puts this function on the `func` of an `alpn` subsection rule, and puts its table in the
 * `uctx` of the rule.  Each item in the section is the `conf_name` of a table entry, with the value `yes` or
 * `no`.  The order of the items is the order of preference, highest first.
 *
 * The rule sets CONF_FLAG_OK_MISSING, so a missing section never reaches the function, and ALPN stays unset as
 * RFC 9765 Section 3.3 Table 1 describes.  A section which is present but empty is an error, as is a section
 * which disables every entry.
 *
 * @param[in] ctx	unused.
 * @param[in] out	unused.
 * @param[in] parent	the #fr_tls_conf_t being parsed.
 * @param[in] ci	the `alpn` section.
 * @param[in] rule	holding the table in `uctx`.
 * @return
 *	- 0 on success.
 *	- -1 on an empty section, an unknown item, a duplicate item, a value which is not `yes` or `no`, or when no
 *	  entry is enabled.
 */
int fr_tls_alpn_parse(UNUSED TALLOC_CTX *ctx, UNUSED void *out, void *parent, CONF_ITEM *ci,
		      conf_parser_t const *rule)
{
	fr_tls_conf_t		*conf = talloc_get_type_abort(parent, fr_tls_conf_t);
	fr_tls_alpn_t const	*table = rule->uctx, *entry;
	CONF_SECTION		*cs = cf_item_to_section(ci);
	int			*list = NULL;
	bool			*seen = NULL;
	size_t			num = 0, table_len = 0;
	int			ret = -1;

	fr_assert(table != NULL);

	for (entry = table; entry->name; entry++) table_len++;

	MEM(list = talloc_zero_array(conf, int, table_len));
	MEM(seen = talloc_zero_array(conf, bool, table_len));

	cf_item_foreach(cs, item) {
		CONF_PAIR	*cp;
		char const	*value;
		size_t		i;

		if (!cf_item_is_pair(item)) {
			cf_log_err(item, "Unexpected subsection in 'alpn'");
			goto done;
		}

		cp = cf_item_to_pair(item);
		value = cf_pair_value(cp);

		for (i = 0; i < table_len; i++) {
			if (strcmp(table[i].conf_name, cf_pair_attr(cp)) == 0) break;
		}

		if (i == table_len) {
			cf_log_err(cp, "Unknown ALPN item '%s'", cf_pair_attr(cp));
			goto done;
		}

		if (seen[i]) {
			cf_log_err(cp, "Duplicate ALPN item '%s'", cf_pair_attr(cp));
			goto done;
		}
		seen[i] = true;

		if (value && ((strcasecmp(value, "no") == 0) || (strcasecmp(value, "false") == 0))) continue;

		if (!value || ((strcasecmp(value, "yes") != 0) && (strcasecmp(value, "true") != 0))) {
			cf_log_err(cp, "Invalid value for ALPN item '%s', expected 'yes' or 'no'", cf_pair_attr(cp));
			goto done;
		}

		list[num++] = table[i].id;
	}

	if (!cf_item_next(cs, NULL)) {
		cf_log_err(ci, "The 'alpn' section is empty");
		goto done;
	}

	if (num == 0) {
		cf_log_err(ci, "The 'alpn' section does not enable any protocol");
		goto done;
	}

	if (fr_tls_alpn_set(conf, conf, table, list, num) < 0) {
		cf_log_err(ci, "Failed setting the ALPN list");
		goto done;
	}

	ret = 0;

done:
	talloc_free(list);
	talloc_free(seen);
	return ret;
}

/** Check if we can use ALPN on this session.
 *
 * RFC 9765 Section 3.4 requires TLS 1.3.  OpenSSL has no DTLS 1.3, so DTLS 1.2 is allowed as well.
 *
 * @param[in] ssl	whose handshake has finished.
 * @return
 *	- true for TLS 1.3 and DTLS 1.2.
 *	- false for any earlier version.
 */
static bool tls_alpn_version_ok(SSL const *ssl)
{
	int version = SSL_version(ssl);

	if (version == TLS1_3_VERSION) return true;

	return SSL_is_dtls(ssl) && (version == DTLS1_2_VERSION);
}

/** Record the negotiated name in `session-state`
 *
 * The TLS library writes `session-state` into a ticket when it issues the ticket.  A server issues the ticket
 * during handshake negotiation, which is before fr_tls_session_alpn_check() runs.  The select callback
 * therefore records the name as soon as the name is chosen.  A resumed session may already hold the name from
 * the ticket, so this function replaces that value rather than adding a second pair.
 *
 * @param[in] request	holding `session-state`.
 * @param[in] name	to record, with no length octet.
 * @param[in] len	length of `name`.
 */
static void tls_alpn_session_state_set(request_t *request, unsigned char const *name, size_t len)
{
	fr_pair_t *vp;

	vp = fr_pair_find_by_da(&request->session_state_pairs, NULL, attr_tls_alpn);
	if (!vp) MEM(pair_append_session_state(&vp, attr_tls_alpn) >= 0);

	MEM(fr_pair_value_bstrndup(vp, (char const *) name, len, false) == 0);
}

/** Find the previous ALPN negotiation string, if it's set as part of the TLS session ticket.
 *
 * RFC 9765 Section 3.5 says a session which negotiated ALPN can be resumed only with the same ALPN.  The
 * previous ALPN string is stored in `session-state`, so we check that.
 *
 * @param[in] conf	holding the table.
 * @param[in] request	holding `session-state`.
 * @param[in] ssl	being negotiated.
 * @param[in] entry	the entry that this handshake chose, or NULL if the handshake chose none.
 * @return
 *	- the sticky entry, if the session was resumed and the handshake chose a different entry.
 *	- NULL if the handshake follows the rule.
 */
static fr_tls_alpn_t const *tls_alpn_sticky_conflict(fr_tls_conf_t const *conf, request_t *request, SSL *ssl,
						     fr_tls_alpn_t const *entry)
{
	fr_pair_t		*vp;
	fr_tls_alpn_t const	*old;

	if (!conf->alpn_table || !SSL_session_reused(ssl)) return NULL;

	vp = fr_pair_find_by_da(&request->session_state_pairs, NULL, attr_tls_alpn);
	if (!vp) return NULL;

	RDEBUG2("(TLS) ALPN - session-state.%pP from the resumed session", vp);

	old = tls_alpn_entry_by_name(conf, (unsigned char const *) vp->vp_strvalue, vp->vp_length);

	if (old && (old->flags & FR_TLS_ALPN_STICKY) && (old != entry)) return old;

	return NULL;
}

/** Select a matching ALPN string.
 *
 * OpenSSL calls this only when the client offered a list, so a client which does not use ALPN never reaches
 * here.  That case is caught after the handshake instead, by fr_tls_session_alpn_check().
 *
 * The servers preference is set by the list order.  SSL_select_next_proto() walks the list, and stops on the
 * first matching name offered by the client.
 *
 * @param[in] ssl	session being negotiated.
 * @param[out] out	the name chosen, pointing into one of the two lists.
 * @param[out] outlen	length of that name.
 * @param[in] in	the client's list.
 * @param[in] inlen	length of the client's list.
 * @param[in] arg	unused, the configuration comes from the SSL *.
 * @return
 *	- SSL_TLSEXT_ERR_OK if a name was chosen.
 *	- SSL_TLSEXT_ERR_ALERT_FATAL if the two lists have nothing in common.
 */
static int tls_session_alpn_select_cb(SSL *ssl, unsigned char const **out, unsigned char *outlen,
				      unsigned char const *in, unsigned int inlen, UNUSED void *arg)
{
	request_t		*request = fr_tls_session_request(ssl);
	fr_tls_conf_t const	*conf = fr_tls_session_conf(ssl);
	fr_tls_session_t	*tls_session = fr_tls_session(ssl);
	unsigned int		i;

	/*
	 *	OpenSSL runs this callback while it parses the ClientHello,
	 *	which happens inside a handshake round, and the library binds
	 *	the request across a round.
	 */
	fr_assert(request != NULL);

	/*
	 *	Check that the list wasn't mangled after the application set it.
	 */
	fr_assert(tls_alpn_valid(conf->alpn, conf->sizeof_alpn));

	if (tls_session->alpn_ignore) {
		RDEBUG2("(TLS) ALPN - not used with TLS 1.2 or earlier, choosing no name");
		return SSL_TLSEXT_ERR_NOACK;
	}

	if (RDEBUG_ENABLED2) {
		for (i = 0; i < inlen; i += in[i] + 1) {
			RDEBUG2("(TLS) ALPN - peer suggests \"%.*s\"", in[i], &in[i + 1]);
		}
	}

	/*
	 *	SSL_select_next_proto() writes through a non-const pointer,
	 *	while the callback is handed a const one.  The data it writes
	 *	is a pointer into one of the two lists, not the list itself,
	 *	so nothing const is written through.
	 */
	if (SSL_select_next_proto(UNCONST(unsigned char **, out), outlen,
				  conf->alpn, (unsigned int) conf->sizeof_alpn,
				  in, inlen) != OPENSSL_NPN_NEGOTIATED) {
		REDEBUG("(TLS) ALPN - no protocol in common with the peer (%s)", tls_alpn_identity(ssl));
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	RDEBUG2("(TLS) ALPN - chose \"%.*s\"", (int) *outlen, *out);

	/*
	 *	A resumed session which negotiated a sticky entry cannot choose another entry.
	 */
	if (conf->alpn_table) {
		fr_tls_alpn_t const *old = tls_alpn_sticky_conflict(conf, request, ssl,
								    tls_alpn_entry_by_name(conf, *out, *outlen));

		if (old) {
			REDEBUG("(TLS) ALPN - session was negotiated as \"%s\" and cannot resume as \"%.*s\" (%s)",
				old->name, (int) *outlen, *out, tls_alpn_identity(ssl));
			return SSL_TLSEXT_ERR_ALERT_FATAL;
		}
	}

	tls_alpn_session_state_set(request, *out, *outlen);

	return SSL_TLSEXT_ERR_OK;
}

/** Set ALPN (or not) for a connection.
 *
 * This is called for both client and server.  A client sends it's list, and verifies that the reply sent back
 * from the server matches one of the ALPN strings it sent.  A server reads the client list, and compares the
 * ALPN strings to the ones that it accepts.
 *
 * @param[in] ctx	to configure.
 * @param[in] conf	holding the protocol list.
 * @param[in] client	true for the client role.
 * @return
 *	- 0 on success, including the case where the application wants no ALPN.
 *	- -1 if the list is malformed, or OpenSSL refused it.
 */
int fr_tls_ctx_alpn_set(SSL_CTX *ctx, fr_tls_conf_t const *conf, bool client)
{
	/*
	 *	No ALPN string.  If ALPN is required, that's a code error.
	 */
	if (!conf->alpn) {
		if (conf->alpn_required) {
			ERROR("ALPN is required, but no protocols were set");
			return -1;
		}

		return 0;
	}

	if (!tls_alpn_valid(conf->alpn, conf->sizeof_alpn)) {
		ERROR("ALPN protocol list is malformed, or does not match sizeof_alpn (%zu)",
		      conf->sizeof_alpn);
		return -1;
	}

	if (client) {
		/*
		 *	Returns zero on success, which is the opposite of
		 *	most of the SSL_CTX_set_* calls around it.
		 */
		if (SSL_CTX_set_alpn_protos(ctx, conf->alpn, (unsigned int) conf->sizeof_alpn) != 0) {
			fr_tls_log_perror(NULL, "Failed setting the ALPN protocol list");
			return -1;
		}
	} else {
		SSL_CTX_set_alpn_select_cb(ctx, tls_session_alpn_select_cb, NULL);
	}

	return 0;
}

/** Get the ALPN string which was selected.
 *
 * @param[in] tls_session to check
 * @return
 *	- true if the two ends agreed on a protocol.
 *	- false if they did not, which includes the case where ALPN was not used.
 */
static bool tls_session_alpn(fr_tls_session_t *tls_session)
{
	unsigned char const	*data;
	unsigned int		len = 0;

	SSL_get0_alpn_selected(tls_session->ssl, &data, &len);
	if (!data || (len == 0)) {
		tls_session->alpn = NULL;
		tls_session->sizeof_alpn = 0;
		return false;
	}

	MEM(tls_session->alpn = talloc_memdup(tls_session, data, len));
	tls_session->sizeof_alpn = len;

	return true;
}

/** Does the wire list hold a name
 *
 * @param[in] conf	holding the list.
 * @param[in] name	to find, with no length octet.
 * @param[in] len	length of `name`.
 * @return
 *	- true if the list holds the name.
 *	- false otherwise.
 */
static bool tls_alpn_listed(fr_tls_conf_t const *conf, unsigned char const *name, size_t len)
{
	size_t i = 0;

	while (i < conf->sizeof_alpn) {
		if ((conf->alpn[i] == len) && (memcmp(&conf->alpn[i + 1], name, len) == 0)) return true;

		i += conf->alpn[i] + 1;
	}

	return false;
}

/** Check that we agreed on an ALPN string (or not).
 *
 * Runs once the handshake is done, for both roles.
 *
 * The client sends a list of proposed ALPN strings.  The server receives it, and checks that against its
 * local list.  If there's no overlap, the server sends a fatal alert.  The fatal alert is also sent when the
 * client sends no ALPN, and the server isn't configured with a `default` entry.
 *
 * Once the server has found a match, it sends back the chosen ALPN string to inform the client.
 *
 * With a table, a peer which agrees on no name is treated as the entry flagged `default`.
 *
 * @param[in] request		to log through.
 * @param[in] tls_session	to check.
 * @return
 *	- 0 if a protocol was agreed, or if none was needed.
 *	- -1 if one was needed and none was agreed.
 */
int fr_tls_session_alpn_check(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_conf_t const	*conf = tls_session->conf;
	fr_tls_alpn_t const	*entry = NULL;
	fr_pair_t		*vp;
	bool			negotiated;
	int			alert = SSL_AD_NO_APPLICATION_PROTOCOL;

	/*
	 *	The only caller is tls_session_async_handshake_done_round(),
	 *	which the interpreter runs with a request.
	 */
	fr_assert(request != NULL);

	/*
	 *	@todo - figure out why we get called twice.  For now, just suppress duplicate calls.
	 */
	if (tls_session->alpn_checked) return 0;
	tls_session->alpn_checked = true;

	if (!conf->alpn) return 0;

	/*
	 *	SSL_get0_alpn_selected() hands back the name on its own, with
	 *	no leading length octet, so the whole of what it gave us is
	 *	the name.
	 */
	negotiated = tls_session_alpn(tls_session);

	if (negotiated) {
		/*
		 *	RFC 9765 Section 3.3 B says a client MUST check that the server chose one of the names
		 *	which the client sent.  OpenSSL may check, and the check here does not depend on that.
		 */
		if (!tls_alpn_listed(conf, tls_session->alpn, tls_session->sizeof_alpn)) {
			REDEBUG("(TLS) ALPN - peer chose \"%.*s\", which is not on our list (%s)",
				(int) tls_session->sizeof_alpn, tls_session->alpn, tls_alpn_identity(tls_session->ssl));
			alert = SSL_AD_ILLEGAL_PARAMETER;
			goto fail;
		}

		if (conf->alpn_table) {
			if (!tls_alpn_version_ok(tls_session->ssl)) {
				REDEBUG("(TLS) ALPN - peer chose \"%.*s\" with TLS 1.2 or earlier (%s)",
					(int) tls_session->sizeof_alpn, tls_session->alpn,
					tls_alpn_identity(tls_session->ssl));
				alert = SSL_AD_ILLEGAL_PARAMETER;
				goto fail;
			}

			entry = tls_alpn_entry_by_name(conf, tls_session->alpn, tls_session->sizeof_alpn);
			fr_assert(entry != NULL);
		}
	} else if (conf->alpn_table) {
		entry = tls_alpn_default(conf);
	}

	if (conf->alpn_table) {
		/*
		 *	The select callback enforces the rule when the handshake chose a name.  A handshake which
		 *	chose no name never reached the select callback, so the check enforces the rule here.
		 */
		if (!negotiated) {
			fr_tls_alpn_t const *old = tls_alpn_sticky_conflict(conf, request, tls_session->ssl, entry);

			if (old) {
				REDEBUG("(TLS) ALPN - session was negotiated as \"%s\" and cannot resume as \"%s\" (%s)",
					old->name, entry ? entry->name : "no ALPN", tls_alpn_identity(tls_session->ssl));
				goto fail;
			}
		}

		if (entry) {
			tls_session->alpn_id = entry->id;
			RDEBUG2("(TLS) ALPN - table id %d", entry->id);
		}
	}

	if (negotiated) {
		RDEBUG2("(TLS) ALPN - agreed on \"%.*s\"",
			(int) tls_session->sizeof_alpn, tls_session->alpn);

		/*
		 *	A client has no select callback, and a list which the application set itself may have
		 *	reached no callback either, so record the name here too.
		 */
		tls_alpn_session_state_set(request, tls_session->alpn, tls_session->sizeof_alpn);

		vp = fr_pair_find_by_da(&request->session_state_pairs, NULL, attr_tls_alpn);
		RDEBUG2("(TLS) session-state.%pP", vp);

		return 0;
	}

	if (entry) {
		RDEBUG2("(TLS) ALPN - peer used no ALPN, assuming \"%s\"", entry->name);
		return 0;
	}

	if (!conf->alpn_required) {
		RDEBUG2("(TLS) ALPN - No protocols in common, not using ALPN");
		return 0;
	}

	REDEBUG("(TLS) ALPN - Failure, no protocols in common (%s)", tls_alpn_identity(tls_session->ssl));

fail:
	fr_tls_session_error_alert(request, tls_session, FR_ERROR_VALUE_ALPN_FAILED, alert);

	return -1;
}

/** Check ALPN while the server parses the ClientHello
 *
 * A server can send the alert while it processes the ClientHello, in order to close the connection early on
 * failure.  This function checks the ALPN strings from the configuration.  If the application manually sets a
 * list, that's checked after the handshake in fr_tls_session_alpn_check().
 *
 * We need to correlate ALPN with TLS version, but TLS hasn't finished negotiating the TLS version when
 * tls_session_alpn_select_cb() runs.
 *
 * @param[in] ssl	inside the ClientHello callback.
 * @param[in] request	to log through.
 * @param[out] alert	set when the function returns SSL_CLIENT_HELLO_ERROR.
 * @param[in] tls13	true if TLS 1.3 will be negotiated.  DTLS needs no test, because the function allows DTLS.
 * @return
 *	- SSL_CLIENT_HELLO_SUCCESS to continue the handshake.
 *	- SSL_CLIENT_HELLO_ERROR to send `alert`, because no ALPN will be negotiated and the list has no default entry.
 */
int fr_tls_session_alpn_client_hello(SSL *ssl, request_t *request, int *alert, bool tls13)
{
	fr_tls_conf_t const	*conf = fr_tls_session_conf(ssl);
	fr_tls_session_t	*tls_session = fr_tls_session(ssl);
	bool			usable;

	if (!conf->alpn_table) return SSL_CLIENT_HELLO_SUCCESS;

	usable = tls13 || SSL_is_dtls(ssl);
	tls_session->alpn_ignore = !usable;

	if (usable && (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation,
						NULL, NULL) == 1)) {
		return SSL_CLIENT_HELLO_SUCCESS;
	}

	if (!conf->alpn_required) return SSL_CLIENT_HELLO_SUCCESS;

	REDEBUG("(TLS) ALPN - Failure, %s and no default ALPN string was configured (%s)",
		usable ? "client offered no ALPN" : "TLS 1.2 or earlier will be negotiated",
		tls_alpn_identity(ssl));

	*alert = SSL_AD_NO_APPLICATION_PROTOCOL;

	return SSL_CLIENT_HELLO_ERROR;
}

/** Offer only a sticky protocol when a client resumes a session which negotiated it
 *
 * RFC 9765 Section 3.5 says a client that resumes a session which negotiated `radius/1.1` MUST advertise only
 * `radius/1.1`.  The negotiated name is stored on the `SSL_SESSION`, which OpenSSL exposes from release 3.3.  An
 * earlier release leaves the list unchanged, and the server enforces the rule.
 *
 * @param[in] request	to log through.
 * @param[in] ssl	about to resume `sess`.
 * @param[in] sess	the session being resumed.
 * @param[in] conf	holding the table.
 */
void fr_tls_alpn_client_resume(request_t *request, SSL *ssl, SSL_SESSION const *sess, fr_tls_conf_t const *conf)
{
#if OPENSSL_VERSION_NUMBER >= 0x30300000L
	unsigned char const	*name;
	size_t			len;
	fr_tls_alpn_t const	*entry;
	unsigned char		list[UINT8_MAX + 1];

	if (!conf->alpn_table) return;

	SSL_SESSION_get0_alpn_selected(sess, &name, &len);
	if (!name || (len == 0) || (len > UINT8_MAX)) return;

	entry = tls_alpn_entry_by_name(conf, name, len);
	if (!entry || !(entry->flags & FR_TLS_ALPN_STICKY)) return;

	list[0] = (unsigned char) len;
	memcpy(&list[1], name, len);

	if (SSL_set_alpn_protos(ssl, list, (unsigned int) (len + 1)) != 0) {
		RPERROR("(TLS) ALPN - Failed offering only \"%s\" for the resumed session", entry->name);
		return;
	}

	RDEBUG2("(TLS) ALPN - resuming a session which negotiated \"%s\", offering only that name", entry->name);
#else
	(void) ssl;
	(void) sess;

	if (!conf->alpn_table) return;

	RWDEBUG2("(TLS) ALPN - OpenSSL before 3.3 does not provide the ALPN string for resumed sessions, "
		"allowing all ALPNs");
#endif
}
#endif /* WITH_TLS */
