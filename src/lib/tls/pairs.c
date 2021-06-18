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
 * @file tls/pairs.c
 * @brief Functions to convert certificate OIDs to attribute pairs
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls - "

#include <openssl/x509v3.h>
#include <openssl/ssl.h>

#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/server/request.h>

#include "attrs.h"
#include "base.h"
#include "session.h"

/*
 *	For creating certificate attributes.
 */
static fr_dict_attr_t const **cert_attr_names[][2] = {
	{ &attr_tls_client_cert_common_name,			&attr_tls_cert_common_name },
	{ &attr_tls_client_cert_expiration,			&attr_tls_cert_expiration },
	{ &attr_tls_client_cert_issuer,				&attr_tls_cert_issuer },
	{ &attr_tls_client_cert_serial,				&attr_tls_cert_serial },
	{ &attr_tls_client_cert_subject,			&attr_tls_cert_subject },
	{ &attr_tls_client_cert_subject_alt_name_dns,		&attr_tls_cert_subject_alt_name_dns },
	{ &attr_tls_client_cert_subject_alt_name_email,		&attr_tls_cert_subject_alt_name_email },
	{ &attr_tls_client_cert_subject_alt_name_upn,		&attr_tls_cert_subject_alt_name_upn }
};

#define IDX_COMMON_NAME			(0)
#define IDX_EXPIRATION			(1)
#define IDX_ISSUER			(2)
#define IDX_SERIAL			(3)
#define IDX_SUBJECT			(4)
#define IDX_SUBJECT_ALT_NAME_DNS	(5)
#define IDX_SUBJECT_ALT_NAME_EMAIL	(6)
#define IDX_SUBJECT_ALT_NAME_UPN	(7)

static inline CC_HINT(always_inline)
fr_pair_t *fr_tls_session_cert_attr_add(TALLOC_CTX *ctx, request_t *request, fr_pair_list_t *pair_list,
					int attr, int attr_index, char const *value)
{
	fr_pair_t *vp;
	fr_dict_attr_t const *da = *(cert_attr_names[attr][attr_index]);

	MEM(vp = fr_pair_afrom_da(ctx, da));
	if (value) {
		if (fr_pair_value_from_str(vp, value, -1, '\0', true) < 0) {
			RPWDEBUG("Failed creating attribute %s", da->name);
			talloc_free(vp);
			return NULL;
		}
	}
	RINDENT();
	RDEBUG3("%pP", vp);
	REXDENT();
	fr_pair_append(pair_list, vp);

	return vp;
}

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(used-but-marked-unused)	/* fix spurious warnings for sk macros */
/** Extract attributes from an X509 certificate
 *
 * @param[out] pair_list	to copy attributes to.
 * @param[in] ctx		to allocate attributes in.
 * @param[in] tls_session	current TLS session.
 * @param[in] cert		to validate.
 * @param[in] depth		the certificate is in the certificate chain (0 == leaf).
 * @return
 *	- 0 on success.
 *	- < 0 on failure.
 */
int fr_tls_session_pairs_from_x509_cert(fr_pair_list_t *pair_list, TALLOC_CTX *ctx,
					fr_tls_session_t *tls_session, X509 *cert, int depth)
{
	char		buffer[1024];
	char		attribute[256];
	char		**identity;
	int		attr_index, loc;

	STACK_OF(X509_EXTENSION) const *ext_list = NULL;
	ASN1_INTEGER	*sn = NULL;
	ASN1_TIME	*asn_time = NULL;

	fr_pair_t	*vp = NULL;

	request_t	*request;

#define CERT_ATTR_ADD(_attr, _attr_index, _value) fr_tls_session_cert_attr_add(ctx, request, pair_list, _attr, _attr_index, _value)

	attr_index = depth;
	if (attr_index > 1) attr_index = 1;

	request = fr_tls_session_request(tls_session->ssl);
	identity = (char **)SSL_get_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_IDENTITY);

	if (RDEBUG_ENABLED3) {
		buffer[0] = '\0';
		X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer));
		buffer[sizeof(buffer) - 1] = '\0';
		RDEBUG3("Creating attributes for \"%s\":", buffer[0] ? buffer : "Cert missing subject OID");
	}

	/*
	 *	Get the Serial Number
	 */
	sn = X509_get_serialNumber(cert);
	if (sn && ((size_t) sn->length < (sizeof(buffer) / 2))) {
		char *p = buffer;
		int i;

		for (i = 0; i < sn->length; i++) {
			sprintf(p, "%02x", (unsigned int)sn->data[i]);
			p += 2;
		}

		CERT_ATTR_ADD(IDX_SERIAL, attr_index, buffer);
	}

	/*
	 *	Get the Expiration Date
	 */
	buffer[0] = '\0';
	asn_time = X509_get_notAfter(cert);
	if (identity && asn_time && (asn_time->length < (int)sizeof(buffer))) {
		time_t expires;

		/*
		 *	Add expiration as a time since the epoch
		 */
		if (fr_tls_utils_asn1time_to_epoch(&expires, asn_time) < 0) {
			RPWDEBUG("Failed parsing certificate expiry time");
		} else {
			vp = CERT_ATTR_ADD(IDX_EXPIRATION, attr_index, NULL);
			vp->vp_date = fr_unix_time_from_sec(expires);
		}
	}

	/*
	 *	Get the Subject & Issuer
	 */
	buffer[0] = '\0';
	X509_NAME_oneline(X509_get_subject_name(cert), buffer, sizeof(buffer));
	buffer[sizeof(buffer) - 1] = '\0';
	if (identity && buffer[0]) {
		CERT_ATTR_ADD(IDX_SUBJECT, attr_index, buffer);

		/*
		 *	Get the Common Name, if there is a subject.
		 */
		X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
					  NID_commonName, buffer, sizeof(buffer));
		buffer[sizeof(buffer) - 1] = '\0';

		if (buffer[0]) {
			CERT_ATTR_ADD(IDX_COMMON_NAME, attr_index, buffer);
		}
	}

	X509_NAME_oneline(X509_get_issuer_name(cert), buffer, sizeof(buffer));
	buffer[sizeof(buffer) - 1] = '\0';
	if (identity && buffer[0]) {
		CERT_ATTR_ADD(IDX_ISSUER, attr_index, buffer);
	}

	/*
	 *	Get the RFC822 Subject Alternative Name
	 */
	loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, 0);
	if (loc >= 0) {
		X509_EXTENSION	*ext = NULL;
		GENERAL_NAMES	*names = NULL;
		int		i;

		ext = X509_get_ext(cert, loc);
		if (ext && (names = X509V3_EXT_d2i(ext))) {
			for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
				GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

				switch (name->type) {
#ifdef GEN_EMAIL
				case GEN_EMAIL: {
					char const *rfc822Name = (char const *)ASN1_STRING_get0_data(name->d.rfc822Name);
					CERT_ATTR_ADD(IDX_SUBJECT_ALT_NAME_EMAIL, attr_index, rfc822Name);
					break;
				}
#endif	/* GEN_EMAIL */
#ifdef GEN_DNS
				case GEN_DNS:
				{
					char const *dNSName = (char const *)ASN1_STRING_get0_data(name->d.dNSName);
					CERT_ATTR_ADD(IDX_SUBJECT_ALT_NAME_DNS, attr_index, dNSName);
					break;
				}
#endif	/* GEN_DNS */
#ifdef GEN_OTHERNAME
				case GEN_OTHERNAME:
					/* look for a MS UPN */
					if (NID_ms_upn != OBJ_obj2nid(name->d.otherName->type_id)) break;

					/* we've got a UPN - Must be ASN1-encoded UTF8 string */
					if (name->d.otherName->value->type == V_ASN1_UTF8STRING) {
						CERT_ATTR_ADD(IDX_SUBJECT_ALT_NAME_UPN, attr_index,
								  (char *)name->d.otherName->value->value.utf8string);
						break;
					}

					RWARN("Invalid UPN in Subject Alt Name (should be UTF-8)");
					break;
#endif	/* GEN_OTHERNAME */
				default:
					/* XXX TODO handle other SAN types */
					break;
				}
			}
		}
		if (names != NULL) GENERAL_NAMES_free(names);
	}

	/*
	 *	Only add extensions for the actual client certificate
	 */
	if (attr_index == 0) {
		ext_list = X509_get0_extensions(cert);

		/*
		 *	Grab the X509 extensions, and create attributes out of them.
		 *	For laziness, we re-use the OpenSSL names
		 */
		if (sk_X509_EXTENSION_num(ext_list) > 0) {
			int i, len;
			char *p;
			BIO *out;

			MEM(out = BIO_new(BIO_s_mem()));
			strlcpy(attribute, "TLS-Client-Cert-", sizeof(attribute));

			for (i = 0; i < sk_X509_EXTENSION_num(ext_list); i++) {
				char			value[1024];
				ASN1_OBJECT		*obj;
				X509_EXTENSION		*ext;
				fr_dict_attr_t const	*da;

				ext = sk_X509_EXTENSION_value(ext_list, i);

				obj = X509_EXTENSION_get_object(ext);
				if (i2a_ASN1_OBJECT(out, obj) <= 0) {
					RPWDEBUG("Skipping X509 Extension (%i) conversion to attribute. "
						 "Conversion from ASN1 failed...", i);
					continue;
				}

				len = BIO_read(out, attribute + 16 , sizeof(attribute) - 16 - 1);
				if (len <= 0) continue;

				attribute[16 + len] = '\0';

				for (p = attribute + 16; *p != '\0'; p++) if (*p == ' ') *p = '-';

				X509V3_EXT_print(out, ext, 0, 0);
				len = BIO_read(out, value , sizeof(value) - 1);
				if (len <= 0) continue;

				value[len] = '\0';

				da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), attribute);
				if (!da) {
					RWDEBUG3("Skipping attribute %s: "
						 "Add dictionary definition if you want to access it", attribute);
					continue;
				}

				MEM(vp = fr_pair_afrom_da(ctx, da));
				if (fr_pair_value_from_str(vp, value, -1, '\0', true) < 0) {
					RPWDEBUG3("Skipping: %s += '%s'", attribute, value);
					talloc_free(vp);
					continue;
				}

				fr_pair_append(pair_list, vp);
			}
			BIO_free_all(out);
		}
	}

	return 0;
}
DIAG_ON(used-but-marked-unused)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)
#endif
