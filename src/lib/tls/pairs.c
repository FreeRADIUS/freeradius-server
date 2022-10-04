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
#define LOG_PREFIX "tls"

#include <freeradius-devel/tls/openssl_user_macros.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/pair.h>

#include "attrs.h"
#include "base.h"
#include "bio.h"
#include "log.h"
#include "session.h"
#include "utils.h"

#include <openssl/x509v3.h>
#include <openssl/ssl.h>

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(used-but-marked-unused)	/* fix spurious warnings for sk macros */
/** Extract attributes from an X509 certificate
 *
 * @param[out] pair_list	to copy attributes to.
 * @param[in] ctx		to allocate attributes in.
 * @param[in] request		the current request.
 * @param[in] cert		to validate.
 * @return
 *	- 1 already exists.
 *	- 0 on success.
 *	- < 0 on failure.
 */
int fr_tls_session_pairs_from_x509_cert(fr_pair_list_t *pair_list, TALLOC_CTX *ctx, request_t *request, X509 *cert)
{
	int		loc;
	char		buff[1024];

	ASN1_TIME const *asn_time;
	time_t		time;

	STACK_OF(X509_EXTENSION) const *ext_list = NULL;

	fr_pair_t	*vp = NULL;
	ssize_t		slen;

	/*
	 *	Subject
	 */
	MEM(fr_pair_append_by_da(ctx, &vp, pair_list, attr_tls_certificate_subject) == 0);
	if (unlikely(X509_NAME_print_ex(fr_tls_bio_dbuff_thread_local(vp, 256, 0),
					X509_get_subject_name(cert), 0, XN_FLAG_ONELINE) < 0)) {
		fr_tls_bio_dbuff_thread_local_clear();
		fr_tls_log(request, "Failed retrieving certificate subject");
	error:
		fr_pair_list_free(pair_list);
		return -1;
	}
	fr_pair_value_bstrdup_buffer_shallow(vp, fr_tls_bio_dbuff_thread_local_finalise_bstr(), true);

	RDEBUG3("Creating attributes for \"%pV\":", fr_box_strvalue_buffer(vp->vp_strvalue));

	/*
	 *	Common name
	 */
	slen = X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
					 NID_commonName, NULL, 0);
	if (slen > 0) {
		char *cn;

		MEM(fr_pair_append_by_da(ctx, &vp, pair_list, attr_tls_certificate_common_name) == 0);
		MEM(fr_pair_value_bstr_alloc(vp, &cn, (size_t)slen, true) == 0); /* Allocs \0 byte in addition to len */

		slen = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, (size_t)slen + 1);
		if (slen < 0) {
			fr_tls_log(request, "Failed retrieving certificate common name");
			goto error;
		}
	}

	/*
	 *	Signature
	 */
	{
		ASN1_BIT_STRING const *sig;
		X509_ALGOR const *alg;

		X509_get0_signature(&sig, &alg, cert);

		MEM(fr_pair_append_by_da(ctx, &vp, pair_list, attr_tls_certificate_signature) == 0);
		MEM(fr_pair_value_memdup(vp,
					 (uint8_t const *)ASN1_STRING_get0_data(sig),
					 ASN1_STRING_length(sig), true) == 0);

		OBJ_obj2txt(buff, sizeof(buff), alg->algorithm, 0);
		MEM(fr_pair_append_by_da(ctx, &vp, pair_list, attr_tls_certificate_signature_algorithm) == 0);
		fr_pair_value_strdup(vp, buff, false);
	}

	/*
	 *	Issuer
	 */
	MEM(fr_pair_append_by_da(ctx, &vp, pair_list, attr_tls_certificate_issuer) == 0);
	if (unlikely(X509_NAME_print_ex(fr_tls_bio_dbuff_thread_local(vp, 256, 0),
					X509_get_issuer_name(cert), 0, XN_FLAG_ONELINE) < 0)) {
		fr_tls_bio_dbuff_thread_local_clear();
		fr_tls_log(request, "Failed retrieving certificate issuer");
		goto error;
	}
	fr_pair_value_bstrdup_buffer_shallow(vp, fr_tls_bio_dbuff_thread_local_finalise_bstr(), true);

	/*
	 *	Serial number
	 */
	{
		ASN1_INTEGER const *serial = NULL;

		serial = X509_get0_serialNumber(cert);
		if (!serial) {
			fr_tls_log(request, "Failed retrieving certificate serial");
			goto error;
		}

		MEM(fr_pair_append_by_da(ctx, &vp, pair_list, attr_tls_certificate_serial) == 0);
		MEM(fr_pair_value_memdup(vp, serial->data, serial->length, true) == 0);
	}

	/*
	 *	Not valid before
	 */
	asn_time = X509_get0_notBefore(cert);

	if (fr_tls_utils_asn1time_to_epoch(&time, asn_time) < 0) {
		RPWDEBUG("Failed parsing certificate not-before");
		goto error;
	}

	MEM(fr_pair_append_by_da(ctx, &vp, pair_list, attr_tls_certificate_not_before) == 0);
	vp->vp_date = fr_unix_time_from_time(time);

	/*
	 *	Not valid after
	 */
	asn_time = X509_get0_notAfter(cert);

	if (fr_tls_utils_asn1time_to_epoch(&time, asn_time) < 0) {
		RPWDEBUG("Failed parsing certificate not-after");
		goto error;
	}

	MEM(fr_pair_append_by_da(ctx, &vp, pair_list, attr_tls_certificate_not_after) == 0);
	vp->vp_date = fr_unix_time_from_time(time);

	/*
	 *	Get the RFC822 Subject Alternative Name
	 */
	loc = X509_get_ext_by_NID(cert, NID_subject_alt_name, 0);
	if (loc >= 0) {
		X509_EXTENSION	*ext = NULL;
		GENERAL_NAMES	*names = NULL;
		int		i;

		ext = X509_get_ext(cert, loc);
		if (!ext || !(names = X509V3_EXT_d2i(ext))) goto skip_alt;


		for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
			GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

			switch (name->type) {
#ifdef GEN_EMAI
			case GEN_EMAIL:
				MEM(fr_pair_append_by_da(ctx, &vp, pair_list,
							 attr_tls_certificate_subject_alt_name_email) == 0);
				MEM(fr_pair_value_bstrndup(vp,
							   (char const *)ASN1_STRING_get0_data(name->d.rfc822Name),
							   ASN1_STRING_length(name->d.rfc822Name), true) == 0);
				break;
#endif	/* GEN_EMAIL */
#ifdef GEN_DNS
			case GEN_DNS:
				MEM(fr_pair_append_by_da(ctx, &vp, pair_list,
							 attr_tls_certificate_subject_alt_name_dns) == 0);
				MEM(fr_pair_value_bstrndup(vp,
							   (char const *)ASN1_STRING_get0_data(name->d.dNSName),
							   ASN1_STRING_length(name->d.dNSName), true) == 0);
				break;
#endif	/* GEN_DNS */
#ifdef GEN_OTHERNAME
			case GEN_OTHERNAME:
				/* look for a MS UPN */
				if (NID_ms_upn != OBJ_obj2nid(name->d.otherName->type_id)) break;

				/* we've got a UPN - Must be ASN1-encoded UTF8 string */
				if (name->d.otherName->value->type == V_ASN1_UTF8STRING) {
					MEM(fr_pair_append_by_da(ctx, &vp, pair_list,
								 attr_tls_certificate_subject_alt_name_upn) == 0);
					MEM(fr_pair_value_bstrndup(vp,
								   (char const *)ASN1_STRING_get0_data(name->d.otherName->value->value.utf8string),
								   ASN1_STRING_length(name->d.otherName->value->value.utf8string),
								   true) == 0);
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
		if (names != NULL) GENERAL_NAMES_free(names);
	}

skip_alt:
	/*
	 *	Only add extensions for the actual client certificate
	 */
	ext_list = X509_get0_extensions(cert);
	if (unlikely(!ext_list)) {
		RWDEBUG("Failed retrieving extensions");
		goto done;
	}

	/*
	 *	Grab the X509 extensions, and create attributes out of them.
	 *	For laziness, we re-use the OpenSSL names
	 */
	if (sk_X509_EXTENSION_num(ext_list) > 0) {
		int			i;
		BIO			*bio;
		fr_tls_bio_dbuff_t	*bd;
		fr_dbuff_t		*in, *out;

		bio = fr_tls_bio_dbuff_alloc(&bd, NULL, NULL, 257, 4097, true);
		in = fr_tls_bio_dbuff_in(bd);
		out = fr_tls_bio_dbuff_out(bd);

		for (i = 0; i < sk_X509_EXTENSION_num(ext_list); i++) {
			ASN1_OBJECT		*obj;
			X509_EXTENSION		*ext;
			fr_dict_attr_t const	*da;
			char			*p;

			ext = sk_X509_EXTENSION_value(ext_list, i);

			obj = X509_EXTENSION_get_object(ext);
			if (i2a_ASN1_OBJECT(bio, obj) <= 0) {
				RPWDEBUG("Skipping X509 Extension (%i) conversion to attribute. "
					 "Conversion from ASN1 failed...", i);
			again:
				fr_tls_bio_dbuff_reset(bd);
				continue;
			}

			if (fr_dbuff_remaining(out) == 0) goto again;	/* Nothing written ? */

			/*
			 *	All disallowed chars get mashed to '-'
			 */
			for (p = (char *)fr_dbuff_current(out);
			     p < (char *)fr_dbuff_end(out);
			     p++) if (!fr_dict_attr_allowed_chars[(uint8_t)*p]) *p = '-';

			/*
			 *	Terminate the buffer (after char replacement,
			 *	so we do don't replace the \0)
			 */
			if (unlikely(fr_dbuff_in_bytes(in, (uint8_t)'\0') <= 0)) {
				RWDEBUG("Attribute name too long");
				goto again;
			}

			da = fr_dict_attr_by_name(NULL, attr_tls_certificate, (char *)fr_dbuff_current(out));

			fr_dbuff_set(in, fr_dbuff_current(in) - 1);	/* Ensure the \0 isn't counted in remaining */

			if (!da) {
				RWDEBUG3("Skipping attribute \"%pV\": "
					 "Add a dictionary definition if you want to access it",
					 fr_box_strvalue_len((char *)fr_dbuff_current(out),
					  		     fr_dbuff_remaining(out)));
				fr_strerror_clear();	/* Don't leave spurious errors from failed resolution */
				goto again;
			}

			fr_tls_bio_dbuff_reset(bd);	/* 'free' any data used */

			X509V3_EXT_print(bio, ext, 0, 0);

			MEM(vp = fr_pair_afrom_da(ctx, da));
			if (fr_pair_value_from_str(vp, (char *)fr_dbuff_current(out), fr_dbuff_remaining(out),
						   NULL, true) < 0) {
				RPWDEBUG3("Skipping: %s += \"%pV\"",
					  da->name, fr_box_strvalue_len((char *)fr_dbuff_current(out),
					  				fr_dbuff_remaining(out)));
				talloc_free(vp);
				goto again;
			}
			fr_tls_bio_dbuff_reset(bd);	/* 'free' any data used */

			fr_pair_append(pair_list, vp);
		}
		talloc_free(bd);
	}

done:
	return 0;
}
DIAG_ON(used-but-marked-unused)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)
#endif
