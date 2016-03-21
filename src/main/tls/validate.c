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
 * @file tls/validate.c
 * @brief Expose certificate OIDs as attributes, and call validation virtual
 *	server to check cert is valid.
 *
 * @copyright 2001 hereUare Communications, Inc. <raghud@hereuare.com>
 * @copyright 2003  Alan DeKok <aland@freeradius.org>
 * @copyright 2006-2016 The FreeRADIUS server project
 */
#ifdef WITH_TLS
#define LOG_PREFIX "tls - "

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <openssl/x509v3.h>

/*
 *	For creating certificate attributes.
 */
static char const *cert_attr_names[8][2] = {
	{ "TLS-Client-Cert-Serial",			"TLS-Cert-Serial" },
	{ "TLS-Client-Cert-Expiration",			"TLS-Cert-Expiration" },
	{ "TLS-Client-Cert-Subject",			"TLS-Cert-Subject" },
	{ "TLS-Client-Cert-Issuer",			"TLS-Cert-Issuer" },
	{ "TLS-Client-Cert-Common-Name",		"TLS-Cert-Common-Name" },
	{ "TLS-Client-Cert-Subject-Alt-Name-Email",	"TLS-Cert-Subject-Alt-Name-Email" },
	{ "TLS-Client-Cert-Subject-Alt-Name-Dns",	"TLS-Cert-Subject-Alt-Name-Dns" },
	{ "TLS-Client-Cert-Subject-Alt-Name-Upn",	"TLS-Cert-Subject-Alt-Name-Upn" }
};

#define FR_TLS_SERIAL		(0)
#define FR_TLS_EXPIRATION	(1)
#define FR_TLS_SUBJECT		(2)
#define FR_TLS_ISSUER		(3)
#define FR_TLS_CN		(4)
#define FR_TLS_SAN_EMAIL       	(5)
#define FR_TLS_SAN_DNS          (6)
#define FR_TLS_SAN_UPN          (7)

/*
 *	Before trusting a certificate, you must make sure that the
 *	certificate is 'valid'. There are several steps that your
 *	application can take in determining if a certificate is
 *	valid. Commonly used steps are:
 *
 *	1.Verifying the certificate's signature, and verifying that
 *	the certificate has been issued by a trusted Certificate
 *	Authority.
 *
 *	2.Verifying that the certificate is valid for the present date
 *	(i.e. it is being presented within its validity dates).
 *
 *	3.Verifying that the certificate has not been revoked by its
 *	issuing Certificate Authority, by checking with respect to a
 *	Certificate Revocation List (CRL).
 *
 *	4.Verifying that the credentials presented by the certificate
 *	fulfill additional requirements specific to the application,
 *	such as with respect to access control lists or with respect
 *	to OCSP (Online Certificate Status Processing).
 *
 *	NOTE: This callback will be called multiple times based on the
 *	depth of the root certificate chain
 */
int tls_validate_cert_cb(int ok, X509_STORE_CTX *ctx)
{
	char		subject[1024]; /* Used for the subject name */
	char		issuer[1024]; /* Used for the issuer name */
	char		attribute[1024];
	char		value[1024];
	char		common_name[1024];
	char		cn_str[1024];
	char		buf[64];
	X509		*client_cert;
	X509_CINF	*client_inf;
	STACK_OF(X509_EXTENSION) *ext_list;
	SSL		*ssl;
	int		err, depth, lookup, loc;
	fr_tls_conf_t *conf;
	int		my_ok = ok;

	ASN1_INTEGER	*sn = NULL;
	ASN1_TIME	*asn_time = NULL;
	VALUE_PAIR	*cert_vps = NULL;
	vp_cursor_t	cursor;

	char **identity;
#ifdef HAVE_OPENSSL_OCSP_H
	X509_STORE	*ocsp_store = NULL;
	X509		*issuer_cert;
#endif
	VALUE_PAIR	*vp;

	REQUEST		*request;

#define ADD_CERT_ATTR(_name, _value) \
do { \
	VALUE_PAIR *_vp; \
	_vp = fr_pair_make(request, NULL, _name, _value, T_OP_SET); \
	if (_vp) { \
		fr_cursor_append(&cursor, _vp); \
	} else { \
		RWDEBUG("Failed creating attribute %s: %s", _name, fr_strerror()); \
	} \
} while (0)

	client_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	lookup = depth;

	/*
	 *	Log client/issuing cert.  If there's an error, log
	 *	issuing cert.
	 */
	if ((lookup > 1) && !my_ok) lookup = 1;

	/*
	 *	Retrieve the pointer to the SSL of the connection currently treated
	 *	and the application specific data stored into the SSL object.
	 */
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	conf = (fr_tls_conf_t *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF);
	if (!conf) return 1;

	request = (REQUEST *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	rad_assert(request != NULL);

	fr_cursor_init(&cursor, &cert_vps);

	identity = (char **)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_IDENTITY);
#ifdef HAVE_OPENSSL_OCSP_H
	ocsp_store = (X509_STORE *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_STORE);
#endif

	/*
	 *	Get the Serial Number
	 */
	buf[0] = '\0';
	sn = X509_get_serialNumber(client_cert);

	RDEBUG2("Creating attributes from certificate OIDs");

	/*
	 *	For this next bit, we create the attributes *only* if
	 *	we're at the client or issuing certificate, AND we
	 *	have a user identity.  i.e. we don't create the
	 *	attributes for RadSec connections.
	 */
	if (identity && (lookup <= 1) && sn && ((size_t) sn->length < (sizeof(buf) / 2))) {
		char *p = buf;
		int i;

		for (i = 0; i < sn->length; i++) {
			sprintf(p, "%02x", (unsigned int)sn->data[i]);
			p += 2;
		}
		ADD_CERT_ATTR(cert_attr_names[FR_TLS_SERIAL][lookup], buf);
	}

	/*
	 *	Get the Expiration Date
	 */
	buf[0] = '\0';
	asn_time = X509_get_notAfter(client_cert);
	if (identity && (lookup <= 1) && asn_time && (asn_time->length < (int) sizeof(buf))) {
		memcpy(buf, (char*) asn_time->data, asn_time->length);
		buf[asn_time->length] = '\0';
		ADD_CERT_ATTR(cert_attr_names[FR_TLS_EXPIRATION][lookup], buf);
	}

	/*
	 *	Get the Subject & Issuer
	 */
	subject[0] = issuer[0] = '\0';
	X509_NAME_oneline(X509_get_subject_name(client_cert), subject,
			  sizeof(subject));
	subject[sizeof(subject) - 1] = '\0';
	if (identity && (lookup <= 1) && subject[0]) {
		ADD_CERT_ATTR(cert_attr_names[FR_TLS_SUBJECT][lookup], subject);
	}

	X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), issuer,
			  sizeof(issuer));
	issuer[sizeof(issuer) - 1] = '\0';
	if (identity && (lookup <= 1) && issuer[0]) {
		ADD_CERT_ATTR(cert_attr_names[FR_TLS_ISSUER][lookup], issuer);
	}

	/*
	 *	Get the Common Name, if there is a subject.
	 */
	X509_NAME_get_text_by_NID(X509_get_subject_name(client_cert),
				  NID_commonName, common_name, sizeof(common_name));
	common_name[sizeof(common_name) - 1] = '\0';
	if (identity && (lookup <= 1) && common_name[0] && subject[0]) {
		ADD_CERT_ATTR(cert_attr_names[FR_TLS_CN][lookup], common_name);
	}

	/*
	 *	Get the RFC822 Subject Alternative Name
	 */
	loc = X509_get_ext_by_NID(client_cert, NID_subject_alt_name, 0);
	if ((lookup <= 1) && (loc >= 0)) {
		X509_EXTENSION *ext = NULL;
		GENERAL_NAMES *names = NULL;
		int i;

		if ((ext = X509_get_ext(client_cert, loc)) &&
		    (names = X509V3_EXT_d2i(ext))) {
			for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
				GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

				switch (name->type) {
#ifdef GEN_EMAIL
				case GEN_EMAIL:
					ADD_CERT_ATTR(cert_attr_names[FR_TLS_SAN_EMAIL][lookup],
						      (char *) ASN1_STRING_data(name->d.rfc822Name));
					break;
#endif	/* GEN_EMAIL */
#ifdef GEN_DNS
				case GEN_DNS:
					ADD_CERT_ATTR(cert_attr_names[FR_TLS_SAN_DNS][lookup],
						      (char *) ASN1_STRING_data(name->d.dNSName));
					break;
#endif	/* GEN_DNS */
#ifdef GEN_OTHERNAME
				case GEN_OTHERNAME:
					/* look for a MS UPN */
					if (NID_ms_upn != OBJ_obj2nid(name->d.otherName->type_id)) break;

					/* we've got a UPN - Must be ASN1-encoded UTF8 string */
					if (name->d.otherName->value->type == V_ASN1_UTF8STRING) {
						ADD_CERT_ATTR(cert_attr_names[FR_TLS_SAN_UPN][lookup],
							      (char *) name->d.otherName->value->value.utf8string);
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
		if (names != NULL) sk_GENERAL_NAME_free(names);
	}

	/*
	 *	If the CRL has expired, that might still be OK.
	 */
	if (!my_ok &&
	    (conf->allow_expired_crl) &&
	    (err == X509_V_ERR_CRL_HAS_EXPIRED)) {
		my_ok = 1;
		X509_STORE_CTX_set_error( ctx, 0 );
	}

	if (!my_ok) {
		char const *p = X509_verify_cert_error_string(err);
		RERROR("TLS error: %s (%i)", p, err);
		fr_pair_list_free(&cert_vps);
		return my_ok;
	}

	if (lookup == 0) {
		client_inf = client_cert->cert_info;
		ext_list = client_inf->extensions;
	} else {
		ext_list = NULL;
	}

	/*
	 *	Grab the X509 extensions, and create attributes out of them.
	 *	For laziness, we re-use the OpenSSL names
	 */
	if (sk_X509_EXTENSION_num(ext_list) > 0) {
		int i, len;
		char *p;
		BIO *out;

		out = BIO_new(BIO_s_mem());
		strlcpy(attribute, "TLS-Client-Cert-", sizeof(attribute));

		for (i = 0; i < sk_X509_EXTENSION_num(ext_list); i++) {
			ASN1_OBJECT *obj;
			X509_EXTENSION *ext;

			ext = sk_X509_EXTENSION_value(ext_list, i);

			obj = X509_EXTENSION_get_object(ext);
			i2a_ASN1_OBJECT(out, obj);
			len = BIO_read(out, attribute + 16 , sizeof(attribute) - 16 - 1);
			if (len <= 0) continue;

			attribute[16 + len] = '\0';

			for (p = attribute + 16; *p != '\0'; p++) {
				if (*p == ' ') *p = '-';
			}

			X509V3_EXT_print(out, ext, 0, 0);
			len = BIO_read(out, value , sizeof(value) - 1);
			if (len <= 0) continue;

			value[len] = '\0';

			vp = fr_pair_make(request, NULL, attribute, value, T_OP_ADD);
			if (!vp) {
				RDEBUG3("Skipping %s += '%s'.  Please check that both the "
					"attribute and value are defined in the dictionaries",
					attribute, value);
			} else {
				fr_cursor_append(&cursor, vp);
			}
		}

		BIO_free_all(out);
	}

	/*
	 *	Add a copy of the cert_vps to session state.
	 */
	if (cert_vps) {
		/*
		 *	Print out all the pairs we have so far
		 */
		rdebug_pair_list(L_DBG_LVL_2, request, cert_vps, "&session-state:");

		/*
		 *	cert_vps have a different talloc parent, so we
		 *	can't just reference them.
		 */
		fr_pair_list_mcopy_by_num(request->state_ctx, &request->state, &cert_vps, 0, 0, TAG_ANY);
		fr_pair_list_free(&cert_vps);
	}

	switch (ctx->error) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		RERROR("issuer=%s", issuer);
		break;

	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		RERROR("notBefore=");
#if 0
		ASN1_TIME_print(bio_err, X509_get_notBefore(ctx->current_cert));
#endif
		break;

	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		RERROR("notAfter=");
#if 0
		ASN1_TIME_print(bio_err, X509_get_notAfter(ctx->current_cert));
#endif
		break;
	}

	/*
	 *	If we're at the actual client cert, apply additional
	 *	checks.
	 */
	if (depth == 0) {
		/*
		 *	If the conf tells us to, check cert issuer
		 *	against the specified value and fail
		 *	verification if they don't match.
		 */
		if (conf->check_cert_issuer &&
		    (strcmp(issuer, conf->check_cert_issuer) != 0)) {
			AUTH("Certificate issuer (%s) does not match specified value (%s)!",
			     issuer, conf->check_cert_issuer);
			my_ok = 0;
		}

		/*
		 *	If the conf tells us to, check the CN in the
		 *	cert against xlat'ed value, but only if the
		 *	previous checks passed.
		 */
		if (my_ok && conf->check_cert_cn) {
			if (radius_xlat(cn_str, sizeof(cn_str), request, conf->check_cert_cn, NULL, NULL) < 0) {
				/* if this fails, fail the verification */
				my_ok = 0;
			} else {
				RDEBUG2("checking certificate CN (%s) with xlat'ed value (%s)", common_name, cn_str);
				if (strcmp(cn_str, common_name) != 0) {
					AUTH("Certificate CN (%s) does not match specified value (%s)!",
					     common_name, cn_str);
					my_ok = 0;
				}
			}
		} /* check_cert_cn */

		while (conf->verify_client_cert_cmd) {
			char filename[256];
			int fd;
			FILE *fp;

			snprintf(filename, sizeof(filename), "%s/%s.client.XXXXXXXX",
				 conf->verify_tmp_dir, main_config.name);
			fd = mkstemp(filename);
			if (fd < 0) {
				RDEBUG("Failed creating file in %s: %s",
				       conf->verify_tmp_dir, fr_syserror(errno));
				break;
			}

			fp = fdopen(fd, "w");
			if (!fp) {
				close(fd);
				RDEBUG("Failed opening file %s: %s",
				       filename, fr_syserror(errno));
				break;
			}

			if (!PEM_write_X509(fp, client_cert)) {
				fclose(fp);
				RDEBUG("Failed writing certificate to file");
				goto do_unlink;
			}
			fclose(fp);

			if (!pair_make_request("TLS-Client-Cert-Filename",
					     filename, T_OP_SET)) {
				RDEBUG("Failed creating TLS-Client-Cert-Filename");

				goto do_unlink;
			}

			RDEBUG("Verifying client certificate: %s", conf->verify_client_cert_cmd);
			if (radius_exec_program(request, NULL, 0, NULL, request, conf->verify_client_cert_cmd,
						request->packet->vps,
						true, true, EXEC_TIMEOUT) != 0) {
				AUTH("Certificate CN (%s) fails external verification!", common_name);
				my_ok = 0;
			} else {
				RDEBUG("Client certificate CN %s passed external validation", common_name);
			}

		do_unlink:
			unlink(filename);
			break;
		}

#ifdef HAVE_OPENSSL_OCSP_H
		/*
		 *	Do OCSP last, so we have the complete set of attributes
		 *	available for the virtual server.
		 *
		 *	Fixme: Do we want to store the matching TLS-Client-cert-Filename?
		 */
		if (my_ok && conf->ocsp_enable){
			RDEBUG2("Starting OCSP Request");
			if (X509_STORE_CTX_get1_issuer(&issuer_cert, ctx, client_cert) != 1) {
				RERROR("Couldn't get issuer_cert for %s", common_name);
			} else {
				my_ok = tls_ocsp_check(request, ocsp_store, issuer_cert, client_cert, conf);
			}
		}
#endif
	} /* depth == 0 */

	if (RDEBUG_ENABLED3) {
		RDEBUG3("chain-depth   : %d", depth);
		RDEBUG3("error         : %d", err);

		if (identity) RDEBUG3("identity      : %s", *identity);
		RDEBUG3("common name   : %s", common_name);
		RDEBUG3("subject       : %s", subject);
		RDEBUG3("issuer        : %s", issuer);
		RDEBUG3("verify return : %d", my_ok);
	}
	return my_ok;
}

#endif /* WITH_TLS */
