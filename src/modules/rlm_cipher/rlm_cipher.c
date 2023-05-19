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
 * @file rlm_cipher.c
 * @brief Creates dynamic expansions for encrypting/decrypting data.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Network RADIUS (legal@networkradius.com)
 *
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/cert.h>
#include <freeradius-devel/tls/log.h>
#include <freeradius-devel/tls/strerror.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/xlat.h>

#include <freeradius-devel/tls/openssl_user_macros.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

static int digest_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			     CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);
static int cipher_rsa_padding_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
					 CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);
static int cipher_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			     CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

static int cipher_rsa_private_key_file_load(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
					    CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);
static int cipher_rsa_certificate_file_load(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
					    CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

typedef enum {
	RLM_CIPHER_TYPE_INVALID = 0,
	RLM_CIPHER_TYPE_RSA = 1,
} cipher_type_t;

/** Certificate validation modes
 *
 */
typedef enum {
	CIPHER_CERT_VERIFY_INVALID = 0,

	CIPHER_CERT_VERIFY_HARD,				//!< Fail if the certificate isn't valid.
	CIPHER_CERT_VERIFY_SOFT,				//!< Warn if the certificate isn't valid.
	CIPHER_CERT_VERIFY_NONE					//!< Don't check to see if the we're between
								///< notBefore or notAfter.
} cipher_cert_verify_mode_t;

typedef enum {
	CIPHER_CERT_ATTR_UNKNOWN = 0,				//!< Unrecognised attribute.
	CIPHER_CERT_ATTR_SERIAL,				//!< Certificate's serial number.
	CIPHER_CERT_ATTR_FINGERPRINT,				//!< Dynamically calculated fingerprint.
	CIPHER_CERT_ATTR_NOT_BEFORE,				//!< Time the certificate becomes valid.
	CIPHER_CERT_ATTR_NOT_AFTER				//!< Time the certificate expires.
} cipher_cert_attributes_t;

/** Public key types
 *
 */
static fr_table_num_sorted_t const pkey_types[] = {
	{ L("DH"),	EVP_PKEY_DH		},
	{ L("DSA"),	EVP_PKEY_DSA		},
	{ L("EC"),	EVP_PKEY_EC		},
	{ L("RSA"),	EVP_PKEY_RSA		}
};
static size_t pkey_types_len = NUM_ELEMENTS(pkey_types);

/** The type of padding used
 *
 */
static fr_table_num_sorted_t const cipher_rsa_padding[] = {
	{ L("none"),	RSA_NO_PADDING		},
	{ L("oaep"),	RSA_PKCS1_OAEP_PADDING	},		/* PKCS OAEP padding */
	{ L("pkcs"),	RSA_PKCS1_PADDING	},		/* PKCS 1.5 */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	{ L("ssl"),	RSA_SSLV23_PADDING	},
#endif
	{ L("x931"),	RSA_X931_PADDING	}
};
static size_t cipher_rsa_padding_len = NUM_ELEMENTS(cipher_rsa_padding);

static fr_table_num_sorted_t const cipher_type[] = {
	{ L("rsa"),	RLM_CIPHER_TYPE_RSA	}
};
static size_t cipher_type_len = NUM_ELEMENTS(cipher_type);

static fr_table_num_sorted_t const cipher_cert_verify_mode_table[] = {
	{ L("hard"),	CIPHER_CERT_VERIFY_HARD	},
	{ L("none"),	CIPHER_CERT_VERIFY_SOFT	},
	{ L("soft"),	CIPHER_CERT_VERIFY_NONE	}
};
static size_t cipher_cert_verify_mode_table_len = NUM_ELEMENTS(cipher_cert_verify_mode_table);

/** Public key types
 *
 */
static fr_table_num_sorted_t const cert_attributes[] = {
	{ L("fingerprint"),	CIPHER_CERT_ATTR_FINGERPRINT	},
	{ L("notAfter"),	CIPHER_CERT_ATTR_NOT_AFTER	},
	{ L("notBefore"),	CIPHER_CERT_ATTR_NOT_BEFORE	},
	{ L("serial"),		CIPHER_CERT_ATTR_SERIAL		},
};
static size_t cert_attributes_len = NUM_ELEMENTS(cert_attributes);

typedef struct {
	EVP_PKEY_CTX		*evp_encrypt_ctx;		//!< Pre-allocated evp_pkey_ctx.
	EVP_PKEY_CTX		*evp_sign_ctx;			//!< Pre-allocated evp_pkey_ctx.
	EVP_PKEY_CTX		*evp_decrypt_ctx;		//!< Pre-allocated evp_pkey_ctx.
	EVP_PKEY_CTX		*evp_verify_ctx;		//!< Pre-allocated evp_pkey_ctx.

	EVP_MD_CTX		*evp_md_ctx;			//!< Pre-allocated evp_md_ctx for sign and verify.
	uint8_t			*digest_buff;			//!< Pre-allocated digest buffer.
} rlm_cipher_rsa_thread_inst_t;

/** Configuration for the OAEP padding method
 *
 */
typedef struct {
	EVP_MD			*oaep_digest;			//!< Padding digest type.
	EVP_MD			*mgf1_digest;			//!< Masking function digest.

	char const		*label;				//!< Additional input to the hashing function.
} cipher_rsa_oaep_t;



/** Configuration for RSA encryption/decryption/signing
 *
 */
typedef struct {
	char const		*private_key_password;		//!< Password to decrypt the private key.
	char const		*random_file;			//!< If set, we read 10K of data (or the complete file)
								//!< and use it to seed OpenSSL's PRNG.

	EVP_PKEY		*private_key_file;		//!< Private key file.
	EVP_PKEY		*certificate_file;		//!< Public (certificate) file.
	X509			*x509_certificate_file;		//!< Needed for extracting certificate attributes.

	cipher_cert_verify_mode_t verify_mode;			//!< How hard we try to verify the certificate.
	fr_unix_time_t		not_before;			//!< Certificate isn't valid before this time.
	fr_unix_time_t		not_after;			//!< Certificate isn't valid after this time.

	int			padding;			//!< Type of padding to apply to the plaintext
								///< or ciphertext before feeding it to RSA crypto
								///< functions.

	EVP_MD			*sig_digest;			//!< Signature digest type.

	cipher_rsa_oaep_t	*oaep;				//!< OAEP can use a configurable message digest type
} cipher_rsa_t;

/** Instance configuration
 *
 */
typedef struct {
	cipher_type_t		type;				//!< Type of encryption to use.

	/** Supported cipher types
	 *
	 */
	union {
		cipher_rsa_t	*rsa;				//!< Use RSA encryption (with optional padding).
	};
} rlm_cipher_t;

/** Configuration for the RSA-PCKS1-OAEP padding scheme
 *
 */
static const CONF_PARSER rsa_oaep_config[] = {
	{ FR_CONF_OFFSET("oaep_digest", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY, cipher_rsa_oaep_t, oaep_digest), .func = digest_type_parse, .dflt = "sha256" },
	{ FR_CONF_OFFSET("mgf1_digest", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY, cipher_rsa_oaep_t, mgf1_digest), .func = digest_type_parse, .dflt = "sha256" },
	{ FR_CONF_OFFSET("label", FR_TYPE_STRING, cipher_rsa_oaep_t, label) },

	CONF_PARSER_TERMINATOR
};

/** Configuration for the RSA cipher type
 *
 */
static const CONF_PARSER rsa_config[] = {
	{ FR_CONF_OFFSET("verify_mode", FR_TYPE_VOID, cipher_rsa_t, verify_mode),
			 .func = cf_table_parse_int,
			 .uctx = &(cf_table_parse_ctx_t){
			 	.table = cipher_cert_verify_mode_table,
			 	.len = &cipher_cert_verify_mode_table_len
			 },
			 .dflt = "hard" }, /* Must come before certificate file */

	{ FR_CONF_OFFSET("private_key_password", FR_TYPE_STRING | FR_TYPE_SECRET, cipher_rsa_t, private_key_password) },	/* Must come before private_key */
	{ FR_CONF_OFFSET("private_key_file", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY, cipher_rsa_t, private_key_file), .func = cipher_rsa_private_key_file_load },
	{ FR_CONF_OFFSET("certificate_file", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY, cipher_rsa_t, certificate_file), .func = cipher_rsa_certificate_file_load },

	{ FR_CONF_OFFSET("random_file", FR_TYPE_STRING, cipher_rsa_t, random_file) },

	{ FR_CONF_OFFSET("signature_digest", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY, cipher_rsa_t, sig_digest), .func = digest_type_parse, .dflt = "sha256" },

	{ FR_CONF_OFFSET("padding_type", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY, cipher_rsa_t, padding), .func = cipher_rsa_padding_type_parse, .dflt = "pkcs" },

	{ FR_CONF_OFFSET("oaep", FR_TYPE_SUBSECTION, cipher_rsa_t, oaep),
			 .subcs_size = sizeof(cipher_rsa_oaep_t), .subcs_type = "cipher_rsa_oaep_t", .subcs = (void const *) rsa_oaep_config },

	CONF_PARSER_TERMINATOR
};

/*
 *	A mapping of configuration file names to internal variables.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("type", FR_TYPE_VOID | FR_TYPE_NOT_EMPTY, rlm_cipher_t, type), .func = cipher_type_parse, .dflt = "rsa" },
	{ FR_CONF_OFFSET("rsa", FR_TYPE_SUBSECTION, rlm_cipher_t, rsa),
			 .subcs_size = sizeof(cipher_rsa_t), .subcs_type = "cipher_rsa_t", .subcs = (void const *) rsa_config },

	CONF_PARSER_TERMINATOR
};

/** Calls EVP_get_digestbyname() to covert the digest type
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	EVP_MD representing the OpenSSL digest type.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the digest.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int digest_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			     CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	EVP_MD const	*md;
	char const	*type_str;

	type_str = cf_pair_value(cf_item_to_pair(ci));
	md = EVP_get_digestbyname(type_str);
	if (!md) {
		cf_log_err(ci, "Invalid digest type \"%s\"", type_str);
		return -1;
	}

	*((EVP_MD const **)out) = md;

	return 0;
}

/** Checks if the specified padding type is valid
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	Padding type.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the padding type..
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int cipher_rsa_padding_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
					 CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	int		type;
	char const	*type_str;

	type_str = cf_pair_value(cf_item_to_pair(ci));
	type = fr_table_value_by_str(cipher_rsa_padding, type_str, -1);
	if (type == -1) {
		cf_log_err(ci, "Invalid padding type \"%s\"", type_str);
		return -1;
	}

	*((int *)out) = type;

	return 0;
}

/** Checks if the specified cipher type is valid
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	Cipher enumeration type.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int cipher_type_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	cipher_type_t	type;
	char const	*type_str;

	type_str = cf_pair_value(cf_item_to_pair(ci));
	type = fr_table_value_by_str(cipher_type, type_str, RLM_CIPHER_TYPE_INVALID);
	switch (type) {
	case RLM_CIPHER_TYPE_RSA:
		break;

	case RLM_CIPHER_TYPE_INVALID:
		cf_log_err(ci, "Invalid cipher type \"%s\"", type_str);
		return -1;
	}

	*((cipher_type_t *)out) = type;

	return 0;
}

/** Return the static private key password we have configured
 *
 * @param[out] buf	Where to write the password to.
 * @param[in] size	The length of buf.
 * @param[in] rwflag
 *			- 0 if password used for decryption.
 *			- 1 if password used for encryption.
 * @param[in] u		The static password.
 * @return
 *	- 0 on error.
 *	- >0 on success (the length of the password).
 */
static int _get_private_key_password(char *buf, int size, UNUSED int rwflag, void *u)
{
	char		*pass;
	size_t		len;

	if (!u) {
		ERROR("Certificate encrypted but no private_key_password configured");
		return 0;
	}

 	pass = talloc_get_type_abort(u, char);
	len = talloc_array_length(pass);	/* Len includes \0 */
	if (len > (size_t)size) {
		ERROR("Password too long.  Maximum length is %i bytes", size - 1);
		return -1;
	}
	memcpy(buf, pass, len);			/* Copy complete password including \0 byte */

	return len - 1;
}

/** Talloc destructor for freeing an EVP_PKEY (representing a certificate)
 *
 * @param[in] pkey	to free.
 * @return 0
 */
static int _evp_pkey_free(EVP_PKEY *pkey)
{
	EVP_PKEY_free(pkey);

	return 0;
}

/** Talloc destructor for freeing an X509 struct (representing a public certificate)
 *
 * @param[in] cert	to free.
 * @return 0
 */
static int _x509_cert_free(X509 *cert)
{
	X509_free(cert);

	return 0;
}

/** Load and (optionally decrypt) an RSA private key using OpenSSL functions
 *
 * @param[in] ctx	UNUSED. Although the EVP_PKEY struct will be allocated
 *			with talloc, we need to call the specialised free
 *			function anyway.
 * @param[out] out	Where to write the EVP_PKEY * representing the
 *			certificate we just loaded.
 * @param[in] parent	Base structure address.
 * @param[in] ci	Config item containing the certificate path.
 * @param[in] rule	this callback was attached to.
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 */
static int cipher_rsa_private_key_file_load(TALLOC_CTX *ctx, void *out, void *parent,
					    CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	FILE		*fp;
	char const	*filename;
	cipher_rsa_t	*rsa_inst = talloc_get_type_abort(parent, cipher_rsa_t);
	EVP_PKEY	*pkey;
	int		pkey_type;

	filename = cf_pair_value(cf_item_to_pair(ci));

	fp = fopen(filename, "r");
	if (!fp) {
		cf_log_err(ci, "Failed opening private_key file \"%s\": %s", filename, fr_syserror(errno));
		return -1;
	}

	pkey = PEM_read_PrivateKey(fp, (EVP_PKEY **)out, _get_private_key_password,
				   UNCONST(void *, rsa_inst->private_key_password));
	fclose(fp);

	if (!pkey) {
		fr_tls_strerror_printf(NULL);
		cf_log_perr(ci, "Error loading private certificate file \"%s\"", filename);

		return -1;
	}

	pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));
	if (pkey_type != EVP_PKEY_RSA) {
		cf_log_err(ci, "Expected certificate to contain %s private key, got %s private key",
			   fr_table_str_by_value(pkey_types, EVP_PKEY_RSA, OBJ_nid2sn(pkey_type)),
			   fr_table_str_by_value(pkey_types, pkey_type, OBJ_nid2sn(pkey_type)));

		EVP_PKEY_free(pkey);
		return -1;
	}

	talloc_set_type(pkey, EVP_PKEY);
	(void)talloc_steal(ctx, pkey);			/* Bind lifetime to config */
	talloc_set_destructor(pkey, _evp_pkey_free);	/* Free pkey correctly on chunk free */

	return 0;
}

/** Load an RSA public key using OpenSSL functions
 *
 * @param[in] ctx	UNUSED. Although the EVP_PKEY struct will be allocated
 *			with talloc, we need to call the specialised free
 *			function anyway.
 * @param[out] out	Where to write the EVP_PKEY * representing the
 *			certificate we just loaded.
 * @param[in] parent	Base structure address.
 * @param[in] ci	Config item containing the certificate path.
 * @param[in] rule	this callback was attached to.
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 */
static int cipher_rsa_certificate_file_load(TALLOC_CTX *ctx, void *out, void *parent,
					    CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	FILE		*fp;
	char const	*filename;
	cipher_rsa_t	*rsa_inst = talloc_get_type_abort(parent, cipher_rsa_t);

	X509		*cert;		/* X509 certificate */
	EVP_PKEY	*pkey;		/* Wrapped public key */
	int		pkey_type;

	filename = cf_pair_value(cf_item_to_pair(ci));

	fp = fopen(filename, "r");
	if (!fp) {
		cf_log_err(ci, "Failed opening certificate_file \"%s\": %s", filename, fr_syserror(errno));
		return -1;
	}

	/*
	 *	Load the PEM encoded X509 certificate
	 */
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (!cert) {
		fr_tls_strerror_printf(NULL);
		cf_log_perr(ci, "Error loading certificate file \"%s\"", filename);

		return -1;
	}

	/*
	 *	Keep the x509 structure around as we may want
	 *	to extract information from fields in the cert
	 *	or calculate its fingerprint.
	 */
	talloc_set_type(cert, X509);
	(void)talloc_steal(ctx, cert);			/* Bind lifetime to config */
	talloc_set_destructor(cert, _x509_cert_free);	/* Free x509 cert correctly on chunk free */

	/*
	 *	Extract the public key from the certificate
	 */
	pkey = X509_get_pubkey(cert);
	if (!pkey) {
		fr_tls_strerror_printf(NULL);
		cf_log_perr(ci, "Failed extracting public key from certificate");

		return -1;
	}

	pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));
	if (pkey_type != EVP_PKEY_RSA) {
		cf_log_err(ci, "Expected certificate to contain %s public key, got %s public key",
			   fr_table_str_by_value(pkey_types, EVP_PKEY_RSA, "?Unknown?"),
			   fr_table_str_by_value(pkey_types, pkey_type, "?Unknown?"));
	error:
		EVP_PKEY_free(pkey);
		return -1;
	}

	/*
	 *	Certificate validity checks
	 */
	switch (fr_tls_cert_is_valid(&rsa_inst->not_before, &rsa_inst->not_after, cert)) {
	case 0:
		cf_log_debug(ci, "Certificate validity starts at %pV and ends at %pV",
			     fr_box_date(rsa_inst->not_before), fr_box_date(rsa_inst->not_after));
		break;

	case -1:
		cf_log_perr(ci, "Malformed certificate");
		return -1;

	case -2:
	case -3:
		switch (rsa_inst->verify_mode) {
		case CIPHER_CERT_VERIFY_SOFT:
			cf_log_pwarn(ci, "Certificate validation failed");
			break;

		case CIPHER_CERT_VERIFY_HARD:
			cf_log_perr(ci, "Certificate validation failed");
			goto error;

		case CIPHER_CERT_VERIFY_NONE:
			break;

		case CIPHER_CERT_ATTR_UNKNOWN:
			fr_assert(0);
			break;
		}
	}

	talloc_set_type(pkey, EVP_PKEY);
	(void)talloc_steal(cert, pkey);			/* Bind lifetime to config */
	talloc_set_destructor(pkey, _evp_pkey_free);	/* Free pkey correctly on chunk free */

	rsa_inst->x509_certificate_file = cert;		/* Not great, but shouldn't cause any issues */
	*(EVP_PKEY **)out = pkey;

	return 0;
}

static xlat_arg_parser_t const cipher_rsa_encrypt_xlat_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Encrypt input data
 *
 * Arguments are @verbatim(<plaintext>...)@endverbatim
 *
@verbatim
%{<inst>.encrypt:<plaintext>...}
@endverbatim
 *
 * If multiple arguments are provided they will be concatenated.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t cipher_rsa_encrypt_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					     xlat_ctx_t const *xctx,
					     request_t *request, fr_value_box_list_t *in)
{
	rlm_cipher_rsa_thread_inst_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_cipher_rsa_thread_inst_t);

	char const			*plaintext;
	size_t				plaintext_len;

	uint8_t				*ciphertext;
	size_t				ciphertext_len;

	fr_value_box_t			*vb;
	fr_value_box_t			*in_head = fr_value_box_list_head(in);

	plaintext = in_head->vb_strvalue;
	plaintext_len = in_head->vb_length;

	/*
	 *	Figure out the buffer we need
	 */
	RHEXDUMP3((uint8_t const *)plaintext, plaintext_len, "Plaintext (%zu bytes)", plaintext_len);
	if (EVP_PKEY_encrypt(t->evp_encrypt_ctx, NULL, &ciphertext_len,
			     (unsigned char const *)plaintext, plaintext_len) <= 0) {
		fr_tls_log(request, "Failed getting length of encrypted plaintext");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_mem_alloc(vb, &ciphertext, vb, NULL, ciphertext_len, false) == 0);
	if (EVP_PKEY_encrypt(t->evp_encrypt_ctx, ciphertext, &ciphertext_len,
			     (unsigned char const *)plaintext, plaintext_len) <= 0) {
		fr_tls_log(request, "Failed encrypting plaintext");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}
	RHEXDUMP3(ciphertext, ciphertext_len, "Ciphertext (%zu bytes)", ciphertext_len);
	MEM(fr_value_box_mem_realloc(vb, NULL, vb, ciphertext_len) == 0);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}


static xlat_arg_parser_t const cipher_rsa_sign_xlat_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Sign input data
 *
 * Arguments are @verbatim(<plaintext>...)@endverbatim
 *
@verbatim
%{<inst>.sign:<plaintext>...}
@endverbatim
 *
 * If multiple arguments are provided they will be concatenated.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t cipher_rsa_sign_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					  xlat_ctx_t const *xctx,
					  request_t *request, fr_value_box_list_t *in)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_cipher_t);
	rlm_cipher_rsa_thread_inst_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_cipher_rsa_thread_inst_t);

	char const			*msg;
	size_t				msg_len;

	uint8_t				*sig;
	size_t				sig_len;

	unsigned int			digest_len = 0;

	fr_value_box_t			*vb;
	fr_value_box_t			*in_head = fr_value_box_list_head(in);

	msg = in_head->vb_strvalue;
	msg_len = in_head->vb_length;

	/*
	 *	First produce a digest of the message
	 */
	if (unlikely(EVP_DigestInit_ex(t->evp_md_ctx, inst->rsa->sig_digest, NULL) <= 0)) {
		fr_tls_log(request, "Failed initialising message digest");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestUpdate(t->evp_md_ctx, msg, msg_len) <= 0) {
		fr_tls_log(request, "Failed ingesting message");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestFinal_ex(t->evp_md_ctx, t->digest_buff, &digest_len) <= 0) {
		fr_tls_log(request, "Failed finalising message digest");
		return XLAT_ACTION_FAIL;
	}
	fr_assert((size_t)digest_len == talloc_array_length(t->digest_buff));

	/*
	 *	Then sign the digest
	 */
	if (EVP_PKEY_sign(t->evp_sign_ctx, NULL, &sig_len, t->digest_buff, (size_t)digest_len) <= 0) {
		fr_tls_log(request, "Failed getting length of digest");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_mem_alloc(vb, &sig, vb, NULL, sig_len, false) == 0);
	if (EVP_PKEY_sign(t->evp_sign_ctx, sig, &sig_len, t->digest_buff, (size_t)digest_len) <= 0) {
		fr_tls_log(request, "Failed signing message digest");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}
	MEM(fr_value_box_mem_realloc(vb, NULL, vb, sig_len) == 0);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const cipher_rsa_decrypt_xlat_arg[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_OCTETS },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Decrypt input data
 *
 * Arguments are @verbatim(<ciphertext\>...)@endverbatim
 *
@verbatim
%{<inst>.decrypt:<ciphertext>...}
@endverbatim
 *
 * If multiple arguments are provided they will be concatenated.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t cipher_rsa_decrypt_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					     xlat_ctx_t const *xctx,
					     request_t *request, fr_value_box_list_t *in)
{
	rlm_cipher_rsa_thread_inst_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_cipher_rsa_thread_inst_t);

	uint8_t	const			*ciphertext;
	size_t				ciphertext_len;

	char				*plaintext;
	size_t				plaintext_len;

	fr_value_box_t			*vb;
	fr_value_box_t			*in_head = fr_value_box_list_head(in);

	ciphertext = in_head->vb_octets;
	ciphertext_len = in_head->vb_length;

	/*
	 *	Decrypt the ciphertext
	 */
	RHEXDUMP3(ciphertext, ciphertext_len, "Ciphertext (%zu bytes)", ciphertext_len);
	if (EVP_PKEY_decrypt(t->evp_decrypt_ctx, NULL, &plaintext_len, ciphertext, ciphertext_len) <= 0) {
		fr_tls_log(request, "Failed getting length of cleartext");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &plaintext, vb, NULL, plaintext_len, true) == 0);
	if (EVP_PKEY_decrypt(t->evp_decrypt_ctx, (unsigned char *)plaintext, &plaintext_len,
			     ciphertext, ciphertext_len) <= 0) {
		fr_tls_log(request, "Failed decrypting ciphertext");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}
	RHEXDUMP3((uint8_t const *)plaintext, plaintext_len, "Plaintext (%zu bytes)", plaintext_len);
	MEM(fr_value_box_bstr_realloc(vb, NULL, vb, plaintext_len) == 0);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const cipher_rsa_verify_xlat_arg[] = {
	{ .required = true, .concat = false, .single = true, .type = FR_TYPE_VOID },
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_SQUASH, .concat = true,  .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Verify input data
 *
 * Arguments are @verbatim(<signature>, <plaintext>...)@endverbatim
 *
@verbatim
%(<inst>.verify:<signature> <plaintext>...)
@endverbatim
 *
 * If multiple arguments are provided (after @verbatim<signature>@endverbatim)
 * they will be concatenated.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t cipher_rsa_verify_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 	    xlat_ctx_t const *xctx,
					    request_t *request, fr_value_box_list_t *in)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_cipher_t);
	rlm_cipher_rsa_thread_inst_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_cipher_rsa_thread_inst_t);

	uint8_t	const			*sig;
	size_t				sig_len;

	char const			*msg;
	size_t				msg_len;

	unsigned int			digest_len = 0;

	fr_value_box_t			*vb;
	fr_value_box_t			*in_head = fr_value_box_list_pop_head(in);
	fr_value_box_t			*args;

	/*
	 *	Don't auto-cast to octets if the signature
	 *	isn't already in that form.
	 *	It could be hexits or base64 or some other encoding.
	 */
	if (in_head->type != FR_TYPE_OCTETS) {
		REDEBUG("Signature argument wrong type, expected %s, got %s.  "
			"Use %%{base64_decode:<text>} or %%{hex_decode:<text>} if signature is armoured",
			fr_type_to_str(FR_TYPE_OCTETS),
			fr_type_to_str(in_head->type));
		return XLAT_ACTION_FAIL;
	}
	sig = in_head->vb_octets;
	sig_len = in_head->vb_length;

	/*
	 *	Concat (...) args to get message data
	 */
	args = fr_value_box_list_head(in);
	if (fr_value_box_list_concat_in_place(ctx,
					      args, in, FR_TYPE_STRING,
					      FR_VALUE_BOX_LIST_FREE, true,
					      SIZE_MAX) < 0) {
		REDEBUG("Failed concatenating arguments to form plaintext");
		return XLAT_ACTION_FAIL;
	}
	msg = args->vb_strvalue;
	msg_len = args->vb_length;

	if (msg_len == 0) {
		REDEBUG("Zero length message data");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	First produce a digest of the message
	 */
	if (unlikely(EVP_DigestInit_ex(t->evp_md_ctx, inst->rsa->sig_digest, NULL) <= 0)) {
		fr_tls_log(request, "Failed initialising message digest");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestUpdate(t->evp_md_ctx, msg, msg_len) <= 0) {
		fr_tls_log(request, "Failed ingesting message");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestFinal_ex(t->evp_md_ctx, t->digest_buff, &digest_len) <= 0) {
		fr_tls_log(request, "Failed finalising message digest");
		return XLAT_ACTION_FAIL;
	}
	fr_assert((size_t)digest_len == talloc_array_length(t->digest_buff));

	/*
	 *	Now check the signature matches what we expected
	 */
	switch (EVP_PKEY_verify(t->evp_verify_ctx, sig, sig_len, t->digest_buff, (size_t)digest_len)) {
	case 1:		/* success (signature valid) */
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, false));
		vb->vb_bool = true;
		fr_dcursor_append(out, vb);
		break;

	case 0:		/* failure (signature not valid) */
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, false));
		vb->vb_bool = false;
		fr_dcursor_append(out, vb);
		break;

	default:
		fr_tls_log(request, "Failed validating signature");
		return XLAT_ACTION_FAIL;
	}

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const cipher_certificate_xlat_args[] = {
	{ .required = true, .concat = false, .single = true, .type = FR_TYPE_STRING },
	{ .required = false, .concat = false, .single = true, .type = FR_TYPE_STRING }, /* Optional hash for fingerprint mode */
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return the fingerprint of the public certificate
 *
 * Arguments are @verbatim(<digest>)@endverbatim
 *
@verbatim
%(<inst>.certificate:fingerprint <digest>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t cipher_fingerprint_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 	     xlat_ctx_t const *xctx,
					     request_t *request, fr_value_box_list_t *in)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_cipher_t);
	char const			*md_name;
	EVP_MD const			*md;
	size_t				md_len;
	fr_value_box_t			*vb;
	uint8_t				*digest;

	if (!fr_value_box_list_next(in, fr_value_box_list_head(in))) {
		REDEBUG("Missing digest argument");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Second arg...
	 */
	md_name = ((fr_value_box_t *)fr_value_box_list_next(in, fr_value_box_list_head(in)))->vb_strvalue;
	md = EVP_get_digestbyname(md_name);
	if (!md) {
		REDEBUG("Specified digest \"%s\" is not a valid digest type", md_name);
		return XLAT_ACTION_FAIL;
	}

	md_len = EVP_MD_size(md);
	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_mem_alloc(vb, &digest, vb, NULL, md_len, false) == 0);

	if (X509_digest(inst->rsa->x509_certificate_file, md, digest, (unsigned int *)&md_len) != 1) {
		fr_tls_log(request, "Failed calculating certificate fingerprint");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Return the serial of the public certificate
 *
@verbatim
%(<inst>.certificate:serial)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t cipher_serial_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 	xlat_ctx_t const *xctx,
					request_t *request, UNUSED fr_value_box_list_t *in)
{
	rlm_cipher_t const	*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_cipher_t);
	ASN1_INTEGER const	*serial;
    	fr_value_box_t		*vb;

	serial = X509_get0_serialNumber(inst->rsa->x509_certificate_file);
	if (!serial) {
		fr_tls_log(request, "Failed retrieving certificate serial");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_memdup(vb, vb, NULL, serial->data, serial->length, true) == 0);

	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_action_t cipher_certificate_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				 	     xlat_ctx_t const *xctx,
					     request_t *request, fr_value_box_list_t *in)
{
	rlm_cipher_t const	*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_cipher_t);
	char const		*attribute = fr_value_box_list_head(in)->vb_strvalue;
    	fr_value_box_t		*vb;

	switch (fr_table_value_by_str(cert_attributes, attribute, CIPHER_CERT_ATTR_UNKNOWN)) {
	default:
		REDEBUG("Unknown certificate attribute \"%s\"", attribute);
		return XLAT_ACTION_FAIL;

	case CIPHER_CERT_ATTR_FINGERPRINT:
		return cipher_fingerprint_xlat(ctx, out, xctx, request, in);

	case CIPHER_CERT_ATTR_SERIAL:
		return cipher_serial_xlat(ctx, out, xctx, request, in);

	case CIPHER_CERT_ATTR_NOT_BEFORE:
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_DATE, NULL, true));
		vb->vb_date = inst->rsa->not_before;
		fr_dcursor_append(out, vb);
		return XLAT_ACTION_DONE;

	case CIPHER_CERT_ATTR_NOT_AFTER:
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_DATE, NULL, true));
		vb->vb_date = inst->rsa->not_after;
		fr_dcursor_append(out, vb);
		return XLAT_ACTION_DONE;
	}
}

/** Talloc destructor for freeing an EVP_PKEY_CTX
 *
 * @param[in] evp_pkey_ctx	to free.
 * @return 0
 */
static int _evp_pkey_ctx_free(EVP_PKEY_CTX *evp_pkey_ctx)
{
	EVP_PKEY_CTX_free(evp_pkey_ctx);

	return 0;
}

/** Talloc destructor for freeing an EVP_MD_CTX
 *
 * @param[in] evp_md_ctx	to free.
 * @return 0
 */
static int _evp_md_ctx_free(EVP_MD_CTX *evp_md_ctx)
{
	EVP_MD_CTX_destroy(evp_md_ctx);

	return 0;
}

static int cipher_rsa_padding_params_set(EVP_PKEY_CTX *evp_pkey_ctx, cipher_rsa_t const *rsa_inst)
{
	if (unlikely(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, rsa_inst->padding)) <= 0) {
		fr_tls_strerror_printf(NULL);
		PERROR("%s: Failed setting RSA padding type", __FUNCTION__);
		return -1;
	}

	switch (rsa_inst->padding) {
	case RSA_NO_PADDING:
	case RSA_X931_PADDING:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	case RSA_SSLV23_PADDING:
#endif
	case RSA_PKCS1_PADDING:
		return 0;

	/*
	 *	Configure OAEP advanced padding options
	 */
	case RSA_PKCS1_OAEP_PADDING:
		if (unlikely(EVP_PKEY_CTX_set_rsa_oaep_md(evp_pkey_ctx, rsa_inst->oaep->oaep_digest) <= 0)) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed setting OAEP digest", __FUNCTION__);
			return -1;
		}

		if (unlikely(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_ctx, rsa_inst->oaep->mgf1_digest) <= 0)) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed setting MGF1 digest", __FUNCTION__);
			return -1;
		}

		if (rsa_inst->oaep->label) {
			char	*label;
			size_t	label_len = talloc_array_length(rsa_inst->oaep->label) - 1;

			/*
			 *	OpenSSL does not duplicate the label when
			 *	EVP_PKEY_CTX_set0_rsa_oaep_label is called,
			 *	but happily frees it on subsequent calls
			 *	or when the EVP_PKEY_CTX is freed,
			 *	idiots...
			 */
			MEM(label = talloc_bstrndup(evp_pkey_ctx, rsa_inst->oaep->label, label_len));
		    	if (unlikely(EVP_PKEY_CTX_set0_rsa_oaep_label(evp_pkey_ctx, label, label_len) <= 0)) {
	   			fr_tls_strerror_printf(NULL);
				PERROR("%s: Failed setting OAEP padding label", __FUNCTION__);
				OPENSSL_free(label);
				return -1;
			}
		}
		return 0;

	default:
		fr_assert(0);
		return -1;
	}
}

/** Pre-initialises the EVP_PKEY_CTX necessary for performing RSA encryption/decryption/sign/verify
 *
 * If reference counting is used for EVP_PKEY structs, should also prevent any mutex contention
 * associated with incrementing/decrementing those references.
 *
 * xlat functions MUST NOT interleave PKEY operations with yields
 *
 * @return 0.
 */
static int cipher_rsa_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort(mctx->inst->data, rlm_cipher_t);
	rlm_cipher_rsa_thread_inst_t	*ti = talloc_get_type_abort(mctx->thread, rlm_cipher_rsa_thread_inst_t);

	/*
	 *	Pre-allocate different contexts for the different operations
	 *	The OpenSSL docs say this is fine, and it reduces the potential
	 *	for SEGVs and other random errors due to trying to change the
	 *	configuration of a context multiple times.
	 */
	if (inst->rsa->certificate_file) {
		/*
		 *	Alloc encrypt
		 */
		ti->evp_encrypt_ctx = EVP_PKEY_CTX_new(inst->rsa->certificate_file, NULL);
		if (!ti->evp_encrypt_ctx) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed allocating encrypt EVP_PKEY_CTX", __FUNCTION__);
			return -1;
		}
		talloc_set_type(ti->evp_encrypt_ctx, EVP_PKEY_CTX);
		ti->evp_encrypt_ctx = talloc_steal(ti, ti->evp_encrypt_ctx);	/* Bind lifetime to instance */
		talloc_set_destructor(ti->evp_encrypt_ctx, _evp_pkey_ctx_free);	/* Free ctx correctly on chunk free */

		/*
		 *	Configure encrypt
		 */
		if (unlikely(EVP_PKEY_encrypt_init(ti->evp_encrypt_ctx) <= 0)) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed initialising encrypt EVP_PKEY_CTX", __FUNCTION__);
			return XLAT_ACTION_FAIL;
		}
		if (unlikely(cipher_rsa_padding_params_set(ti->evp_encrypt_ctx, inst->rsa) < 0)) {
			ERROR("%s: Failed setting padding for encrypt EVP_PKEY_CTX", __FUNCTION__);
			return -1;
		}

		/*
		 *	Alloc verify
		 */
		ti->evp_verify_ctx = EVP_PKEY_CTX_new(inst->rsa->certificate_file, NULL);
		if (!ti->evp_verify_ctx) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed allocating verify EVP_PKEY_CTX", __FUNCTION__);
			return -1;
		}
		talloc_set_type(ti->evp_verify_ctx, EVP_PKEY_CTX);
		ti->evp_verify_ctx = talloc_steal(ti, ti->evp_verify_ctx);	/* Bind lifetime to instance */
		talloc_set_destructor(ti->evp_verify_ctx, _evp_pkey_ctx_free);	/* Free ctx correctly on chunk free */

		/*
		 *	Configure verify
		 */
		if (unlikely(EVP_PKEY_verify_init(ti->evp_verify_ctx) <= 0)) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed initialising verify EVP_PKEY_CTX", __FUNCTION__);
			return XLAT_ACTION_FAIL;
		}

		/*
		 *	OAEP not valid for signing or verification
		 */
		if (inst->rsa->padding != RSA_PKCS1_OAEP_PADDING) {
			if (unlikely(cipher_rsa_padding_params_set(ti->evp_verify_ctx, inst->rsa) < 0)) {
				ERROR("%s: Failed setting padding for verify EVP_PKEY_CTX", __FUNCTION__);
				return -1;
			}
		}

		if (unlikely(EVP_PKEY_CTX_set_signature_md(ti->evp_verify_ctx, inst->rsa->sig_digest)) <= 0) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed setting signature digest type", __FUNCTION__);
			return XLAT_ACTION_FAIL;
		}
	}

	if (inst->rsa->private_key_file) {
		/*
		 *	Alloc decrypt
		 */
		ti->evp_decrypt_ctx = EVP_PKEY_CTX_new(inst->rsa->private_key_file, NULL);
		if (!ti->evp_decrypt_ctx) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed allocating decrypt EVP_PKEY_CTX", __FUNCTION__);
			return -1;
		}
		talloc_set_type(ti->evp_decrypt_ctx, EVP_PKEY_CTX);
		ti->evp_decrypt_ctx = talloc_steal(ti, ti->evp_decrypt_ctx);	/* Bind lifetime to instance */
		talloc_set_destructor(ti->evp_decrypt_ctx, _evp_pkey_ctx_free);	/* Free ctx correctly on chunk free */

		/*
		 *	Configure decrypt
		 */
		if (unlikely(EVP_PKEY_decrypt_init(ti->evp_decrypt_ctx) <= 0)) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed initialising decrypt EVP_PKEY_CTX", __FUNCTION__);
			return XLAT_ACTION_FAIL;
		}
		if (unlikely(cipher_rsa_padding_params_set(ti->evp_decrypt_ctx, inst->rsa) < 0)) {
			ERROR("%s: Failed setting padding for decrypt EVP_PKEY_CTX", __FUNCTION__);
			return -1;
		}

		/*
		 *	Alloc sign
		 */
		ti->evp_sign_ctx = EVP_PKEY_CTX_new(inst->rsa->private_key_file, NULL);
		if (!ti->evp_sign_ctx) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed allocating sign EVP_PKEY_CTX", __FUNCTION__);
			return -1;
		}
		talloc_set_type(ti->evp_sign_ctx, EVP_PKEY_CTX);
		ti->evp_sign_ctx = talloc_steal(ti, ti->evp_sign_ctx);		/* Bind lifetime to instance */
		talloc_set_destructor(ti->evp_sign_ctx, _evp_pkey_ctx_free);	/* Free ctx correctly on chunk free */

		/*
		 *	Configure sign
		 */
		if (unlikely(EVP_PKEY_sign_init(ti->evp_sign_ctx) <= 0)) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed initialising sign EVP_PKEY_CTX", __FUNCTION__);
			return XLAT_ACTION_FAIL;
		}

		/*
		 *	OAEP not valid for signing or verification
		 */
		if (inst->rsa->padding != RSA_PKCS1_OAEP_PADDING) {
			if (unlikely(cipher_rsa_padding_params_set(ti->evp_sign_ctx, inst->rsa) < 0)) {
				ERROR("%s: Failed setting padding for sign EVP_PKEY_CTX", __FUNCTION__);
				return -1;
			}
		}

		if (unlikely(EVP_PKEY_CTX_set_signature_md(ti->evp_sign_ctx, inst->rsa->sig_digest)) <= 0) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed setting signature digest type", __FUNCTION__);
			return XLAT_ACTION_FAIL;
		}

		/*
		 *	Alloc digest ctx for signing and verification
		 */
		ti->evp_md_ctx = EVP_MD_CTX_create();
		if (!ti->evp_md_ctx) {
			fr_tls_strerror_printf(NULL);
			PERROR("%s: Failed allocating EVP_MD_CTX", __FUNCTION__);
			return -1;
		}
		talloc_set_type(ti->evp_md_ctx, EVP_MD_CTX);
		ti->evp_md_ctx = talloc_steal(ti, ti->evp_md_ctx);			/* Bind lifetime to instance */
		talloc_set_destructor(ti->evp_md_ctx, _evp_md_ctx_free);		/* Free ctx correctly on chunk free */
		MEM(ti->digest_buff = talloc_array(ti, uint8_t, EVP_MD_size(inst->rsa->sig_digest)));
	}

	return 0;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_cipher_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_cipher_t);

	switch (inst->type) {
	case RLM_CIPHER_TYPE_RSA:
		talloc_set_type(mctx->thread, rlm_cipher_rsa_thread_inst_t);
		return cipher_rsa_thread_instantiate(mctx);

	case RLM_CIPHER_TYPE_INVALID:
		fr_assert(0);
	}

	return 0;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_cipher_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_cipher_t);
	CONF_SECTION	*conf = mctx->inst->conf;

	switch (inst->type) {
	case RLM_CIPHER_TYPE_RSA:
		if (!inst->rsa) {
			cf_log_err(conf, "type = rsa, but no 'rsa { ... }' configuration section provided");
			return -1;
		}

		if (!inst->rsa->private_key_file && !inst->rsa->certificate_file) {
			cf_log_err(conf, "type = rsa, but neither "
					 "'private_key_file' nor 'certificate_file' configured");
			return -1;
		}

		if (inst->rsa->private_key_file) {
			xlat_t *xlat;

			/*
			 *	Register decrypt xlat
			 */
			xlat = xlat_func_register_module(inst, mctx, "decrypt", cipher_rsa_decrypt_xlat, FR_TYPE_STRING);
			xlat_func_mono_set(xlat, cipher_rsa_decrypt_xlat_arg);

			/*
			 *	Verify sign xlat
			 */
			xlat = xlat_func_register_module(inst, mctx, "verify", cipher_rsa_verify_xlat, FR_TYPE_BOOL);
			xlat_func_args_set(xlat, cipher_rsa_verify_xlat_arg);
		}

		if (inst->rsa->certificate_file) {
			xlat_t *xlat;

			/*
			 *	If we have both public and private keys check they're
			 *	part of the same keypair.  This isn't technically a requirement
			 *	but it fixes some obscure errors where the user uses the serial
			 *	xlat, expecting it to be the serial of the keypair containing
			 *	the private key.
			 */
			if (inst->rsa->private_key_file && inst->rsa->x509_certificate_file) {
				if (X509_check_private_key(inst->rsa->x509_certificate_file,
							   inst->rsa->private_key_file) == 0) {
					fr_tls_strerror_printf(NULL);
					cf_log_perr(conf, "Private key does not match the certificate public key");
					return -1;
				}
			}

			/*
			 *	Register encrypt xlat
			 */
			xlat = xlat_func_register_module(inst, mctx, "encrypt", cipher_rsa_encrypt_xlat, FR_TYPE_OCTETS);
			xlat_func_mono_set(xlat, cipher_rsa_encrypt_xlat_arg);

			/*
			 *	Register sign xlat
			 */
			xlat = xlat_func_register_module(inst, mctx, "sign", cipher_rsa_sign_xlat, FR_TYPE_OCTETS);
			xlat_func_mono_set(xlat, cipher_rsa_sign_xlat_arg);

			/*
			 *	FIXME: These should probably be split into separate xlats
			 *	so we can optimise for return types.
			 */
			xlat = xlat_func_register_module(inst, mctx, "certificate", cipher_certificate_xlat, FR_TYPE_VOID);
			xlat_func_args_set(xlat, cipher_certificate_xlat_args);
		}
		break;

	/*
	 *	Populated by cipher_type_parse() so if
	 *	the value is unrecognised we've got an issue.
	 */
	default:
		fr_assert(0);
		return -1;
	};

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_cipher;
module_rlm_t rlm_cipher = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "cipher",
		.type			= MODULE_TYPE_THREAD_SAFE,
		.inst_size		= sizeof(rlm_cipher_t),
		.thread_inst_size	= sizeof(rlm_cipher_rsa_thread_inst_t),
		.config			= module_config,
		.bootstrap		= mod_bootstrap,
		.thread_instantiate	= mod_thread_instantiate
	}
};
