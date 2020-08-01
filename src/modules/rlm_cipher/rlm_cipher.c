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
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/tls/base.h>

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

/** Public key types
 *
 */
static fr_table_num_sorted_t const pkey_types[] = {
	{ L("DH"),		EVP_PKEY_DH		},
	{ L("DSA"),	EVP_PKEY_DSA		},
	{ L("EC"),		EVP_PKEY_EC		},
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
	{ L("ssl"),	RSA_SSLV23_PADDING	},
	{ L("x931"),	RSA_X931_PADDING	}
};
static size_t cipher_rsa_padding_len = NUM_ELEMENTS(cipher_rsa_padding);

static fr_table_num_sorted_t const cipher_type[] = {
	{ L("rsa"),	RLM_CIPHER_TYPE_RSA	}
};
static size_t cipher_type_len = NUM_ELEMENTS(cipher_type);

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
	char const		*xlat_name;			//!< Name of xlat we registered.
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
static int cipher_rsa_private_key_file_load(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
					    CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	FILE		*fp;
	char const	*filename;
	cipher_rsa_t	*rsa_inst = talloc_get_type_abort(ctx, cipher_rsa_t);	/* Yeah this is a bit hacky */
	EVP_PKEY	*pkey;
	void		*pass;
	int		pkey_type;

	filename = cf_pair_value(cf_item_to_pair(ci));

	fp = fopen(filename, "r");
	if (!fp) {
		cf_log_err(ci, "Failed opening private_key file \"%s\": %s", filename, fr_syserror(errno));
		return -1;
	}

	memcpy(&pass, &rsa_inst->private_key_password, sizeof(pass));

	pkey = PEM_read_PrivateKey(fp, (EVP_PKEY **)out, _get_private_key_password, pass);
	fclose(fp);

	if (!pkey) {
		tls_strerror_printf(NULL);
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
static int cipher_rsa_certificate_file_load(TALLOC_CTX *ctx, void *out, UNUSED void *parent,
					    CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	FILE		*fp;
	char const	*filename;

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
		tls_strerror_printf(NULL);
		cf_log_perr(ci, "Error loading certificate file \"%s\"", filename);

		return -1;
	}

	/*
	 *	Extract the public key from the certificate
	 */
	pkey = X509_get_pubkey(cert);
	X509_free(cert);	/* Decrease reference count or free cert */

	if (!pkey) {
		tls_strerror_printf(NULL);
		cf_log_perr(ci, "Failed extracting public key from certificate");

		return -1;
	}

	pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));
	if (pkey_type != EVP_PKEY_RSA) {
		cf_log_err(ci, "Expected certificate to contain %s public key, got %s public key",
			   fr_table_str_by_value(pkey_types, EVP_PKEY_RSA, "?Unknown?"),
			   fr_table_str_by_value(pkey_types, pkey_type, "?Unknown?"));

		EVP_PKEY_free(pkey);
		return -1;
	}

	talloc_set_type(pkey, EVP_PKEY);
	(void)talloc_steal(ctx, pkey);			/* Bind lifetime to config */
	talloc_set_destructor(pkey, _evp_pkey_free);	/* Free pkey correctly on chunk free */

	*(EVP_PKEY **)out = pkey;

	return 0;
}

/** Encrypt input data
 *
 * Arguments are @verbatim(<plaintext>...)@endverbatim
 *
@verbatim
%{<inst>_encrypt:<plaintext>...}
@endverbatim
 *
 * If multiple arguments are provided they will be concatenated.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t cipher_rsa_encrypt_xlat(TALLOC_CTX *ctx, fr_cursor_t *out,
					     REQUEST *request, UNUSED void const *xlat_inst, void *xlat_thread_inst,
					     fr_value_box_t **in)
{
	rlm_cipher_rsa_thread_inst_t	*xt = talloc_get_type_abort(*((void **)xlat_thread_inst),
								    rlm_cipher_rsa_thread_inst_t);

	char const			*plaintext;
	size_t				plaintext_len;

	uint8_t				*ciphertext;
	size_t				ciphertext_len;

	fr_value_box_t			*vb;

	if (!*in) {
		REDEBUG("encrypt requires one or arguments (<plaintext>...)");
		return XLAT_ACTION_FAIL;
	}

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		fr_tls_log_error(request, "Failed concatenating arguments to form plaintext");
		return XLAT_ACTION_FAIL;
	}
	plaintext = (*in)->vb_strvalue;
	plaintext_len = (*in)->vb_length;

	/*
	 *	Figure out the buffer we need
	 */
	RHEXDUMP3((uint8_t const *)plaintext, plaintext_len, "Plaintext (%zu bytes)", plaintext_len);
	if (EVP_PKEY_encrypt(xt->evp_encrypt_ctx, NULL, &ciphertext_len,
			     (unsigned char const *)plaintext, plaintext_len) <= 0) {
		fr_tls_log_error(request, "Failed getting length of encrypted plaintext");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_mem_alloc(vb, &ciphertext, vb, NULL, ciphertext_len, false) == 0);
	if (EVP_PKEY_encrypt(xt->evp_encrypt_ctx, ciphertext, &ciphertext_len,
			     (unsigned char const *)plaintext, plaintext_len) <= 0) {
		fr_tls_log_error(request, "Failed encrypting plaintext");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}
	RHEXDUMP3(ciphertext, ciphertext_len, "Ciphertext (%zu bytes)", ciphertext_len);
	MEM(fr_value_box_mem_realloc(vb, NULL, vb, ciphertext_len) == 0);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Sign input data
 *
 * Arguments are @verbatim(<plaintext>...)@endverbatim
 *
@verbatim
%{<inst>_sign:<plaintext>...}
@endverbatim
 *
 * If multiple arguments are provided they will be concatenated.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t cipher_rsa_sign_xlat(TALLOC_CTX *ctx, fr_cursor_t *out,
					  REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
					  fr_value_box_t **in)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort_const(*((void const * const *)xlat_inst),
									    rlm_cipher_t);
	rlm_cipher_rsa_thread_inst_t	*xt = talloc_get_type_abort(*((void **)xlat_thread_inst),
								    rlm_cipher_rsa_thread_inst_t);

	char const			*msg;
	size_t				msg_len;

	uint8_t				*sig;
	size_t				sig_len;

	unsigned int			digest_len = 0;

	fr_value_box_t			*vb;

	if (!*in) {
		REDEBUG("sign requires one or arguments (<plaintext>...)");
		return XLAT_ACTION_FAIL;
	}

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		REDEBUG("Failed concatenating arguments to form plaintext");
		return XLAT_ACTION_FAIL;
	}
	msg = (*in)->vb_strvalue;
	msg_len = (*in)->vb_length;

	/*
	 *	First produce a digest of the message
	 */
	if (unlikely(EVP_DigestInit_ex(xt->evp_md_ctx, inst->rsa->sig_digest, NULL) <= 0)) {
		fr_tls_log_error(request, "Failed initialising message digest");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestUpdate(xt->evp_md_ctx, msg, msg_len) <= 0) {
		fr_tls_log_error(request, "Failed ingesting message");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestFinal_ex(xt->evp_md_ctx, xt->digest_buff, &digest_len) <= 0) {
		fr_tls_log_error(request, "Failed finalising message digest");
		return XLAT_ACTION_FAIL;
	}
	fr_assert((size_t)digest_len == talloc_array_length(xt->digest_buff));

	/*
	 *	Then sign the digest
	 */
	if (EVP_PKEY_sign(xt->evp_sign_ctx, NULL, &sig_len, xt->digest_buff, (size_t)digest_len) <= 0) {
		fr_tls_log_error(request, "Failed getting length of digest");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_mem_alloc(vb, &sig, vb, NULL, sig_len, false) == 0);
	if (EVP_PKEY_sign(xt->evp_sign_ctx, sig, &sig_len, xt->digest_buff, (size_t)digest_len) <= 0) {
		fr_tls_log_error(request, "Failed signing message digest");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}
	MEM(fr_value_box_mem_realloc(vb, NULL, vb, sig_len) == 0);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Decrypt input data
 *
 * Arguments are @verbatim(<ciphertext\>...)@endverbatim
 *
@verbatim
%{<inst>_decrypt:<ciphertext>...}
@endverbatim
 *
 * If multiple arguments are provided they will be concatenated.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t cipher_rsa_decrypt_xlat(TALLOC_CTX *ctx, fr_cursor_t *out,
					     REQUEST *request, UNUSED void const *xlat_inst, void *xlat_thread_inst,
					     fr_value_box_t **in)
{
	rlm_cipher_rsa_thread_inst_t	*xt = talloc_get_type_abort(*((void **)xlat_thread_inst),
								    rlm_cipher_rsa_thread_inst_t);

	uint8_t	const			*ciphertext;
	size_t				ciphertext_len;

	char				*plaintext;
	size_t				plaintext_len;

	fr_value_box_t			*vb;

	if (!*in) {
		REDEBUG("decrypt requires one or more arguments (<ciphertext>...)");
		return XLAT_ACTION_FAIL;
	}

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_OCTETS, true) < 0) {
		REDEBUG("Failed concatenating arguments to form plaintext");
		return XLAT_ACTION_FAIL;
	}
	ciphertext = (*in)->vb_octets;
	ciphertext_len = (*in)->vb_length;

	/*
	 *	Decrypt the ciphertext
	 */
	RHEXDUMP3(ciphertext, ciphertext_len, "Ciphertext (%zu bytes)", ciphertext_len);
	if (EVP_PKEY_decrypt(xt->evp_decrypt_ctx, NULL, &plaintext_len, ciphertext, ciphertext_len) <= 0) {
		fr_tls_log_error(request, "Failed getting length of cleartext");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	MEM(fr_value_box_bstr_alloc(vb, &plaintext, vb, NULL, plaintext_len, true) == 0);
	if (EVP_PKEY_decrypt(xt->evp_decrypt_ctx, (unsigned char *)plaintext, &plaintext_len,
			     ciphertext, ciphertext_len) <= 0) {
		fr_tls_log_error(request, "Failed decrypting ciphertext");
		talloc_free(vb);
		return XLAT_ACTION_FAIL;
	}
	RHEXDUMP3((uint8_t const *)plaintext, plaintext_len, "Plaintext (%zu bytes)", plaintext_len);
	MEM(fr_value_box_bstr_realloc(vb, NULL, vb, plaintext_len) == 0);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Verify input data
 *
 * Arguments are @verbatim(<signature>, <plaintext>...)@endverbatim
 *
@verbatim
%{<inst>_verify:<signature> <plaintext>...}
@endverbatim
 *
 * If multiple arguments are provided (after @verbatim<signature>@endverbatim)
 * they will be concatenated.
 *
 * @ingroup xlat_functions
 */
static xlat_action_t cipher_rsa_verify_xlat(TALLOC_CTX *ctx, fr_cursor_t *out,
					    REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
					    fr_value_box_t **in)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort_const(*((void const * const *)xlat_inst),
									    rlm_cipher_t);
	rlm_cipher_rsa_thread_inst_t	*xt = talloc_get_type_abort(*((void **)xlat_thread_inst),
								    rlm_cipher_rsa_thread_inst_t);

	uint8_t	const			*sig;
	size_t				sig_len;

	char const			*msg;
	size_t				msg_len;

	unsigned int			digest_len = 0;

	fr_value_box_t			*vb;

	if (!*in) {
		REDEBUG("verification requires two or more arguments (<signature>, <message>...)");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Check we have at least two boxed values
	 */
	if (!(*in)->next) {
		REDEBUG("Missing message data arg or message data was (null)");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Don't auto-cast to octets if the signature
	 *	isn't already in that form.
	 *	It could be hexits or base64 or some other encoding.
	 */
	if ((*in)->type != FR_TYPE_OCTETS) {
		REDEBUG("Signature argument wrong type, expected %s, got %s.  "
			"Use %%{base64_decode:<text>} or %%{hex_decode:<text>} if signature is armoured",
			fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_OCTETS, "?Unknown?"),
			fr_table_str_by_value(fr_value_box_type_table, (*in)->type, "?Unknown?"));
		return XLAT_ACTION_FAIL;
	}
	sig = (*in)->vb_octets;
	sig_len = (*in)->vb_length;

	/*
	 *	Concat (...) args to get message data
	 */
	if (fr_value_box_list_concat(ctx, (*in)->next, &((*in)->next), FR_TYPE_STRING, true) < 0) {
		REDEBUG("Failed concatenating arguments to form plaintext");
		return XLAT_ACTION_FAIL;
	}
	msg = (*in)->next->vb_strvalue;
	msg_len = (*in)->next->vb_length;

	/*
	 *	The argument separator also gets rolled into
	 *	the concatenate buffer... We should probably
	 *	figure out a cleaner way of doing this.
	 */
	if (*msg != ' ') {
		REDEBUG("Expected whitespace argument separator");
		return XLAT_ACTION_FAIL;
	}
	msg++;
	msg_len--;

	if (msg_len == 0) {
		REDEBUG("Zero length message data");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	First produce a digest of the message
	 */
	if (unlikely(EVP_DigestInit_ex(xt->evp_md_ctx, inst->rsa->sig_digest, NULL) <= 0)) {
		fr_tls_log_error(request, "Failed initialising message digest");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestUpdate(xt->evp_md_ctx, msg, msg_len) <= 0) {
		fr_tls_log_error(request, "Failed ingesting message");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestFinal_ex(xt->evp_md_ctx, xt->digest_buff, &digest_len) <= 0) {
		fr_tls_log_error(request, "Failed finalising message digest");
		return XLAT_ACTION_FAIL;
	}
	fr_assert((size_t)digest_len == talloc_array_length(xt->digest_buff));

	/*
	 *	Now check the signature matches what we expected
	 */
	switch (EVP_PKEY_verify(xt->evp_verify_ctx, sig, sig_len, xt->digest_buff, (size_t)digest_len)) {
	case 1:		/* success (signature valid) */
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, false));
		vb->vb_bool = true;
		fr_cursor_append(out, vb);
		break;

	case 0:		/* failure (signature not valid) */
		MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL, false));
		vb->vb_bool = false;
		fr_cursor_append(out, vb);
		break;

	default:
		fr_tls_log_error(request, "Failed validating signature");
		return XLAT_ACTION_FAIL;
	}

	return XLAT_ACTION_DONE;
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

/** Boilerplate to copy the pointer to the main module thread instance into xlat thread instance data
 *
 */
static int cipher_xlat_thread_instantiate(UNUSED void *xlat_inst, void *xlat_thread_inst,
					  UNUSED xlat_exp_t const *exp, void *uctx)
{
	rlm_cipher_t			*inst = talloc_get_type_abort(uctx, rlm_cipher_t);

	*((rlm_cipher_rsa_thread_inst_t **)xlat_thread_inst) =
		talloc_get_type_abort(module_thread_by_data(inst)->data, rlm_cipher_rsa_thread_inst_t);

	return 0;
}

/** Boilerplate to copy the pointer to the main module config into the xlat instance data
 *
 */
static int cipher_xlat_instantiate(void *xlat_inst, UNUSED xlat_exp_t const *exp, void *uctx)
{
	*((rlm_cipher_t **)xlat_inst) = talloc_get_type_abort(uctx, rlm_cipher_t);

	return 0;
}

static int cipher_rsa_padding_params_set(EVP_PKEY_CTX *evp_pkey_ctx, cipher_rsa_t const *rsa_inst)
{
	if (unlikely(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, rsa_inst->padding)) <= 0) {
		tls_strerror_printf(NULL);
		PERROR("%s: Failed setting RSA padding type", __FUNCTION__);
		return -1;
	}

	switch (rsa_inst->padding) {
	case RSA_NO_PADDING:
	case RSA_X931_PADDING:
	case RSA_SSLV23_PADDING:
	case RSA_PKCS1_PADDING:
		return 0;

	/*
	 *	Configure OAEP advanced padding options
	 */
	case RSA_PKCS1_OAEP_PADDING:
		if (unlikely(EVP_PKEY_CTX_set_rsa_oaep_md(evp_pkey_ctx, rsa_inst->oaep->oaep_digest) <= 0)) {
			tls_strerror_printf(NULL);
			PERROR("%s: Failed setting OAEP digest", __FUNCTION__);
			return -1;
		}

		if (unlikely(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_ctx, rsa_inst->oaep->mgf1_digest) <= 0)) {
			tls_strerror_printf(NULL);
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
	   			tls_strerror_printf(NULL);
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
static int cipher_rsa_thread_instantiate(UNUSED CONF_SECTION const *conf, void *instance,
					 UNUSED fr_event_list_t *el, void *thread)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort(instance, rlm_cipher_t);
	rlm_cipher_rsa_thread_inst_t	*ti = thread;

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
			tls_strerror_printf(NULL);
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
			tls_strerror_printf(NULL);
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
			tls_strerror_printf(NULL);
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
			tls_strerror_printf(NULL);
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
			tls_strerror_printf(NULL);
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
			tls_strerror_printf(NULL);
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
			tls_strerror_printf(NULL);
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
			tls_strerror_printf(NULL);
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
			tls_strerror_printf(NULL);
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
			tls_strerror_printf(NULL);
			PERROR("%s: Failed setting signature digest type", __FUNCTION__);
			return XLAT_ACTION_FAIL;
		}

		/*
		 *	Alloc digest ctx for signing and verification
		 */
		ti->evp_md_ctx = EVP_MD_CTX_create();
		if (!ti->evp_md_ctx) {
			tls_strerror_printf(NULL);
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

static int mod_thread_instantiate(CONF_SECTION const *conf, void *instance,
				  fr_event_list_t *el, void *thread)
{
	rlm_cipher_t	*inst = talloc_get_type_abort(instance, rlm_cipher_t);

	switch (inst->type) {
	case RLM_CIPHER_TYPE_RSA:
		talloc_set_type(thread, rlm_cipher_rsa_thread_inst_t);
		return cipher_rsa_thread_instantiate(conf, instance, el, thread);

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
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_cipher_t	*inst = talloc_get_type_abort(instance, rlm_cipher_t);

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) inst->xlat_name = cf_section_name1(conf);

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
			char *decrypt_name;
			char *verify_name;
			xlat_t const *xlat;

			/*
			 *	Register decrypt xlat
			 */
			decrypt_name = talloc_asprintf(inst, "%s_decrypt", inst->xlat_name);
			xlat = xlat_async_register(inst, decrypt_name, cipher_rsa_decrypt_xlat);
			xlat_async_instantiate_set(xlat, cipher_xlat_instantiate,
						   rlm_cipher_t *,
						   NULL,
						   inst);
			xlat_async_thread_instantiate_set(xlat,
							  cipher_xlat_thread_instantiate,
							  rlm_cipher_rsa_thread_inst_t *,
							  NULL,
							  inst);
			talloc_free(decrypt_name);

			/*
			 *	Verify sign xlat
			 */
			verify_name = talloc_asprintf(inst, "%s_verify", inst->xlat_name);
			xlat = xlat_async_register(inst, verify_name, cipher_rsa_verify_xlat);
			xlat_async_instantiate_set(xlat, cipher_xlat_instantiate,
						   rlm_cipher_t *,
						   NULL,
						   inst);
			xlat_async_thread_instantiate_set(xlat,
							  cipher_xlat_thread_instantiate,
							  rlm_cipher_rsa_thread_inst_t *,
							  NULL,
							  inst);
			talloc_free(verify_name);
		}

		if (inst->rsa->certificate_file) {
			char *encrypt_name;
			char *sign_name;
			xlat_t const *xlat;

			/*
			 *	Register encrypt xlat
			 */
			encrypt_name = talloc_asprintf(inst, "%s_encrypt", inst->xlat_name);
			xlat = xlat_async_register(inst, encrypt_name, cipher_rsa_encrypt_xlat);
			xlat_async_instantiate_set(xlat, cipher_xlat_instantiate,
						   rlm_cipher_t *,
						   NULL,
						   inst);
			xlat_async_thread_instantiate_set(xlat, cipher_xlat_thread_instantiate,
							  rlm_cipher_rsa_thread_inst_t *,
							  NULL,
							  inst);
			talloc_free(encrypt_name);

			/*
			 *	Register sign xlat
			 */
			sign_name = talloc_asprintf(inst, "%s_sign", inst->xlat_name);
			xlat = xlat_async_register(inst, sign_name, cipher_rsa_sign_xlat);
			xlat_async_instantiate_set(xlat, cipher_xlat_instantiate,
						   rlm_cipher_t *,
						   NULL,
						   inst);
			xlat_async_thread_instantiate_set(xlat, cipher_xlat_thread_instantiate,
							  rlm_cipher_rsa_thread_inst_t *,
							  NULL,
							  inst);
			talloc_free(sign_name);
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
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_cipher;
module_t rlm_cipher = {
	.magic			= RLM_MODULE_INIT,
	.name			= "cipher",
	.type			= RLM_TYPE_THREAD_SAFE,
	.inst_size		= sizeof(rlm_cipher_t),
	.thread_inst_size	= sizeof(rlm_cipher_rsa_thread_inst_t),
	.config			= module_config,
	.bootstrap		= mod_bootstrap,
	.thread_instantiate	= mod_thread_instantiate,
};
