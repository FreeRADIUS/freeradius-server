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
 * @author Arran Cudbard-Bell \<a.cudbardb@freeradius.org\>
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Network RADIUS \<info@networkradius.com\>
 *
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

static int digest_type_parse(UNUSED TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);
static int cipher_rsa_padding_type_parse(UNUSED TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);
static int cipher_type_parse(UNUSED TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

static int cipher_rsa_private_key_file_load(UNUSED TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);
static int cipher_rsa_certificate_file_load(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

typedef enum {
	RLM_CIPHER_TYPE_INVALID = 0,
	RLM_CIPHER_TYPE_RSA = 1,
} cipher_type_t;

/** The type of padding used
 *
 */
const FR_NAME_NUMBER cipher_rsa_padding[] = {
	{ "none",	RSA_NO_PADDING		},
	{ "pkcs",	RSA_PKCS1_PADDING	},		/* PKCS 1.5 */
	{ "oaep",	RSA_PKCS1_OAEP_PADDING	},		/* PKCS OAEP padding */
	{ "x931",	RSA_X931_PADDING	},
	{ "ssl",	RSA_SSLV23_PADDING	},

	{ NULL, 0				},
};

const FR_NAME_NUMBER cipher_type[] = {
	{ "rsa",	RLM_CIPHER_TYPE_RSA	},

	{ NULL, 0				}
};

typedef struct {
	EVP_PKEY_CTX		*evp_pkey_ctx;			//!< Pre-allocated evp_pkey_ctx.
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
								///< and additional keying labeleter.
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
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	EVP_MD representing the OpenSSL digest type.
 * @param[in] ci	#CONF_PAIR specifying the name of the digest.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int digest_type_parse(UNUSED TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
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
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Padding type.
 * @param[in] ci	#CONF_PAIR specifying the padding type..
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int cipher_rsa_padding_type_parse(UNUSED TALLOC_CTX *ctx, void *out, CONF_ITEM *ci,
					 UNUSED CONF_PARSER const *rule)
{
	int		type;
	char const	*type_str;

	type_str = cf_pair_value(cf_item_to_pair(ci));
	type = fr_str2int(cipher_rsa_padding, type_str, -1);
	if (type == -1) {
		cf_log_err(ci, "Invalid padding type \"%s\"", type_str);
		return -1;
	}

	*((int *)out) = type;

	return 0;
}

/** Checks if the specified cipher type is valid
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Cipher enumeration type.
 * @param[in] ci	#CONF_PAIR specifying the name of the type module.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int cipher_type_parse(UNUSED TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	cipher_type_t	type;
	char const	*type_str;

	type_str = cf_pair_value(cf_item_to_pair(ci));
	type = fr_str2int(cipher_type, type_str, RLM_CIPHER_TYPE_INVALID);
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
 * @param[in] num	The length of buf.
 * @param[in] rwflag
 *			- 0 if password used for decryption.
 *			- 1 if password used for encryption.
 * @param[in] userdata	The static password.
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
 * @param[in] ci	Config item containing the certificate path.
 * @param[in] rule	this callback was attached to.
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 */
static int cipher_rsa_private_key_file_load(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci,
					    UNUSED CONF_PARSER const *rule)
{
	FILE		*fp;
	char const	*filename;
	cipher_rsa_t	*rsa_inst = talloc_get_type_abort(ctx, cipher_rsa_t);	/* Yeah this is a bit hacky */
	EVP_PKEY	*pkey;
	void		*pass;

	filename = cf_pair_value(cf_item_to_pair(ci));

	fp = fopen(filename, "r");
	if (!fp) {
		cf_log_err(ci, "Failed opening file: %s", fr_syserror(errno));
		return -1;
	}

	memcpy(&pass, &rsa_inst->private_key_password, sizeof(pass));

	pkey = PEM_read_PrivateKey(fp, (EVP_PKEY **)out, _get_private_key_password, pass);
	fclose(fp);

	if (!pkey) {
		tls_strerror_printf(true, NULL);
		cf_log_perr(ci, "Error loading private certificate file \"%s\"", filename);

		return -1;
	}

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
 * @param[in] ci	Config item containing the certificate path.
 * @param[in] rule	this callback was attached to.
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 */
static int cipher_rsa_certificate_file_load(UNUSED TALLOC_CTX *ctx, void *out, CONF_ITEM *ci,
					    UNUSED CONF_PARSER const *rule)
{
	FILE		*fp;
	char const	*filename;
	EVP_PKEY	*pkey;

	filename = cf_pair_value(cf_item_to_pair(ci));

	fp = fopen(filename, "r");
	if (!fp) {
		cf_log_err(ci, "Failed opening file: %s", fr_syserror(errno));
		return -1;
	}

	pkey = PEM_read_PUBKEY(fp, (EVP_PKEY **)out, NULL, NULL);
	fclose(fp);

	if (!pkey) {
		tls_strerror_printf(true, NULL);
		cf_log_perr(ci, "Error loading certificate file \"%s\"", filename);

		return -1;
	}

	(void)talloc_steal(ctx, pkey);			/* Bind lifetime to config */
	talloc_set_destructor(pkey, _evp_pkey_free);	/* Free pkey correctly on chunk free */

	return 0;
}

static int cipher_rsa_padding_params_set(REQUEST *request, EVP_PKEY_CTX *evp_pkey_ctx, cipher_rsa_t const *rsa_inst)
{

	if (unlikely(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ctx, rsa_inst->padding)) <= 0) {
		tls_log_error(request, "Failed setting RSA padding type");
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
/*
		if (unlikely(EVP_PKEY_CTX_set_rsa_oaep_md(evp_pkey_ctx, rsa_inst->oaep->oaep_digest) <= 0)) {
			tls_log_error(request, "Failed setting OAEP digest");
			return -1;
		}

		if (unlikely(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_ctx, rsa_inst->oaep->mgf1_digest) <= 0)) {
			tls_log_error(request, "Failed setting MGF1 digest");
			return -1;
		}

		if (rsa_inst->oaep->label) {
			char *label;

			memcpy(&label, &rsa_inst->oaep->label, sizeof(label));

		    	if (unlikely(EVP_PKEY_CTX_set0_rsa_oaep_label(evp_pkey_ctx, label,
								      talloc_array_length(label) - 1) <= 0)) {
				tls_log_error(request, "Failed setting OAEP padding label");
				return -1;
			}
		}
*/
		return 0;

	default:
		rad_assert(0);
		return -1;
	}
}

/** Encrypt input data
 *
 * Arguments are (<plaintext>...).
 *
 * If multiple arguments are provided they will be concatenated.
 */
static xlat_action_t cipher_rsa_encrypt_xlat(TALLOC_CTX *ctx, fr_cursor_t *out,
					     REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
					     fr_value_box_t **in)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort(*((void const * const *)xlat_inst), rlm_cipher_t);
	rlm_cipher_rsa_thread_inst_t	*xt = talloc_get_type_abort(*((void const * const *)xlat_thread_inst),
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
		tls_log_error(request, "Failed concatenating arguments to form plaintext");
		return XLAT_ACTION_FAIL;
	}
	plaintext = (*in)->vb_strvalue;
	plaintext_len = (*in)->vb_length;

	if (unlikely(EVP_PKEY_encrypt_init(xt->evp_pkey_ctx) <= 0)) {
		tls_log_error(request, "Failed initialising EVP_PKEY_CTX");
		return XLAT_ACTION_FAIL;
	}

	if (unlikely(cipher_rsa_padding_params_set(request, xt->evp_pkey_ctx, inst->rsa) < 0)) return XLAT_ACTION_FAIL;

	/*
	 *	Figure out the buffer we need
	 */
	if (EVP_PKEY_encrypt(xt->evp_pkey_ctx, NULL, &ciphertext_len,
			     (unsigned char const *)plaintext, plaintext_len) <= 0) {
		tls_log_error(request, "Failed encrypting plaintext");
		return XLAT_ACTION_FAIL;
	}

	MEM(ciphertext = talloc_array(ctx, uint8_t, ciphertext_len));
	if (EVP_PKEY_encrypt(xt->evp_pkey_ctx, ciphertext, &ciphertext_len,
			     (unsigned char const *)plaintext, plaintext_len) <= 0) {
		tls_log_error(request, "Failed encrypting plaintext");
		return XLAT_ACTION_FAIL;
	}

	if (ciphertext_len != talloc_array_length(ciphertext)) {
		uint8_t *n;

		n = talloc_realloc_size(ctx, ciphertext, ciphertext_len);
		if (unlikely(!n)) {
			REDEBUG("Failed shrinking ciphertext buffer");
			talloc_free(ciphertext);
			return XLAT_ACTION_FAIL;
		}
		talloc_set_type(n, uint8_t);

		ciphertext = n;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memsteal(vb, vb, NULL, ciphertext, false);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Sign input data
 *
 * Arguments are (<plaintext>...).
 *
 * If multiple arguments are provided they will be concatenated.
 */
static xlat_action_t cipher_rsa_sign_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_cursor_t *out,
					  REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
					  fr_value_box_t **in)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort(*((void const * const *)xlat_inst), rlm_cipher_t);
	rlm_cipher_rsa_thread_inst_t	*xt = talloc_get_type_abort(*((void const * const *)xlat_thread_inst),
								    rlm_cipher_rsa_thread_inst_t);

	char const			*msg;
	size_t				msg_len;

	uint8_t				*sig;
	size_t				sig_len;

	size_t				digest_len;

	fr_value_box_t			*vb;

	if (!*in) {
		REDEBUG("sign requires one or arguments (<plaintext>...)");
		return XLAT_ACTION_FAIL;
	}

	if (fr_value_box_list_concat(ctx, *in, in, FR_TYPE_STRING, true) < 0) {
		REDEBUG("Failed concatenating arguments to form plaintext");
		return XLAT_ACTION_FAIL;
	}
	msg = (*in)->next->vb_strvalue;
	msg_len = (*in)->vb_length;

	if (unlikely(EVP_PKEY_sign_init(xt->evp_pkey_ctx) <= 0)) {
		tls_log_error(request, "Failed initialising EVP_PKEY_CTX");
		return XLAT_ACTION_FAIL;
	}

	if (unlikely(cipher_rsa_padding_params_set(request, xt->evp_pkey_ctx, inst->rsa) < 0)) return XLAT_ACTION_FAIL;
	if (unlikely(EVP_PKEY_CTX_set_signature_md(xt->evp_pkey_ctx, inst->rsa->sig_digest)) <= 0) {
		tls_log_error(request, "Failed setting signature digest type");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	First produce a digest of the message
	 */
	if (unlikely(EVP_DigestInit(xt->evp_md_ctx, inst->rsa->sig_digest) <= 0)) {
		tls_log_error(request, "Failed initialising message digest");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestUpdate(xt->evp_md_ctx, msg, msg_len) <= 0) {
		tls_log_error(request, "Failed ingesting message");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestFinal(xt->evp_md_ctx, xt->digest_buff, (unsigned int *)&digest_len) <= 0) {
		tls_log_error(request, "Failed finalising message digest");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Then sign the digest
	 */
	if (EVP_PKEY_sign(ctx, NULL, &sig_len, xt->digest_buff, digest_len) <= 0) {
		tls_log_error(request, "Failed signing message digest");
		return XLAT_ACTION_FAIL;
	}

	MEM(sig = talloc_array(ctx, uint8_t, sig_len));
	if (EVP_PKEY_sign(ctx, sig, &sig_len, xt->digest_buff, digest_len) <= 0) {
		tls_log_error(request, "Failed signing message digest");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Fixup the output buffer
	 */
	if (sig_len != talloc_array_length(sig)) {
		uint8_t *n;

		n = talloc_realloc_size(ctx, sig, sig_len);
		if (unlikely(!n)) {
			REDEBUG("Failed shrinking signature buffer");
			talloc_free(sig);
			return XLAT_ACTION_FAIL;
		}
		talloc_set_type(n, uint8_t);

		sig = n;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_memsteal(vb, vb, NULL, sig, false);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Decrypt input data
 *
 * Arguments are (<ciphertext>...).
 *
 * If multiple arguments are provided they will be concatenated.
 */
static xlat_action_t cipher_rsa_decrypt_xlat(TALLOC_CTX *ctx, UNUSED fr_cursor_t *out,
					     REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
					     fr_value_box_t **in)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort(*((void const * const *)xlat_inst), rlm_cipher_t);
	rlm_cipher_rsa_thread_inst_t	*xt = talloc_get_type_abort(*((void const * const *)xlat_thread_inst),
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

	if (unlikely(EVP_PKEY_decrypt_init(xt->evp_pkey_ctx) <= 0)) {
		tls_log_error(request, "Failed initialising EVP_PKEY_CTX");
		return XLAT_ACTION_FAIL;
	}

	if (unlikely(cipher_rsa_padding_params_set(request, xt->evp_pkey_ctx, inst->rsa) < 0)) return XLAT_ACTION_FAIL;

	/*
	 *	Decrypt the plaintext
	 */
	if (EVP_PKEY_decrypt(ctx, NULL, &plaintext_len, ciphertext, ciphertext_len) <= 0) {
		tls_log_error(request, "Failed decrypting ciphertext");
		return XLAT_ACTION_FAIL;
	}

	MEM(plaintext = talloc_array(ctx, char, plaintext_len + 1));
	if (EVP_PKEY_decrypt(ctx, (unsigned char *)plaintext, &plaintext_len, ciphertext, ciphertext_len) <= 0) {
		tls_log_error(request, "Failed decrypting ciphertext");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Fixup the output buffer (and ensure it's \0 terminated)
	 */
	{
		char *n;

		n = talloc_realloc_bstr(plaintext, plaintext_len);
		if (unlikely(!n)) {
			REDEBUG("Failed shrinking plaintext buffer");
			talloc_free(plaintext);
			return XLAT_ACTION_FAIL;
		}

		plaintext = n;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_strsteal(vb, vb, NULL, plaintext, false);
	fr_cursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Verify input data
 *
 * Arguments are (<signature>, <plaintext>...).
 *
 * If multiple arguments are provided (after <signature>) they will be concatenated.
 */
static xlat_action_t cipher_rsa_verify_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_cursor_t *out,
					    REQUEST *request, void const *xlat_inst, void *xlat_thread_inst,
					    fr_value_box_t **in)
{
	rlm_cipher_t const		*inst = talloc_get_type_abort(*((void const * const *)xlat_inst), rlm_cipher_t);
	rlm_cipher_rsa_thread_inst_t	*xt = talloc_get_type_abort(*((void const * const *)xlat_thread_inst),
								    rlm_cipher_rsa_thread_inst_t);

	uint8_t	const			*sig;
	size_t				sig_len;

	char const			*msg;
	size_t				msg_len;

	size_t				digest_len;

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
			fr_int2str(dict_attr_types, FR_TYPE_OCTETS, "?Unknown?"),
			fr_int2str(dict_attr_types, (*in)->type, "?Unknown?"));
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

	if (unlikely(EVP_PKEY_verify_init(xt->evp_pkey_ctx) <= 0)) {
		tls_log_error(request, "Failed initialising EVP_PKEY_CTX");
		return XLAT_ACTION_FAIL;
	}

	if (unlikely(cipher_rsa_padding_params_set(request, xt->evp_pkey_ctx, inst->rsa) < 0)) return XLAT_ACTION_FAIL;
	if (unlikely(EVP_PKEY_CTX_set_signature_md(xt->evp_pkey_ctx, inst->rsa->sig_digest)) <= 0) {
		tls_log_error(request, "Failed setting signature digest type");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	First produce a digest of the message
	 */
	if (unlikely(EVP_DigestInit(xt->evp_md_ctx, inst->rsa->sig_digest) <= 0)) {
		tls_log_error(request, "Failed initialising message digest");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestUpdate(xt->evp_md_ctx, msg, msg_len) <= 0) {
		tls_log_error(request, "Failed ingesting message");
		return XLAT_ACTION_FAIL;
	}

	if (EVP_DigestFinal(xt->evp_md_ctx, xt->digest_buff, (unsigned int *)&digest_len) <= 0) {
		tls_log_error(request, "Failed finalising message digest");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Now check the signature matches what we expected
	 */
	switch (EVP_PKEY_verify(ctx, sig, sig_len, xt->digest_buff, digest_len)) {
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
		tls_log_error(request, "Failed validating signature");
		return XLAT_ACTION_FAIL;
	}

	return XLAT_ACTION_DONE;
}

/** Talloc destructor for freeing an EVP_PKEY_CTX
 *
 * @param[in] pkey	to free.
 * @return 0
 */
static int _evp_pkey_ctx_free(EVP_PKEY_CTX *evp_pkey_ctx)
{
	EVP_PKEY_CTX_free(evp_pkey_ctx);

	return 0;
}

/** Talloc destructor for freeing an EVP_MD_CTX
 *
 * @param[in] pkey	to free.
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
		talloc_get_type_abort(module_thread_instance_by_data(inst), rlm_cipher_rsa_thread_inst_t);

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
	rlm_cipher_rsa_thread_inst_t	*ti = talloc_get_type_abort(thread, rlm_cipher_rsa_thread_inst_t);

	ti->evp_pkey_ctx = EVP_PKEY_CTX_new(inst->rsa->certificate_file, NULL);
	if (!ti->evp_pkey_ctx) {
		tls_strerror_printf(true, NULL);
		PERROR("%s: Failed allocating EVP_PKEY_CTX", __FUNCTION__);
		return -1;
	}

	ti->evp_pkey_ctx = talloc_steal(ti, ti->evp_pkey_ctx);	/* Bind lifetime to instance */
	talloc_set_destructor(ti->evp_pkey_ctx, _evp_pkey_ctx_free);	/* Free ctx correctly on chunk free */

	ti->evp_md_ctx = EVP_MD_CTX_create();
	if (!ti->evp_md_ctx) {
		tls_strerror_printf(true, NULL);
		PERROR("%s: Failed allocating EVP_MD_CTX", __FUNCTION__);
		return -1;
	}

	ti->evp_md_ctx = talloc_steal(ti, ti->evp_md_ctx);		/* Bind lifetime to instance */
	talloc_set_destructor(ti->evp_md_ctx, _evp_md_ctx_free);		/* Free ctx correctly on chunk free */

	MEM(ti->digest_buff = talloc_array(ti, uint8_t, EVP_MD_size(inst->rsa->sig_digest)));

	return 0;
}

static int mod_thread_instantiate(CONF_SECTION const *conf, void *instance,
				  fr_event_list_t *el, void *thread)
{
	rlm_cipher_t	*inst = talloc_get_type_abort(instance, rlm_cipher_t);

	switch (inst->type) {
	case RLM_CIPHER_TYPE_RSA:
		return cipher_rsa_thread_instantiate(conf, instance, el, thread);

	case RLM_CIPHER_TYPE_INVALID:
		rad_assert(0);
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

			decrypt_name = talloc_asprintf(inst, "%s_decrypt", inst->xlat_name);
			verify_name = talloc_asprintf(inst, "%s_verify", inst->xlat_name);

			xlat_async_register(inst, decrypt_name, cipher_rsa_decrypt_xlat,
				    	    cipher_xlat_instantiate, rlm_cipher_t *, NULL,
				    	    cipher_xlat_thread_instantiate, rlm_cipher_rsa_thread_inst_t *,
				    	    NULL, inst);

			xlat_async_register(inst, verify_name, cipher_rsa_verify_xlat,
					    cipher_xlat_instantiate, rlm_cipher_t *, NULL,
					    cipher_xlat_thread_instantiate, rlm_cipher_rsa_thread_inst_t *,
					    NULL, inst);

			talloc_free(decrypt_name);
			talloc_free(verify_name);
		}

		if (inst->rsa->certificate_file) {
			char *encrypt_name;
			char *sign_name;

			encrypt_name = talloc_asprintf(inst, "%s_encrypt", inst->xlat_name);
			sign_name = talloc_asprintf(inst, "%s_sign", inst->xlat_name);

			xlat_async_register(inst, encrypt_name, cipher_rsa_encrypt_xlat,
				    	    cipher_xlat_instantiate, rlm_cipher_t *, NULL,
				    	    cipher_xlat_thread_instantiate, rlm_cipher_rsa_thread_inst_t *,
				    	    NULL, inst);
			xlat_async_register(inst, sign_name, cipher_rsa_sign_xlat,
				    	    cipher_xlat_instantiate, rlm_cipher_t *, NULL,
				    	    cipher_xlat_thread_instantiate, rlm_cipher_rsa_thread_inst_t *,
				    	    NULL, inst);

			talloc_free(encrypt_name);
			talloc_free(sign_name);
		}
		break;

	/*
	 *	Populated by cipher_type_parse() so if
	 *	the value is unrecognised we've got an issue.
	 */
	default:
		rad_assert(0);
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
extern rad_module_t rlm_cipher;
rad_module_t rlm_cipher = {
	.magic			= RLM_MODULE_INIT,
	.name			= "cipher",
	.type			= RLM_TYPE_THREAD_SAFE,
	.inst_size		= sizeof(rlm_cipher_t),
	.config			= module_config,
	.bootstrap		= mod_bootstrap,
	.thread_instantiate	= mod_thread_instantiate,
};
