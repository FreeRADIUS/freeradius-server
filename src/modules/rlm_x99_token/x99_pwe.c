/*
 * x99_pwe.c
 * $Id$
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  Google, Inc.
 */

/*
 * This file implements password checking functions for each supported
 * encoding (PAP, CHAP, etc.).  It is expected to be temporary until a
 * libradius modular interface can be created.  The current libradius
 * interface is not sufficient for x9.9 use.
 */

#include "autoconf.h"
#include "libradius.h"
#include "x99.h"
#include "x99_pwe.h"

#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

static const char rcsid[] = "$Id$";


/* Attribute IDs for supported password encodings. */
static int pwattr[8];


/* Initialize the pwattr array for supported password encodings. */
void
x99_pwe_init(void)
{
    DICT_ATTR *da;
    int i = 0;

    /*
     * Setup known password types.  These are pairs.
     * NB: Increase pwattr array size when adding a type.
     *     It should be sized as (number of password types * 2)
     * This is temporary until this code becomes modular.
     */
    memset(pwattr, 0, sizeof(pwattr));

    /* PAP */
    if ((da = dict_attrbyname("User-Password")) != NULL) {
	pwattr[i++] = da->attr;
	pwattr[i++] = da->attr;
    }

    /* CHAP */
    if ((da = dict_attrbyname("CHAP-Challenge")) != NULL) {
	pwattr[i++] = da->attr;
	if ((da = dict_attrbyname("CHAP-Password")) != NULL)
	    pwattr[i++] = da->attr;
	else
	    pwattr[--i] = 0;
    }

#if 0
    /* MS-CHAP (recommended not to use) */
    if ((da = dict_attrbyname("MS-CHAP-Challenge")) != NULL) {
	pwattr[i++] = da->attr;
	if ((da = dict_attrbyname("MS-CHAP-Response")) != NULL)
	    pwattr[i++] = da->attr;
	else
	    pwattr[--i] = 0;
    }
#endif /* 0 */

    /* MS-CHAPv2 */
    if ((da = dict_attrbyname("MS-CHAP-Challenge")) != NULL) {
	pwattr[i++] = da->attr;
	if ((da = dict_attrbyname("MS-CHAP2-Response")) != NULL)
	    pwattr[i++] = da->attr;
	else
	    pwattr[--i] = 0;
    }
}


/*
 * Test for password presence in an Access-Request packet.
 * Returns 0 for "no supported password present", or an non-zero
 * opaque value that must be used when calling x99_pw_valid.
 */
int
x99_pw_present(const REQUEST *request)
{
    int i;

    for (i = 0; i < sizeof(pwattr) && pwattr[i]; i += 2) {
	if (pairfind(request->packet->vps, pwattr[i]) &&
	    pairfind(request->packet->vps, pwattr[i + 1])) {
	    DEBUG("rlm_x99_token: pw_present: found password attributes %d, %d",
		   pwattr[i], pwattr[i + 1]);
	    return i + 1; /* Can't return 0 (indicates failure) */
	}
    }

    return 0;
}


/*
 * Test for password validity.  attr must be the return value from
 * x99_pw_present().
 * returns 1 for match, 0 for non-match.
 * If vps is non-null, then on matches, it will point to vps that
 * should be added to an Access-Accept packet.  If access is denied,
 * the caller is responsible for freeing any vps returned.
 * (vps is used for MPPE atttributes.)
 */
int
x99_pw_valid(const REQUEST *request, int attr,
	     const char *password, VALUE_PAIR **vps)
{
    int match = 0;
    VALUE_PAIR *chal_vp, *resp_vp;

    /*
     * A module that does this might want to verify the presence of these.
     * This code is self contained to x99, so I know these exist.
     */
    chal_vp = pairfind(request->packet->vps, pwattr[attr - 1]);
    resp_vp = pairfind(request->packet->vps, pwattr[attr]);

    /* Prepare for failure return. */
    if (vps)
	*vps = NULL;

    /* If modular, this would actually call the authentication function. */
    switch(pwattr[attr]) {
    case PW_PASSWORD:
	DEBUG("rlm_x99_token: pw_valid: handling PW_PASSWORD");
	match = !strcmp(password, resp_vp->strvalue);
	break;

    case PW_CHAP_PASSWORD:
    {
	/*
	 * See RFC 1994.
	 * A CHAP password is MD5(CHAP_ID|SECRET|CHAP_CHALLENGE).
       	 * CHAP_ID is a value set by the authenticator (the NAS), and used
	 * in the response calculation.  It is available as the first byte
	 * of the CHAP-Password attribute.
	 * SECRET is the password.
	 * CHAP_CHALLENGE is the challenge given to the peer (the user).
	 * The CHAP-Challenge Attribute may be missing, in which case the
	 * challenge is taken to be the Request Authenticator.  We don't
	 * handle this case.
	 */
	/*                 ID       password    chal */
	unsigned char input[1 + MAX_STRING_LEN + 16];
	unsigned char output[MD5_DIGEST_LENGTH];

	DEBUG("rlm_x99_token: pw_valid: handling PW_CHAP_PASSWORD");
	if (1 + strlen(password) + chal_vp->length > sizeof(input)) {
	    DEBUG("rlm_x99_token: pw_valid: CHAP-Challenge/password too long");
	    match = 0;
	    break;
	}
	if (resp_vp->length != 17) {
	    radlog(L_AUTH, "rlm_x99_token: pw_valid: CHAP-Password wrong size");
	    match = 0;
	    break;
	}
	input[0] = *(resp_vp->strvalue);
	(void) memcpy(&input[1], password, strlen(password));
	(void) memcpy(&input[1+strlen(password)], chal_vp->strvalue,
		      chal_vp->length);
	(void) MD5(input, 1 + strlen(password) + chal_vp->length, output);
	match = !memcmp(output, &(resp_vp->strvalue)[1], MD5_DIGEST_LENGTH);
    } /* case PW_CHAP_PASSWORD */
    break;

#if 0
    case PW_MS_CHAP_RESPONSE:
    {
	/*
	 * See RFCs 2548, 2433, 3079.
	 * An MS-CHAP response is (IDENT|FLAGS|LM_RESPONSE|NT_RESPONSE).
	 *                 octets:   1     1       24           24
	 * IDENT is not used by RADIUS (it is the PPP MS-CHAP Identifier).
	 * FLAGS is 1 to indicate the NT_RESPONSE should be preferred.
	 * LM_RESPONSE is the LAN Manager compatible response.
	 * NT_RESPONSE is the NT compatible response.
	 * Either response may be zero-filled indicating its absence.
	 * Use of the LM response has been deprecated (RFC 2433, par. 6),
         * so we don't handle it.
	 *
	 * The NT_RESPONSE is (DES(CHAL,K1)|DES(CHAL,K2)|DES(CHAL,K3)), where
	 * CHAL is the 8-octet challenge, and K1, K2, K3 are 7-octet pieces
	 * of MD4(unicode(password)), zero-filled to 21 octets.  Sigh.
	 */
	unsigned char nt_keys[21]; /* sized for 3 DES keys */
	unsigned char input[MAX_STRING_LEN * 2]; /* doubled for unicode */
	unsigned char output[24];
	int password_len, i;
	VALUE_PAIR *vp;

	DEBUG("rlm_x99_token: pw_valid: handling PW_MS_CHAP_RESPONSE");
	if (chal_vp->length != 8) {
	    radlog(L_AUTH, "rlm_x99_token: pw_valid: "
			   "MS-CHAP-Challenge wrong size");
	    match = 0;
	    break;
	}
	if (resp_vp->length != 50) {
	    radlog(L_AUTH, "rlm_x99_token: pw_valid: "
			   "MS-CHAP-Response wrong size");
	    match = 0;
	    break;
	}
	if ((resp_vp->strvalue)[1] != 1) {
	    radlog(L_AUTH, "rlm_x99_token: pw_valid: "
			   "MS-CHAP-Response wrong flags (LM not supported)");
	    match = 0;
	    break;
	}
	/* This is probably overkill. */
	if (strlen(password) > MAX_STRING_LEN) {
	    radlog(L_AUTH, "rlm_x99_token: pw_valid: "
			   "MS-CHAP password too long");
	    match = 0;
	    break;
	}

	/*
	 * Start by hashing the unicode password.
	 * This is broken because unicode chars are machine-ordered,
	 * but the spec (RFC 2433) doesn't say how to prepare
	 * the password for md4 (other than by example values).
	 */
	password_len = strlen(password);
	for (i = 0; i < password_len; ++i) {
	    /* Set the high order 8 bits to 0 (little-endian) */
	    input[i * 2] = *password++;
	    input[i * 2 + 1] = 0;
	}
	(void) memset(nt_keys, 0, sizeof(nt_keys));
	(void) MD4(input, 2 * password_len, nt_keys);

	/* The challenge gets encrypted. */
	(void) memcpy(input, chal_vp->strvalue, 8);

	/* Convert the password hash to keys, and do the encryptions. */
	for (i = 0; i < 3; ++i) {
	    des_cblock key;
	    des_key_schedule ks;

	    x99_key_from_hash(&key, &nt_keys[i * 7]);
	    des_set_key_unchecked(&key, ks);
	    des_ecb_encrypt((des_cblock *) input,
			    (des_cblock *) &output[i * 8],
			    ks, DES_ENCRYPT);
	}

	match = !memcmp(output, resp_vp->strvalue + 26, 24);
	if (!match || !vps)
	    break;

	/*
	 * Generate the MS-CHAP-MPPE-Keys attribute if needed.  This is not
	 * specified anywhere -- RFC 2548, par. 2.4.1 is the authority but
	 * it has typos and omissions that make this unimplementable.  The
	 * code here is based on experimental results provided by
	 * Takahiro Wagatsuma <waga@sic.shibaura-it.ac.jp>.
	 * We only support 128-bit keys derived from the NT hash; 40-bit
	 * and 56-bit keys are derived from the LM hash, which besides
	 * being deprecated, has severe security problems.
	 */
	if (1) {
	    unsigned char mppe_keys[32];
	    /*                    0x    ASCII(mppe_keys)      '\0' */
	    char mppe_keys_string[2 + (2 * sizeof(mppe_keys)) + 1];

	    unsigned char md5_md[MD5_DIGEST_LENGTH];
	    unsigned char encode_buf[AUTH_VECTOR_LEN + MAX_STRING_LEN];
	    int secretlen;

	    /* First, set some related attributes. */
	    if ((vp = pairmake("MS-MPPE-Encryption-Policy",
			       MPPE_ENC_POL_ENCRYPTION_REQUIRED,
			       T_OP_EQ)) != NULL)
		pairadd(vps, vp);
	    else
		; /* choke and die */
	    if ((vp = pairmake("MS-MPPE-Encryption-Types",
			       MPPE_ENC_TYPES_RC4_128,
			       T_OP_EQ)) != NULL)
		pairadd(vps, vp);
	    else
		; /* choke and die */

	    /* Zero the LM-Key sub-field (and padding). */
	    (void) memset(mppe_keys, 0, sizeof(mppe_keys));
	    /* The NT-Key sub-field is MD4(MD4(unicode(password))). */
	    (void) MD4(nt_keys, 16, &mppe_keys[8]);

	    /* Now we must encode the key as User-Password is encoded. */
	    secretlen = strlen(request->secret);
	    (void) memcpy(encode_buf, request->secret, secretlen);
	    (void) memcpy(encode_buf + secretlen, request->packet->vector,
			  AUTH_VECTOR_LEN);
	    (void) MD5(encode_buf, secretlen + AUTH_VECTOR_LEN, md5_md);
	    for (i = 0; i < 16; ++i)
		mppe_keys[i] ^= md5_md[i];
	    (void) memcpy(encode_buf + secretlen, mppe_keys, MD5_DIGEST_LENGTH);
	    (void) MD5(encode_buf, secretlen + MD5_DIGEST_LENGTH, md5_md);
	    for (i = 0; i < 16; ++i)
		mppe_keys[i + 16] ^= md5_md[i];

	    /* Whew.  Now stringify it for pairmake(). */
	    mppe_keys_string[0] = '0';
	    mppe_keys_string[1] = 'x';
	    for (i = 0; i < 32; ++i)
		(void) sprintf(&mppe_keys_string[i*2+2], "%02X", mppe_keys[i]);
	    if ((vp = pairmake("MS-CHAP-MPPE-Keys", mppe_keys_string,
			       T_OP_EQ)) != NULL)
		pairadd(vps, vp);
	    else
		; /* choke and die */
	} else {
	    /* Encryption not supported. */
	    if ((vp = pairmake("MS-MPPE-Encryption-Policy",
			       MPPE_ENC_POL_ENCRYPTION_FORBIDDEN,
			       T_OP_EQ)) != NULL)
		pairadd(vps, vp);
	    else
		; /* choke and die */
	}

    } /* case PW_MS_CHAP_RESPONSE */
    break;
#endif /* 0 (MS_CHAP) */

    case PW_MS_CHAP2_RESPONSE:
    {
	/*
	 * See RFCs 2548, 2759, 3079.
	 * An MS-CHAPv2 response is
	 *          (IDENT|FLAGS|PEER_CHALLENGE|RESERVED|NT_RESPONSE).
	 *   octets:   1     1         16          8        24
	 * IDENT is the PPP MS-CHAPv2 Identifier, used in MS-CHAP2-Success.
	 * FLAGS is currently unused.
	 * PEER_CHALLENGE is a random number, generated by the peer.
	 * NT_RESPONSE is (DES(CHAL,K1)|DES(CHAL,K2)|DES(CHAL,K3)), where
	 * K1, K2, K3 are 7-octet pieces of MD4(unicode(password)), zero-
	 * filled to 21 octets (just as in MS-CHAP); and CHAL is
	 * MSB8(SHA(PEER_CHALLENGE|MS_CHAP_CHALLENGE|USERNAME)).
	 */
	unsigned char nt_keys[21]; /* aka "password_md", sized for 3 DES keys */
	unsigned char password_md_md[MD4_DIGEST_LENGTH]; /* for mutual auth */
	unsigned char input[MAX_STRING_LEN * 2]; /* doubled for unicode */
	unsigned char output[24];
	int password_len, i;
	VALUE_PAIR *vp;

	DEBUG("rlm_x99_token: pw_valid: handling PW_MS_CHAP2_RESPONSE");
	if (chal_vp->length != 16) {
	    radlog(L_AUTH, "rlm_x99_token: pw_valid: "
			   "MS-CHAP-Challenge (v2) wrong size");
	    match = 0;
	    break;
	}
	if (resp_vp->length != 50) {
	    radlog(L_AUTH, "rlm_x99_token: pw_valid: "
			   "MS-CHAP2-Response wrong size");
	    match = 0;
	    break;
	}
	/* This is probably overkill. */
	if (strlen(password) > MAX_STRING_LEN) {
	    radlog(L_AUTH, "rlm_x99_token: pw_valid: "
			   "MS-CHAPv2 password too long");
	    match = 0;
	    break;
	}

	/*
	 * Start by hashing the unicode password.
	 * This is broken because unicode chars are machine-ordered,
	 * but the spec (RFC 2759) doesn't say how to prepare
	 * the password for md4 (other than by example values).
	 */
	password_len = strlen(password);
	for (i = 0; i < password_len; ++i) {
	    /* Set the high order 8 bits to 0 (little-endian) */
	    input[i * 2] = *password++;
	    input[i * 2 + 1] = 0;
	}
	(void) memset(nt_keys, 0, sizeof(nt_keys));
	(void) MD4(input, 2 * password_len, nt_keys);

	/* Now calculate the CHAL value from our various inputs. */
	{
	    SHA_CTX ctx;
	    unsigned char md[SHA_DIGEST_LENGTH];
	    char *username = request->username->strvalue;
	    int username_len = request->username->length;

	    SHA1_Init(&ctx);
	    SHA1_Update(&ctx, resp_vp->strvalue + 2, 16);
	    SHA1_Update(&ctx, chal_vp->strvalue, 16);
	    SHA1_Update(&ctx, username, username_len);
	    SHA1_Final(md, &ctx);

	    (void) memcpy(input, md, 8);
	}

	/* Convert the password hash to keys, and do the encryptions. */
	for (i = 0; i < 3; ++i) {
	    des_cblock key;
	    des_key_schedule ks;

	    x99_key_from_hash(&key, &nt_keys[i * 7]);
	    des_set_key_unchecked(&key, ks);
	    des_ecb_encrypt((des_cblock *) input,
			    (des_cblock *) &output[i * 8],
			    ks, DES_ENCRYPT);
	}

	match = !memcmp(output, resp_vp->strvalue + 26, 24);
	if (!match || !vps)
	    break;

	/*
	 * MS-CHAPv2 requires mutual authentication; we must prove
	 * that we know the secret.  This is a bit circuitous: set
	 * MD1 = SHA(MD4(MD4(unicode(password)))|NT_RESPONSE|MAGIC1),
	 * MD2 = MSB8(SHA(PEER_CHALLENGE|MS_CHAP_CHALLENGE|USERNAME)),
	 * and finally use SHA(MD1|MD2|MAGIC2) as the authenticator.
	 * The authenticator is returned as the string "S=<auth>",
	 * <auth> is the authenticator expressed as [uppercase] ASCII.
	 * See RFC 2759.
	 */
	{
	    SHA_CTX ctx;
	    unsigned char md1[SHA_DIGEST_LENGTH];
	    unsigned char md2[SHA_DIGEST_LENGTH];
	    unsigned char auth_md[SHA_DIGEST_LENGTH];
	    /*                  S=  (  ASCII(auth_md)   )  \0 */
	    char auth_md_string[2 + (2 * sizeof(auth_md)) + 1];
	    /*
	     * ugh.  The ASCII authenticator (auth_md_string) is sent
	     * along with a single (useless) binary byte (the ID).
	     * So we must "stringify" it again (for pairmake()) since the
	     * binary byte requires the attribute to be of type "octets".
	     */
	    /*                    0x  (ID) ( ASCII("S="ASCII(auth_md))) */
	    char auth_octet_string[2 + 2 + (2 * sizeof(auth_md_string))];

	    char *username = request->username->strvalue;
	    int username_len = request->username->length;

	    /* "Magic server to client signing constant" */
	    unsigned char magic1[39] =
	    { 0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
	      0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
	      0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
	      0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74 };
	    /* "Pad to make it do more than one iteration" */
	    unsigned char magic2[41] =
	    { 0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
	      0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
	      0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
	      0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
	      0x6E };

	    /* MD1 */
	    (void) MD4(nt_keys, MD4_DIGEST_LENGTH, password_md_md);
	    SHA1_Init(&ctx);
	    SHA1_Update(&ctx, password_md_md, MD4_DIGEST_LENGTH);
	    SHA1_Update(&ctx, resp_vp->strvalue + 26, 24);
	    SHA1_Update(&ctx, magic1, sizeof(magic1));
	    SHA1_Final(md1, &ctx);

	    /* MD2 */
	    SHA1_Init(&ctx);
	    SHA1_Update(&ctx, resp_vp->strvalue + 2, 16);
	    SHA1_Update(&ctx, chal_vp->strvalue, 16);
	    SHA1_Update(&ctx, username, username_len);
	    SHA1_Final(md2, &ctx);

	    /* The Authenticator */
	    SHA1_Init(&ctx);
	    SHA1_Update(&ctx, md1, SHA_DIGEST_LENGTH);
	    SHA1_Update(&ctx, md2, 8);
	    SHA1_Update(&ctx, magic2, sizeof(magic2));
	    SHA1_Final(auth_md, &ctx);

	    /* String conversion. */
	    auth_md_string[0] = 'S';
	    auth_md_string[1] = '=';
	    for (i = 0; i < sizeof(auth_md); ++i)
		(void) sprintf(&auth_md_string[i * 2 + 2], "%02X", auth_md[i]);

	    /* And then octet conversion.  Ugh! */
	    auth_octet_string[0] = '0';
	    auth_octet_string[1] = 'x';
	    (void) sprintf(&auth_octet_string[2], "%02X", resp_vp->strvalue[0]);
	    for (i = 0; i < sizeof(auth_md_string) - 1; ++i)
		(void) sprintf(&auth_octet_string[i * 2 + 4], "%02X",
			       auth_md_string[i]);

	    if ((vp = pairmake("MS-CHAP2-Success", auth_octet_string,
			       T_OP_EQ)) != NULL)
		pairadd(vps, vp);
	    else
		; /* choke and die */
	} /* Generate mutual auth info. */

	/*
	 * Generate the MPPE initial session key if needed, per RFC 3079.
	 * (Although, RFC 2548 leaves us guessing at how to generate this.)
	 * For MS-CHAPv2 we support all key lengths (40-, 56- and 128-bit),
	 * although MPPE via RADIUS supports only 40- and 128-bit keys.
	 * This is a bit more complicated than MS-CHAP.  Start by generating
	 * a "master session key"
	 *    MSB16(SHA(NTPasswordHashHash|NT_RESPONSE|MAGIC1)), where
	 * NTPasswordHashHash is MD4(MD4(unicode(password))), NT_RESPONSE
	 * is from the MS-CHAP2-Response attribute, and MAGIC1 is a
	 * constant from RFC 3079.  Then, we derive asymmetric send/receive
	 * keys from the master session key.  The "master send key" is
	 *     MSBx(SHA(MASTERKEY|SHSPAD1|MAGIC3|SHSPAD2)),
	 * and the "master receive key" is
	 *     MSBx(SHA(MASTERKEY|SHSPAD1|MAGIC2|SHSPAD2)), where
	 * MASTERKEY is the "master session key" generated above, and the
	 * other values are constants from RFC 3079.  MSBx is the x-most
	 * significant bytes, where x is 5, 7, or 16 as appropriate for
	 * the desired key length.  We always generate 16 byte (128-bit)
	 * keys, the NAS is required to truncate as needed.
	 */
	if (1) {
	    /* These constants and key vars are named from RFC 3079. */
	    /* "This is the MPPE Master Key" */
	    unsigned char Magic1[27] =
	    { 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
	      0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
	      0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79 };
	    /* "On the client side, this is the send key; "
	       "on the server side, it is the receive key." */
	    unsigned char Magic2[84] =
	    { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
	      0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
	      0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
	      0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
	      0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
	      0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
	      0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
	      0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
	      0x6b, 0x65, 0x79, 0x2e };
	    /* "On the client side, this is the receive key; "
	       "on the server side, it is the send key." */
	    unsigned char Magic3[84] =
	    { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
	      0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
	      0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
	      0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
	      0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
	      0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
	      0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
	      0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
	      0x6b, 0x65, 0x79, 0x2e };
	    unsigned char SHSpad1[40] =
	    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	    unsigned char SHSpad2[40] =
	    { 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
	      0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
	      0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
	      0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2 };
	    unsigned char MasterKey[16];
	    unsigned char MasterSendKey[16];
	    unsigned char MasterReceiveKey[16];

	    SHA_CTX ctx;
	    unsigned char sha_md[SHA_DIGEST_LENGTH];
	    unsigned char md5_md[MD5_DIGEST_LENGTH];

	    /*   From RFC 2548:           S                 R           A */
	    unsigned char encode_buf[MAX_STRING_LEN + AUTH_VECTOR_LEN + 2];
	    int secretlen;

	    /* A useless value required by RFC 2548. */
	    unsigned char salt[2];
	    unsigned char mppe_key[32]; /* 1 + 16 + padding */
	    /*                           0x   (   ASCII(salt)  ) */
	    unsigned char mppe_key_string[2 + (2 * sizeof(salt)) +
	    /*				  (   ASCII(mppe_key)  )  \0 */
					  (2 * sizeof(mppe_key)) + 1];

	    /* First, set some related attributes. */
	    if ((vp = pairmake("MS-MPPE-Encryption-Policy",
			       MPPE_ENC_POL_ENCRYPTION_REQUIRED,
			       T_OP_EQ)) != NULL)
		pairadd(vps, vp);
	    else
		; /* choke and die */
	    if ((vp = pairmake("MS-MPPE-Encryption-Types",
			       MPPE_ENC_TYPES_RC4_128,
			       T_OP_EQ)) != NULL)
		pairadd(vps, vp);
	    else
		; /* choke and die */

	    (void) memset(mppe_key, 0, 32);
	    mppe_key[0] = 16; /* length (s/rant//) */

	    /* Generate the master session key. */
	    SHA1_Init(&ctx);
	    SHA1_Update(&ctx, password_md_md, MD4_DIGEST_LENGTH);
	    SHA1_Update(&ctx, resp_vp->strvalue + 26, 24);
	    SHA1_Update(&ctx, Magic1, sizeof(Magic1));
	    SHA1_Final(sha_md, &ctx);
	    (void) memcpy(MasterKey, sha_md, 16);

	    /* Generate the master send key. */
	    SHA1_Init(&ctx);
	    SHA1_Update(&ctx, MasterKey, 16);
	    SHA1_Update(&ctx, SHSpad1, 40);
	    SHA1_Update(&ctx, Magic3, sizeof(Magic3));
	    SHA1_Update(&ctx, SHSpad2, 40);
	    SHA1_Final(sha_md, &ctx);
	    (void) memcpy(MasterSendKey, sha_md, 16);

	    /* Generate the master receive key. */
	    SHA1_Init(&ctx);
	    SHA1_Update(&ctx, MasterKey, 16);
	    SHA1_Update(&ctx, SHSpad1, 40);
	    SHA1_Update(&ctx, Magic2, sizeof(Magic3));
	    SHA1_Update(&ctx, SHSpad2, 40);
	    SHA1_Final(sha_md, &ctx);
	    (void) memcpy(MasterReceiveKey, sha_md, 16);

	    /* Now, generate the MS-MPPE-Send-Key attribute. */

	    /* Setup the salt value. */
	    salt[0] = 0x80;
	    salt[1] = 0x01;

	    /* Encode the key. */
	    (void) memcpy(&mppe_key[1], MasterSendKey, 16);
	    secretlen = strlen(request->secret);
	    (void) memcpy(encode_buf, request->secret, secretlen);
	    (void) memcpy(encode_buf + secretlen, request->packet->vector,
			  AUTH_VECTOR_LEN);
	    (void) memcpy(encode_buf + secretlen + 16, salt, 2);
	    (void) MD5(encode_buf, secretlen + AUTH_VECTOR_LEN + 2, md5_md);
	    for (i = 0; i < 16; ++i)
		mppe_key[i] ^= md5_md[i];
	    (void) memcpy(encode_buf + secretlen, mppe_key, 16);
	    (void) MD5(encode_buf, secretlen + 16, md5_md);
	    for (i = 0; i < 16; ++i)
		mppe_key[i + 16] ^= md5_md[i];

	    /* Whew.  Now stringify it for pairmake(). */
	    mppe_key_string[0] = '0';
	    mppe_key_string[1] = 'x';
	    (void) sprintf(&mppe_key_string[2], "%02X", salt[0]);
	    (void) sprintf(&mppe_key_string[4], "%02X", salt[1]);
	    for (i = 0; i < sizeof(mppe_key); ++i)
		(void) sprintf(&mppe_key_string[i*2+6], "%02X", mppe_key[i]);
	    if ((vp = pairmake("MS-MPPE-Send-Key", mppe_key_string,
			       T_OP_EQ)) != NULL)
		pairadd(vps, vp);
	    else
		; /* choke and die */

	    /* Generate the MS-MPPE-Recv-Key attribute. */

	    /* Setup the salt value. */
	    salt[0] = 0x80;
	    salt[1] = 0x02;

	    /* Encode the key. */
	    (void) memcpy(&mppe_key[1], MasterReceiveKey, 16);
	    secretlen = strlen(request->secret);
	    (void) memcpy(encode_buf, request->secret, secretlen);
	    (void) memcpy(encode_buf + secretlen, request->packet->vector,
			  AUTH_VECTOR_LEN);
	    (void) memcpy(encode_buf + secretlen + 16, salt, 2);
	    (void) MD5(encode_buf, secretlen + AUTH_VECTOR_LEN + 2, md5_md);
	    for (i = 0; i < 16; ++i)
		mppe_key[i] ^= md5_md[i];
	    (void) memcpy(encode_buf + secretlen, mppe_key, 16);
	    (void) MD5(encode_buf, secretlen + 16, md5_md);
	    for (i = 0; i < 16; ++i)
		mppe_key[i + 16] ^= md5_md[i];

	    /* Whew.  Now stringify it for pairmake(). */
	    mppe_key_string[0] = '0';
	    mppe_key_string[1] = 'x';
	    (void) sprintf(&mppe_key_string[2], "%02X", salt[0]);
	    (void) sprintf(&mppe_key_string[4], "%02X", salt[1]);
	    for (i = 0; i < sizeof(mppe_key); ++i)
		(void) sprintf(&mppe_key_string[i*2+6], "%02X", mppe_key[i]);
	    if ((vp = pairmake("MS-MPPE-Recv-Key", mppe_key_string,
			       T_OP_EQ)) != NULL)
		pairadd(vps, vp);
	    else
		; /* choke and die */

	} else {
	    /* Encryption not supported. */
	    if ((vp = pairmake("MS-MPPE-Encryption-Policy",
			       MPPE_ENC_POL_ENCRYPTION_FORBIDDEN,
			       T_OP_EQ)) != NULL)
		pairadd(vps, vp);
	    else
		; /* choke and die */
	}

    } /* case PW_MS_CHAP2_RESPONSE */
    break;

    default:
	DEBUG("rlm_x99_token: pw_valid: unknown password type");
	match = 0;
	break;

    } /* switch(pwattr[attr]) */

    return match;
}


/*
 * #$!#@ have to convert 7 octet ranges into 8 octet keys.
 * Implementation cribbed (and slightly modified) from
 * rlm_mschap.c by Jay Miller <jaymiller@socket.net>.
 * We don't bother checking/setting parity.
 */
static void
x99_key_from_hash(des_cblock *key, const unsigned char hashbytes[7])
{
    int i;
    unsigned char cNext = 0;
    unsigned char cWorking = 0;

    for (i = 0; i < 7; ++i) {
	cWorking = hashbytes[i];
	(*key)[i] = (cWorking >> i) | cNext;
	cNext = (cWorking << (7 - i));
    }
    (*key)[i] = cNext;
}

