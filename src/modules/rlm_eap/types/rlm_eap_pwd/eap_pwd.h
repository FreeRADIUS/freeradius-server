/*
 * Copyright (c) Dan Harkins, 2012
 *
 *  Copyright holder grants permission for redistribution and use in source 
 *  and binary forms, with or without modification, provided that the 
 *  following conditions are met:
 *     1. Redistribution of source code must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in all source files.
 *     2. Redistribution in binary form must retain the above copyright
 *        notice, this list of conditions, and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *
 *  "DISCLAIMER OF LIABILITY
 *  
 *  THIS SOFTWARE IS PROVIDED BY DAN HARKINS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INDUSTRIAL LOUNGE BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE."
 *
 * This license and distribution terms cannot be changed. In other words,
 * this code cannot simply be copied and put under a different distribution
 * license (including the GNU public license).
 */

#ifndef _EAP_PWD_H
#define _EAP_PWD_H

#include <freeradius-devel/ident.h>
RCSIDH(eap_pwd_h, "$Id$")
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "eap.h"

typedef struct _pwd_hdr {
    unsigned char lm_exchange;
#define EAP_PWD_EXCH_ID                 1
#define EAP_PWD_EXCH_COMMIT             2
#define EAP_PWD_EXCH_CONFIRM            3
//    unsigned short total_length;      /* there if the L-bit is set */
    unsigned char data[0];
} __attribute__ ((packed)) pwd_hdr;

#define EAP_PWD_GET_LENGTH_BIT(x)       ((x)->lm_exchange & 0x80)
#define EAP_PWD_SET_LENGTH_BIT(x)       ((x)->lm_exchange |= 0x80)
#define EAP_PWD_GET_MORE_BIT(x)         ((x)->lm_exchange & 0x40)
#define EAP_PWD_SET_MORE_BIT(x)         ((x)->lm_exchange |= 0x40)
#define EAP_PWD_GET_EXCHANGE(x)         ((x)->lm_exchange & 0x3f)
#define EAP_PWD_SET_EXCHANGE(x,y)       ((x)->lm_exchange |= (y))

typedef struct _pwd_id_packet {
    unsigned short group_num;
    unsigned char random_function;
#define EAP_PWD_DEF_RAND_FUN            1
    unsigned char prf;
#define EAP_PWD_DEF_PRF                 1
    unsigned char token[4];
    unsigned char prep;
#define EAP_PWD_PREP_NONE               0
#define EAP_PWD_PREP_MS                 1
#define EAP_PWD_PREP_SASL               2
    unsigned char identity[0];
} __attribute__ ((packed)) pwd_id_packet;

typedef struct _pwd_session_t {
    unsigned short state;
#define PWD_STATE_ID_REQ                1
#define PWD_STATE_COMMIT                2
#define PWD_STATE_CONFIRM               3
    unsigned short group_num;
    unsigned long ciphersuite;
    unsigned long token;
    char peer_id[MAX_STRING_LEN];
    int peer_id_len;
    int mtu;
    unsigned char *in_buf;      /* reassembled fragments */
    int in_buf_pos;
    int in_buf_len;
    unsigned char *out_buf;     /* message to fragment */
    int out_buf_pos;
    int out_buf_len;
    EC_GROUP *group;
    EC_POINT *pwe;
    BIGNUM *order;
    BIGNUM *prime;
    BIGNUM *k;
    BIGNUM *private_value;
    BIGNUM *peer_scalar;
    BIGNUM *my_scalar;
    EC_POINT *my_element;
    EC_POINT *peer_element;
    unsigned char my_confirm[SHA256_DIGEST_LENGTH];
} pwd_session_t;

int compute_password_element(pwd_session_t *sess, unsigned short grp_num,
                             char *password, int password_len,
                             char *id_server, int id_server_len,
                             char *id_peer, int id_peer_len, 
                             unsigned long *token);
int compute_scalar_element(pwd_session_t *sess, BN_CTX *bnctx);
int process_peer_commit (pwd_session_t *sess, unsigned char *commit, BN_CTX *bnctx);
int compute_server_confirm(pwd_session_t *sess, unsigned char *buf, BN_CTX *bnctx);
int compute_peer_confirm(pwd_session_t *sess, unsigned char *buf, BN_CTX *bnctx);
int compute_keys(pwd_session_t *sess, unsigned char *peer_confirm,
                 unsigned char *msk, unsigned char *emsk);
#ifdef PRINTBUF
void print_buf(char *str, unsigned char *buf, int len);
#endif  /* PRINTBUF */

#endif  /* _EAP_PWD_H */
