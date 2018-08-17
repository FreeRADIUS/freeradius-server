/* crypto/ec/ectest.c */
/*
 * Originally written by Bodo Moeller for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#ifdef FLAT_INC
#include "e_os.h"
#else
#include "../e_os.h"
#endif
#include <string.h>
#include <time.h>


#ifdef OPENSSL_NO_EC
int main(int argc, char * argv[]) { puts("Elliptic curves are disabled."); return 0; }
#else


#include <openssl/ec.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/opensslconf.h>

#if defined(_MSC_VER) && defined(_MIPS_) && (_MSC_VER/100==12)
/* suppress "too big too optimize" warning */
#pragma warning(disable:4959)
#endif

#define ABORT do { \
	fflush(stdout); \
	fprintf(stderr, "%s:%d: ABORT\n", __FILE__, __LINE__); \
	ERR_print_errors_fp(stderr); \
	EXIT(1); \
} while (0)

#define TIMING_BASE_PT 0
#define TIMING_RAND_PT 1
#define TIMING_SIMUL 2

#if 0
static void timings(EC_GROUP *group, int type, BN_CTX *ctx)
	{
	clock_t clck;
	int i, j;
	BIGNUM *s;
	BIGNUM *r[10], *r0[10];
	EC_POINT *P;

	s = BN_new();
	if (s == NULL) ABORT;

	fprintf(stdout, "Timings for %d-bit field, ", EC_GROUP_get_degree(group));
	if (!EC_GROUP_get_order(group, s, ctx)) ABORT;
	fprintf(stdout, "%d-bit scalars ", (int)BN_num_bits(s));
	fflush(stdout);

	P = EC_POINT_new(group);
	if (P == NULL) ABORT;
	EC_POINT_copy(P, EC_GROUP_get0_generator(group));

	for (i = 0; i < 10; i++)
		{
		if ((r[i] = BN_new()) == NULL) ABORT;
		if (!BN_pseudo_rand(r[i], BN_num_bits(s), 0, 0)) ABORT;
		if (type != TIMING_BASE_PT)
			{
			if ((r0[i] = BN_new()) == NULL) ABORT;
			if (!BN_pseudo_rand(r0[i], BN_num_bits(s), 0, 0)) ABORT;
			}
		}

	clck = clock();
	for (i = 0; i < 10; i++)
		{
		for (j = 0; j < 10; j++)
			{
			if (!EC_POINT_mul(group, P, (type != TIMING_RAND_PT) ? r[i] : NULL,
				(type != TIMING_BASE_PT) ? P : NULL, (type != TIMING_BASE_PT) ? r0[i] : NULL, ctx)) ABORT;
			}
		}
	clck = clock() - clck;

	fprintf(stdout, "\n");

#ifdef CLOCKS_PER_SEC
	/* "To determine the time in seconds, the value returned
	 * by the clock function should be divided by the value
	 * of the macro CLOCKS_PER_SEC."
	 *                                       -- ISO/IEC 9899 */
#	define UNIT "s"
#else
	/* "`CLOCKS_PER_SEC' undeclared (first use this function)"
	 *                            -- cc on NeXTstep/OpenStep */
#	define UNIT "units"
#	define CLOCKS_PER_SEC 1
#endif

	if (type == TIMING_BASE_PT) {
		fprintf(stdout, "%i %s in %.2f " UNIT "\n", i*j,
			"base point multiplications", (double)clck/CLOCKS_PER_SEC);
	} else if (type == TIMING_RAND_PT) {
		fprintf(stdout, "%i %s in %.2f " UNIT "\n", i*j,
			"random point multiplications", (double)clck/CLOCKS_PER_SEC);
	} else if (type == TIMING_SIMUL) {
		fprintf(stdout, "%i %s in %.2f " UNIT "\n", i*j,
			"s*P+t*Q operations", (double)clck/CLOCKS_PER_SEC);
	}
	fprintf(stdout, "average: %.4f " UNIT "\n", (double)clck/(CLOCKS_PER_SEC*i*j));

	EC_POINT_free(P);
	BN_free(s);
	for (i = 0; i < 10; i++)
		{
		BN_free(r[i]);
		if (type != TIMING_BASE_PT) BN_free(r0[i]);
		}
	}
#endif

/* test multiplication with group order, long and negative scalars */
static void group_order_tests(EC_GROUP *group)
	{
	BIGNUM *n1, *n2, *order;
	EC_POINT *P = EC_POINT_new(group);
	EC_POINT *Q = EC_POINT_new(group);
	BN_CTX *ctx = BN_CTX_new();

	n1 = BN_new(); n2 = BN_new(); order = BN_new();
	fprintf(stdout, "verify group order ...");
	fflush(stdout);
	if (!EC_GROUP_get_order(group, order, ctx)) ABORT;
	if (!EC_POINT_mul(group, Q, order, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_is_at_infinity(group, Q)) ABORT;
	fprintf(stdout, ".");
	fflush(stdout);
	if (!EC_GROUP_precompute_mult(group, ctx)) ABORT;
	if (!EC_POINT_mul(group, Q, order, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_is_at_infinity(group, Q)) ABORT;
	fprintf(stdout, " ok\n");
	fprintf(stdout, "long/negative scalar tests ... ");
	if (!BN_one(n1)) ABORT;
	/* n1 = 1 - order */
	if (!BN_sub(n1, n1, order)) ABORT;
	if(!EC_POINT_mul(group, Q, NULL, P, n1, ctx)) ABORT;
	if (0 != EC_POINT_cmp(group, Q, P, ctx)) ABORT;
	/* n2 = 1 + order */
	if (!BN_add(n2, order, BN_value_one())) ABORT;
	if(!EC_POINT_mul(group, Q, NULL, P, n2, ctx)) ABORT;
	if (0 != EC_POINT_cmp(group, Q, P, ctx)) ABORT;
	/* n2 = (1 - order) * (1 + order) */
	if (!BN_mul(n2, n1, n2, ctx)) ABORT;
	if(!EC_POINT_mul(group, Q, NULL, P, n2, ctx)) ABORT;
	if (0 != EC_POINT_cmp(group, Q, P, ctx)) ABORT;
	fprintf(stdout, "ok\n");
	EC_POINT_free(P);
	EC_POINT_free(Q);
	BN_free(n1);
	BN_free(n2);
	BN_free(order);
	BN_CTX_free(ctx);
	}

static void prime_field_tests(void)
	{
	BN_CTX *ctx = NULL;
	BIGNUM *p, *a, *b;
	EC_GROUP *group;
	EC_GROUP *P_160 = NULL, *P_192 = NULL, *P_224 = NULL, *P_256 = NULL, *P_384 = NULL, *P_521 = NULL;
	EC_POINT *P, *Q, *R;
	BIGNUM *x, *y, *z;
	unsigned char buf[100];
	size_t i, len;
	int k;

#if 1 /* optional */
	ctx = BN_CTX_new();
	if (!ctx) ABORT;
#endif

	p = BN_new();
	a = BN_new();
	b = BN_new();
	if (!p || !a || !b) ABORT;

	group = EC_GROUP_new(EC_GFp_mont_method()); /* applications should use EC_GROUP_new_curve_GFp
	                                             * so that the library gets to choose the EC_METHOD */
	if (!group) ABORT;

	P = EC_POINT_new(group);
	Q = EC_POINT_new(group);
	R = EC_POINT_new(group);
	if (!P || !Q || !R) ABORT;

	x = BN_new();
	y = BN_new();
	z = BN_new();
	if (!x || !y || !z) ABORT;

/* Curve P-256 (FIPS PUB 186-2, App. 6) */

	if (!BN_hex2bn(&p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")) ABORT;
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ABORT;
	if (!BN_hex2bn(&a, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC")) ABORT;
	if (!BN_hex2bn(&b, "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")) ABORT;
	if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) ABORT;

	if (!BN_hex2bn(&x, "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")) ABORT;
	if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 1, ctx)) ABORT;
	if (!EC_POINT_is_on_curve(group, P, ctx)) ABORT;
	if (!BN_hex2bn(&z, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E"
		"84F3B9CAC2FC632551")) ABORT;
	if (!EC_GROUP_set_generator(group, P, z, BN_value_one())) ABORT;

	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nNIST curve P-256 -- Generator:\n     x = 0x");
	BN_print_fp(stdout, x);
	fprintf(stdout, "\n     y = 0x");
	BN_print_fp(stdout, y);
	fprintf(stdout, "\n");
	/* G_y value taken from the standard: */
	if (!BN_hex2bn(&z, "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")) ABORT;
	if (0 != BN_cmp(y, z)) ABORT;

	fprintf(stdout, "verify degree ...");
	if (EC_GROUP_get_degree(group) != 256) ABORT;
	fprintf(stdout, " ok\n");

	group_order_tests(group);

	if (!(P_256 = EC_GROUP_new(EC_GROUP_method_of(group)))) ABORT;
	if (!EC_GROUP_copy(P_256, group)) ABORT;


	/* Curve P-384 (FIPS PUB 186-2, App. 6) */

	if (!BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF")) ABORT;
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ABORT;
	if (!BN_hex2bn(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC")) ABORT;
	if (!BN_hex2bn(&b, "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141"
		"120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF")) ABORT;
	if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) ABORT;

	if (!BN_hex2bn(&x, "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B"
		"9859F741E082542A385502F25DBF55296C3A545E3872760AB7")) ABORT;
	if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 1, ctx)) ABORT;
	if (!EC_POINT_is_on_curve(group, P, ctx)) ABORT;
	if (!BN_hex2bn(&z, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973")) ABORT;
	if (!EC_GROUP_set_generator(group, P, z, BN_value_one())) ABORT;

	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nNIST curve P-384 -- Generator:\n     x = 0x");
	BN_print_fp(stdout, x);
	fprintf(stdout, "\n     y = 0x");
	BN_print_fp(stdout, y);
	fprintf(stdout, "\n");
	/* G_y value taken from the standard: */
	if (!BN_hex2bn(&z, "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A14"
		"7CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F")) ABORT;
	if (0 != BN_cmp(y, z)) ABORT;

	fprintf(stdout, "verify degree ...");
	if (EC_GROUP_get_degree(group) != 384) ABORT;
	fprintf(stdout, " ok\n");

	group_order_tests(group);

	if (!(P_384 = EC_GROUP_new(EC_GROUP_method_of(group)))) ABORT;
	if (!EC_GROUP_copy(P_384, group)) ABORT;


	/* Curve P-521 (FIPS PUB 186-2, App. 6) */

	if (!BN_hex2bn(&p, "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFF")) ABORT;
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ABORT;
	if (!BN_hex2bn(&a, "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFC")) ABORT;
	if (!BN_hex2bn(&b, "051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B"
		"315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573"
		"DF883D2C34F1EF451FD46B503F00")) ABORT;
	if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) ABORT;

	if (!BN_hex2bn(&x, "C6858E06B70404E9CD9E3ECB662395B4429C648139053F"
		"B521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B"
		"3C1856A429BF97E7E31C2E5BD66")) ABORT;
	if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx)) ABORT;
	if (!EC_POINT_is_on_curve(group, P, ctx)) ABORT;
	if (!BN_hex2bn(&z, "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
		"FFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5"
		"C9B8899C47AEBB6FB71E91386409")) ABORT;
	if (!EC_GROUP_set_generator(group, P, z, BN_value_one())) ABORT;

	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nNIST curve P-521 -- Generator:\n     x = 0x");
	BN_print_fp(stdout, x);
	fprintf(stdout, "\n     y = 0x");
	BN_print_fp(stdout, y);
	fprintf(stdout, "\n");
	/* G_y value taken from the standard: */
	if (!BN_hex2bn(&z, "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579"
		"B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C"
		"7086A272C24088BE94769FD16650")) ABORT;
	if (0 != BN_cmp(y, z)) ABORT;

	fprintf(stdout, "verify degree ...");
	if (EC_GROUP_get_degree(group) != 521) ABORT;
	fprintf(stdout, " ok\n");

 	group_order_tests(group);

	if (!(P_521 = EC_GROUP_new(EC_GROUP_method_of(group)))) ABORT;
	if (!EC_GROUP_copy(P_521, group)) ABORT;


	/* more tests using the last curve */

	if (!EC_POINT_copy(Q, P)) ABORT;
	if (EC_POINT_is_at_infinity(group, Q)) ABORT;
	if (!EC_POINT_dbl(group, P, P, ctx)) ABORT;
	if (!EC_POINT_is_on_curve(group, P, ctx)) ABORT;
	if (!EC_POINT_invert(group, Q, ctx)) ABORT; /* P = -2Q */

	if (!EC_POINT_add(group, R, P, Q, ctx)) ABORT;
	if (!EC_POINT_add(group, R, R, Q, ctx)) ABORT;
	if (!EC_POINT_is_at_infinity(group, R)) ABORT; /* R = P + 2Q */

	{
		const EC_POINT *points[4];
		const BIGNUM *scalars[4];
		BIGNUM scalar3;

		if (EC_POINT_is_at_infinity(group, Q)) ABORT;
		points[0] = Q;
		points[1] = Q;
		points[2] = Q;
		points[3] = Q;

		if (!EC_GROUP_get_order(group, z, ctx)) ABORT;
		if (!BN_add(y, z, BN_value_one())) ABORT;
		if (BN_is_odd(y)) ABORT;
		if (!BN_rshift1(y, y)) ABORT;
		scalars[0] = y; /* (group order + 1)/2, so  y*Q + y*Q = Q */
		scalars[1] = y;

		fprintf(stdout, "combined multiplication ...");
		fflush(stdout);

		/* z is still the group order */
		if (!EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx)) ABORT;
		if (!EC_POINTs_mul(group, R, z, 2, points, scalars, ctx)) ABORT;
		if (0 != EC_POINT_cmp(group, P, R, ctx)) ABORT;
		if (0 != EC_POINT_cmp(group, R, Q, ctx)) ABORT;

		fprintf(stdout, ".");
		fflush(stdout);

		if (!BN_pseudo_rand(y, BN_num_bits(y), 0, 0)) ABORT;
		if (!BN_add(z, z, y)) ABORT;
		BN_set_negative(z, 1);
		scalars[0] = y;
		scalars[1] = z; /* z = -(order + y) */

		if (!EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx)) ABORT;
		if (!EC_POINT_is_at_infinity(group, P)) ABORT;

		fprintf(stdout, ".");
		fflush(stdout);

		if (!BN_pseudo_rand(x, BN_num_bits(y) - 1, 0, 0)) ABORT;
		if (!BN_add(z, x, y)) ABORT;
		BN_set_negative(z, 1);
		scalars[0] = x;
		scalars[1] = y;
		scalars[2] = z; /* z = -(x+y) */

		BN_init(&scalar3);
		BN_zero(&scalar3);
		scalars[3] = &scalar3;

		if (!EC_POINTs_mul(group, P, NULL, 4, points, scalars, ctx)) ABORT;
		if (!EC_POINT_is_at_infinity(group, P)) ABORT;

		fprintf(stdout, " ok\n\n");

		BN_free(&scalar3);
	}


#if 0
	timings(P_256, TIMING_BASE_PT, ctx);
	timings(P_256, TIMING_RAND_PT, ctx);
	timings(P_256, TIMING_SIMUL, ctx);
	timings(P_384, TIMING_BASE_PT, ctx);
	timings(P_384, TIMING_RAND_PT, ctx);
	timings(P_384, TIMING_SIMUL, ctx);
#endif


	if (ctx)
		BN_CTX_free(ctx);
	BN_free(p); BN_free(a);	BN_free(b);
	EC_GROUP_free(group);
	EC_POINT_free(P);
	EC_POINT_free(Q);
	EC_POINT_free(R);
	BN_free(x); BN_free(y); BN_free(z);

	if (P_160) EC_GROUP_free(P_160);
	if (P_192) EC_GROUP_free(P_192);
	if (P_224) EC_GROUP_free(P_224);
	if (P_256) EC_GROUP_free(P_256);
	if (P_384) EC_GROUP_free(P_384);
	if (P_521) EC_GROUP_free(P_521);

	}


static void internal_curve_test(void)
	{
	EC_builtin_curve *curves = NULL;
	size_t crv_len = 0, n = 0;
	int    ok = 1;

	crv_len = EC_get_builtin_curves(NULL, 0);

	curves = OPENSSL_malloc(sizeof(EC_builtin_curve) * crv_len);

	if (curves == NULL)
		return;

	if (!EC_get_builtin_curves(curves, crv_len))
		{
		OPENSSL_free(curves);
		return;
		}

	fprintf(stdout, "testing internal curves: ");

	for (n = 0; n < crv_len; n++)
		{
		EC_GROUP *group = NULL;
		int nid = curves[n].nid;
		if ((group = EC_GROUP_new_by_curve_name(nid)) == NULL)
			{
			ok = 0;
			fprintf(stdout, "\nEC_GROUP_new_curve_name() failed with"
				" curve %s\n", OBJ_nid2sn(nid));
			/* try next curve */
			continue;
			}
		if (!EC_GROUP_check(group, NULL))
			{
			ok = 0;
			fprintf(stdout, "\nEC_GROUP_check() failed with"
				" curve %s\n", OBJ_nid2sn(nid));
			EC_GROUP_free(group);
			/* try the next curve */
			continue;
			}
		fprintf(stdout, ".");
		fflush(stdout);
		EC_GROUP_free(group);
		}
	if (ok)
		fprintf(stdout, " ok\n\n");
	else
		{
		fprintf(stdout, " failed\n\n");
		ABORT;
		}
	OPENSSL_free(curves);
	return;
	}

#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
/* nistp_test_params contains magic numbers for testing our optimized
 * implementations of several NIST curves with characteristic > 3. */
struct nistp_test_params
	{
	const EC_METHOD* (*meth) ();
	int degree;
	/* Qx, Qy and D are taken from
	 * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/ECDSA_Prime.pdf
	 * Otherwise, values are standard curve parameters from FIPS 180-3 */
	const char *p, *a, *b, *Qx, *Qy, *Gx, *Gy, *order, *d;
	};

static const struct nistp_test_params nistp_tests_params[] =
	{
		{
		/* P-256 */
		EC_GFp_nistp256_method,
		256,
		"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", /* p */
		"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", /* a */
		"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", /* b */
		"b7e08afdfe94bad3f1dc8c734798ba1c62b3a0ad1e9ea2a38201cd0889bc7a19", /* Qx */
		"3603f747959dbf7a4bb226e41928729063adc7ae43529e61b563bbc606cc5e09", /* Qy */
		"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", /* Gx */
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", /* Gy */
		"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", /* order */
		"c477f9f65c22cce20657faa5b2d1d8122336f851a508a1ed04e479c34985bf96", /* d */
		},
	};

void nistp_single_test(const struct nistp_test_params *test)
	{
	BN_CTX *ctx;
	BIGNUM *p, *a, *b, *x, *y, *n, *m, *order;
	EC_GROUP *NISTP;
	EC_POINT *G, *P, *Q, *Q_CHECK;

	fprintf(stdout, "\nNIST curve P-%d (optimised implementation):\n", test->degree);
	ctx = BN_CTX_new();
	p = BN_new();
	a = BN_new();
	b = BN_new();
	x = BN_new(); y = BN_new();
	m = BN_new(); n = BN_new(); order = BN_new();

	NISTP = EC_GROUP_new(test->meth());
	if(!NISTP) ABORT;
	if (!BN_hex2bn(&p, test->p)) ABORT;
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ABORT;
	if (!BN_hex2bn(&a, test->a)) ABORT;
	if (!BN_hex2bn(&b, test->b)) ABORT;
	if (!EC_GROUP_set_curve_GFp(NISTP, p, a, b, ctx)) ABORT;
	G = EC_POINT_new(NISTP);
	P = EC_POINT_new(NISTP);
	Q = EC_POINT_new(NISTP);
	Q_CHECK = EC_POINT_new(NISTP);
	if(!BN_hex2bn(&x, test->Qx)) ABORT;
	if(!BN_hex2bn(&y, test->Qy)) ABORT;
	if(!EC_POINT_set_affine_coordinates_GFp(NISTP, Q_CHECK, x, y, ctx)) ABORT;
	if (!BN_hex2bn(&x, test->Gx)) ABORT;
	if (!BN_hex2bn(&y, test->Gy)) ABORT;
	if (!EC_POINT_set_affine_coordinates_GFp(NISTP, G, x, y, ctx)) ABORT;
	if (!BN_hex2bn(&order, test->order)) ABORT;
	if (!EC_GROUP_set_generator(NISTP, G, order, BN_value_one())) ABORT;

	fprintf(stdout, "verify degree ... ");
	if (EC_GROUP_get_degree(NISTP) != test->degree) ABORT;
	fprintf(stdout, "ok\n");

	fprintf(stdout, "NIST test vectors ... ");
	if (!BN_hex2bn(&n, test->d)) ABORT;
	/* fixed point multiplication */
	EC_POINT_mul(NISTP, Q, n, NULL, NULL, ctx);
	if (0 != EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)) ABORT;
	/* random point multiplication */
	EC_POINT_mul(NISTP, Q, NULL, G, n, ctx);
	if (0 != EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)) ABORT;

	/* set generator to P = 2*G, where G is the standard generator */
	if (!EC_POINT_dbl(NISTP, P, G, ctx)) ABORT;
	if (!EC_GROUP_set_generator(NISTP, P, order, BN_value_one())) ABORT;
	/* set the scalar to m=n/2, where n is the NIST test scalar */
	if (!BN_rshift(m, n, 1)) ABORT;

	/* test the non-standard generator */
	/* fixed point multiplication */
	EC_POINT_mul(NISTP, Q, m, NULL, NULL, ctx);
	if (0 != EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)) ABORT;
	/* random point multiplication */
	EC_POINT_mul(NISTP, Q, NULL, P, m, ctx);
	if (0 != EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)) ABORT;

	/* now repeat all tests with precomputation */
	if (!EC_GROUP_precompute_mult(NISTP, ctx)) ABORT;

	/* fixed point multiplication */
	EC_POINT_mul(NISTP, Q, m, NULL, NULL, ctx);
	if (0 != EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)) ABORT;
	/* random point multiplication */
	EC_POINT_mul(NISTP, Q, NULL, P, m, ctx);
	if (0 != EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)) ABORT;

	/* reset generator */
	if (!EC_GROUP_set_generator(NISTP, G, order, BN_value_one())) ABORT;
	/* fixed point multiplication */
	EC_POINT_mul(NISTP, Q, n, NULL, NULL, ctx);
	if (0 != EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)) ABORT;
	/* random point multiplication */
	EC_POINT_mul(NISTP, Q, NULL, G, n, ctx);
	if (0 != EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)) ABORT;

	fprintf(stdout, "ok\n");
	group_order_tests(NISTP);
#if 0
	timings(NISTP, TIMING_BASE_PT, ctx);
	timings(NISTP, TIMING_RAND_PT, ctx);
#endif
	EC_GROUP_free(NISTP);
	EC_POINT_free(G);
	EC_POINT_free(P);
	EC_POINT_free(Q);
	EC_POINT_free(Q_CHECK);
	BN_free(n);
	BN_free(m);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(order);
	BN_CTX_free(ctx);
	}

void nistp_tests()
	{
	unsigned i;

	for (i = 0; i < sizeof(nistp_tests_params) / sizeof(struct nistp_test_params); i++)
		{
		nistp_single_test(&nistp_tests_params[i]);
		}
	}
#endif

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

int main(int argc, char *argv[])
	{

	/* enable memory leak checking unless explicitly disabled */
	if (!((getenv("OPENSSL_DEBUG_MEMORY") != NULL) && (0 == strcmp(getenv("OPENSSL_DEBUG_MEMORY"), "off"))))
		{
		CRYPTO_malloc_debug_init();
		CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
		}
	else
		{
		/* OPENSSL_DEBUG_MEMORY=off */
		CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
		}
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();

	RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */

	prime_field_tests();
	puts("");
#ifndef OPENSSL_NO_EC2M
	char2_field_tests();
#endif
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
	nistp_tests();
#endif
	/* test the internal curves */
	internal_curve_test();

#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_thread_state(NULL);
	CRYPTO_mem_leaks_fp(stderr);

	return 0;
	}
#endif
