/*
 * md4.h        Structures and prototypes for md4.
 *
 * Version:     $Id$
 * License:		LGPL, but largely derived from a public domain source.
 *
 */


#ifndef _LRAD_MD4_H
#define _LRAD_MD4_H

#include "autoconf.h"

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <string.h>

/*
 *  FreeRADIUS defines to ensure globally unique MD4 function names,
 *  so that we don't pick up other MD4 libraries.
 */
#define MD4_CTX		librad_MD4_CTX
#define MD4Init		librad_MD4Init
#define MD4Update	librad_MD4Update
#define MD4Final       	librad_MD4Final

void md4_calc (unsigned char *, const unsigned char *, unsigned int);

/*  The below was retrieved from
 *  http://www.openbsd.org/cgi-bin/cvsweb/src/include/md4.h?rev=1.12
 *  With the following changes: uint64_t => uint32_t[2]
 *  Commented out #include <sys/cdefs.h>
 *  Commented out the __BEGIN and __END _DECLS, and the __attributes.
 *  Commented out MD4End, MD4File, MD4Data
 *  Commented out header file protection #ifndef,#define,#endif
 */

/*	$OpenBSD: md4.h,v 1.12 2004/04/28 16:54:00 millert Exp $	*/

/*
 * This code implements the MD4 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 * Todd C. Miller modified the MD5 code to do MD4 based on RFC 1186.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */

/*#ifndef _MD4_H_*/
/*#define _MD4_H_*/

#define	MD4_BLOCK_LENGTH		64
#define	MD4_DIGEST_LENGTH		16
#define	MD4_DIGEST_STRING_LENGTH	(MD4_DIGEST_LENGTH * 2 + 1)

typedef struct MD4Context {
	uint32_t state[4];			/* state */
	uint32_t count[2];			/* number of bits, mod 2^64 */
	uint8_t buffer[MD4_BLOCK_LENGTH];	/* input buffer */
} MD4_CTX;

/*#include <sys/cdefs.h>*/

/*__BEGIN_DECLS*/
void	 MD4Init(MD4_CTX *);
void	 MD4Update(MD4_CTX *, const uint8_t *, size_t)
/*		__attribute__((__bounded__(__string__,2,3)))*/;
void	 MD4Final(uint8_t [MD4_DIGEST_LENGTH], MD4_CTX *)
/*		__attribute__((__bounded__(__minbytes__,1,MD4_DIGEST_LENGTH)))*/;
void	 MD4Transform(uint32_t [4], const uint8_t [MD4_BLOCK_LENGTH])
/*		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD4_BLOCK_LENGTH)))*/;
/*char	*MD4End(MD4_CTX *, char [MD4_DIGEST_STRING_LENGTH])
		__attribute__((__bounded__(__minbytes__,2,MD4_DIGEST_STRING_LENGTH)));
char	*MD4File(char *, char [MD4_DIGEST_STRING_LENGTH])
		__attribute__((__bounded__(__minbytes__,2,MD4_DIGEST_STRING_LENGTH)));
char	*MD4Data(const uint8_t *, size_t, char [MD4_DIGEST_STRING_LENGTH])
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD4_DIGEST_STRING_LENGTH)));*/
/*__END_DECLS*/

#endif /* _LRAD_MD4_H */
