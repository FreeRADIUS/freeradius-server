#ifndef _FR_SHA1_H
#define _FR_SHA1_H

/*
 *  FreeRADIUS defines to ensure globally unique SHA1 function names,
 *  so that we don't pick up vendor-specific broken SHA1 libraries.
 */
#define fr_SHA1_CTX		fr_SHA1_CTX
#define fr_SHA1Transform		fr_SHA1Transform
#define fr_SHA1Init		fr_SHA1Init
#define fr_SHA1Update		fr_SHA1Update
#define fr_SHA1Final       	fr_SHA1Final

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} fr_SHA1_CTX;

void fr_SHA1Transform(uint32_t state[5], const uint8_t buffer[64]);
void fr_SHA1Init(fr_SHA1_CTX* context);
void fr_SHA1Update(fr_SHA1_CTX* context, const uint8_t* data, unsigned int len);
void fr_SHA1Final(uint8_t digest[20], fr_SHA1_CTX* context);

/*
 * this version implements a raw SHA1 transform, no length is appended,
 * nor any 128s out to the block size.
 */
void fr_fr_SHA1FinalNoLen(uint8_t digest[20], fr_SHA1_CTX* context);

/*
 * FIPS 186-2 PRF based upon SHA1.
 */
extern void fips186_2prf(uint8_t mk[20], uint8_t finalkey[160]);


#endif /* _FR_SHA1_H */
