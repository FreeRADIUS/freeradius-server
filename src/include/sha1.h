#ifndef _LRAD_SHA1_H
#define _LRAD_SHA1_H

/*
 *  FreeRADIUS defines to ensure globally unique SHA1 function names,
 *  so that we don't pick up vendor-specific broken SHA1 libraries.
 */
#define SHA1_CTX		librad_SHA1_CTX
#define SHA1Transform		librad_SHA1Transform
#define SHA1Init		librad_SHA1Init
#define SHA1Update		librad_SHA1Update
#define SHA1Final       	librad_SHA1Final

typedef struct {
    unsigned long state[5];
    unsigned long count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(unsigned long state[5], const unsigned char buffer[64]);
void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, const unsigned char* data, unsigned int len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);

#endif /* _LRAD_SHA1_H */
