/*
	smbencrypt - produces LM-Passowrd and NT-Password from
	cleartext password
	
	(c) 2002 3APA3A for FreeRADIUS project
 
 */

#include	"../../include/autoconf.h"
#include	"../../include/libradius.h"
#include        <stdio.h>
#include        <stdlib.h>
#include        <string.h>
#include        <ctype.h>

#include        "des.h"
#include        "md5.h"

char * hex = "0123456789ABCDEF";

void tohex (const unsigned char * src, size_t len, char *dst) {
 int i;
 for (i=0; i<len; i++) {
 	dst[(i*2)] = hex[(src[i]/16)];
 	dst[(i*2) + 1] = hex[(src[i]&0x0F)];
 }
 dst[(i*2)] = 0;
}

/* 
 *	parity_key takes a 7-byte string in szIn and returns an
 *	8-byte string in szOut.  It inserts a 1 into every 8th bit.
 *	DES just strips these back out.
 */
static void parity_key(char * szOut, const char * szIn)
{
	int i;
	unsigned char cNext = 0;
	unsigned char cWorking = 0;
	
	for (i = 0; i < 7; i++) {
		/* Shift operator works in place.  Copy the char out */
		cWorking = szIn[i];
		szOut[i] = (cWorking >> i) | cNext | 1;
		cWorking = szIn[i];
		cNext = (cWorking << (7 - i));
	}
	szOut[i] = cNext | 1;
}


/*
 *	des_encrypt takes an 8-byte string and a 7-byte key and
 *	returns an 8-byte DES encrypted string in szOut
 */
static void des_encrypt(const char *szClear, const char *szKey, char *szOut)
{
	char szParityKey[9];
	unsigned long ulK[16][2];
	
	parity_key(szParityKey, szKey); /* Insert parity bits */
	strncpy(szOut, szClear, 8);     /* des encrypts in place */
	deskey(ulK, (unsigned char *) szParityKey, 0);  /* generate keypair */
	des(ulK, szOut);  /* encrypt */
}


static void ntpwdhash (char *szHash, const char *szPassword)
{
	char szUnicodePass[513];
	char nPasswordLen;
	int i;

	/*
	 *	NT passwords are unicode.  Convert plain text password
	 *	to unicode by inserting a zero every other byte
	 */
	nPasswordLen = strlen(szPassword);
	for (i = 0; i < nPasswordLen; i++) {
		szUnicodePass[i << 1] = szPassword[i];
		szUnicodePass[(i << 1) + 1] = 0;
	}

	/* Encrypt Unicode password to a 16-byte MD4 hash */
	md4_calc(szHash, szUnicodePass, (nPasswordLen<<1) );
}



/*
 *	lmpwdhash converts 14-byte null-padded uppercase OEM
 *	password to 16-byte DES hash with predefined salt string
 */
static void lmpwdhash (char *szHash, const char *szPassword)
{
	char szOEMPass[14];
	char stdText[] = "KGS!@#$%";
	int i;

	memset(szOEMPass, 0, 14);
	for (i = 0; i < 14 && szPassword[i]; i++)
		szOEMPass[i] = toupper(szPassword[i]);

	/* Obtain DES hash of OEM password */
	des_encrypt(stdText, szOEMPass, szHash); 
	des_encrypt(stdText, szOEMPass+7, szHash+8);
}

int main (int argc, char *argv[]) {
	int i, l;
	char password[1024];
	char hash[16];
	char ntpass[33];
	char lmpass[33];
	
	fprintf(stderr, "LM Hash                         \tNT Hash\n");
	fprintf(stderr, "--------------------------------\t--------------------------------\n");
	fflush(stderr);
	for(i=1; i<argc; i++ ) {
		l = strlen(password);
		if (l & password[l-1] == '\n') password [l-1] = 0;
		lmpwdhash (hash, argv[i]);
		tohex (hash, 16, lmpass);
		ntpwdhash (hash, argv[i]);
		tohex (hash, 16, ntpass);
		printf("%s\t%s\n", lmpass, ntpass);
	}
	return 0;
}
