/* In deskey.c: */
void deskey(unsigned long [16][2],unsigned char *,int);

/* In desport.c, desborl.cas or desgnu.s: */
void des(unsigned long [16][2],unsigned char *);
extern int Asmversion;	/* 1 if we're linked with an asm version, 0 if C */

