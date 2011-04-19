/* Copyright 2006 The FreeRADIUS server project */

#ifndef _SMBDES_H
#define _SMBDES_H

#include <freeradius-devel/ident.h>
RCSIDH(smbdes_h, "$Id$")

void smbhash(unsigned char *out, const unsigned char *in, unsigned char *key);
void smbdes_lmpwdhash(const char *password, uint8_t *lmhash);
void smbdes_mschap(const uint8_t win_password[16],
		 const uint8_t *challenge, uint8_t *response);

#endif /*_SMBDES_H*/
