#pragma once
/* @copyright 2006 The FreeRADIUS server project */
RCSIDH(smbdes_h, "$Id$")

void smbhash(unsigned char *out, unsigned char const *in, unsigned char *key);
void smbdes_lmpwdhash(char const *password, uint8_t *lmhash);
void smbdes_mschap(uint8_t const win_password[16],
		 uint8_t const *challenge, uint8_t *response);
