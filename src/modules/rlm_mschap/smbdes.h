#ifndef _SMBDES_H
#define _SMBDES_H

void smbdes_lmpwdhash(const unsigned char *password,unsigned char *lmhash);
void smbdes_mschap(const unsigned char *win_password,
		 const unsigned char *challenge, unsigned char *response);

#endif /*_SMBDES_H*/
