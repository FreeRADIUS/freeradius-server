#ifndef RLM_MSCHAP_SMBPASS_H
#define RLM_MSCHAP_SMBPASS_H

typedef unsigned int uint16;

struct smb_passwd
{
	uid_t smb_userid;     /* this is actually the unix uid_t */
	char *smb_name;     /* username string */

	unsigned char *smb_passwd; /* Null if no password */
	unsigned char *smb_nt_passwd; /* Null if no password */

	uint16 acct_ctrl; /* account info (ACB_xxxx bit-mask) */
	time_t pass_last_set_time;    /* password last set time */
	
	char smb_name_value[256];
	unsigned char smb_passwd_value[16];
	unsigned char smb_nt_passwd_value[16];
};

/* Allowable account control bits */
#define ACB_DISABLED   0x0001  /* 1 = User account disabled */
#define ACB_HOMDIRREQ  0x0002  /* 1 = Home directory required */
#define ACB_PWNOTREQ   0x0004  /* 1 = User password not required */
#define ACB_TEMPDUP    0x0008  /* 1 = Temporary duplicate account */
#define ACB_NORMAL     0x0010  /* 1 = Normal user account */
#define ACB_MNS        0x0020  /* 1 = MNS logon user account */
#define ACB_DOMTRUST   0x0040  /* 1 = Interdomain trust account */
#define ACB_WSTRUST    0x0080  /* 1 = Workstation trust account */
#define ACB_SVRTRUST   0x0100  /* 1 = Server trust account */
#define ACB_PWNOEXP    0x0200  /* 1 = User password does not expire */
#define ACB_AUTOLOCK   0x0400  /* 1 = Account auto locked */


int hex2bin(const char *szHex, unsigned char* szBin, int len);
void bin2hex (const unsigned char *szBin, char *szHex, int len);
void pdb_init_smb(struct smb_passwd *user);
uint16 pdb_decode_acct_ctrl(const char *p);
struct smb_passwd *getsmbfilepwent(struct smb_passwd *pw_buf,FILE *fp);
struct smb_passwd *getsmbfilepwname(struct smb_passwd *pw_buf,const char *fname, const char *name);
void setsmbname(struct smb_passwd *pw_buf,const char *name);
#endif
