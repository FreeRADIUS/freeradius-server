/*
 * cache.h   Definitions for structures and functions needed in cache.c
 *
 * Version: cache.c  0.99  04-13-1999  jeff@apex.net
 */    
#ifndef _CACHE_H
#define _CACHE_H

/* Misc definitions */
#define BUFSIZE  1024
#define MAXUSERNAME 20
#define HASHTABLESIZE 100000
#define PASSWDFILE "/etc/passwd"
#define SHADOWFILE "/etc/shadow"
#endif

/* Structure definitions */
struct mypasswd {
	char    *pw_name;       /* user name */
	char    *pw_passwd;     /* user password */
	uid_t   pw_uid;         /* user id */
	gid_t   pw_gid;         /* group id */
	int     loggedin;       /* number of logins */
	struct mypasswd *next;  /* next */
};

struct mygroup {
	char    *gr_name;        /* group name */
	char    *gr_passwd;      /* group password */
	gid_t   gr_gid;          /* group id */
	char    **gr_mem;        /* group members */
	struct mygroup *next;    /* next */
};         

/* Function prototypes */
int unix_buildHashTable(const char *passwd_file, const char *shadow_file);
int unix_buildGrpList();
int unix_hashradutmp(void);
int H_unix_pass(char *name, char *passwd);
int H_groupcmp(VALUE_PAIR *check, char *username);
