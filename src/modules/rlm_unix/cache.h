/*
 * cache.h   Definitions for structures and functions needed in cache.c
 *
 * Version: cache.c  0.99  04-13-1999  jeff@apex.net
 */
#ifndef _CACHE_H
#define _CACHE_H

/* Misc definitions */
#define BUFSIZE  1024
#define HASHTABLESIZE 100000
#endif

/* Structure definitions */
struct mypasswd {
	char    *pw_name;       /* user name */
	char    *pw_passwd;     /* user password */
	uid_t   pw_uid;         /* user id */
	gid_t   pw_gid;         /* group id */
	char	*pw_gecos;	/* full name (used for class attr */
	struct mypasswd *next;  /* next */
};

struct mygroup {
	char    *gr_name;        /* group name */
	char    *gr_passwd;      /* group password */
	gid_t   gr_gid;          /* group id */
	char    **gr_mem;        /* group members */
	struct mygroup *next;    /* next */
};

struct pwcache {
  struct mypasswd *hashtable[HASHTABLESIZE];
  struct mygroup *grphead;
};

/* Function prototypes */
struct pwcache *unix_buildpwcache(const char *passwd_file,
                                  const char *shadow_file,
                                  const char *group_file);
int H_unix_pass(struct pwcache *cache, char *name, char *passwd,
                VALUE_PAIR **reply_items);
int H_groupcmp(struct pwcache *cache, VALUE_PAIR *check, char *username);
void unix_freepwcache(struct pwcache *cache);
