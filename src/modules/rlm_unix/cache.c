/*
 * cache.c	Offers ability to cache /etc/group, /etc/passwd, 
 * 		/etc/shadow,
 *
 * 		All users in the passwd/shadow files are stored in a hash table.
 * 		the hash lookup is VERY fast,  generally 1.0673 comparisons per
 * 		lookup.  For the unitiated, that's blazing.  You can't have less
 * 		than one comparison, for example.
 *
 * 		The /etc/group file is stored in a singly linked list, as that 
 * 		appears to be fast enough.  It's generally a small enough file 
 * 		that hashing is	unnecessary.
 *
 * Version: $Id$
 *
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
 * 
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *  
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright 2000  The FreeRADIUS server project.
 * Copyright 1999  Jeff Carneal <jeff@apex.com>, Apex Internet Services, Inc.
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */    
static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include	"libradius.h"


#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <grp.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#if HAVE_MALLOC_H
#  include <malloc.h>
#endif

#if HAVE_SHADOW_H
#  include <shadow.h>
#endif

#if HAVE_CRYPT_H
#  include <crypt.h>
#endif 

#include "radiusd.h"
#include "cache.h"
#include "config.h"

/*
 *  Static prototypes
 */
static struct mypasswd *findHashUser(struct pwcache *cache, const char *user);
static int storeHashUser(struct pwcache *cache, struct mypasswd *new, int idx);
static int hashUserName(const char *s);

/* Builds the hash table up by storing passwd/shadow fields
 * in memory.  Returns NULL on failure, pointer to the cache on success.
 */
struct pwcache *unix_buildpwcache(const char *passwd_file,
                                  const char *shadow_file)
{
	FILE *passwd;
#if HAVE_SHADOW_H
	FILE *shadow;
#endif
	char buffer[BUFSIZE];
	char idtmp[10];
	char username[MAXUSERNAME];
	char *ptr, *bufptr;
	int len, hashindex, numread=0;
	struct mypasswd *new, *cur;

	int len2, idx;
	struct group *grp;
	struct mygroup *g_new;
	char **member;

        struct pwcache *cache;

	if((cache = malloc(sizeof *cache)) == NULL) {
		radlog(L_ERR, "HASH:  Out of memory!");
		return NULL;
	}

	memset(username, 0, MAXUSERNAME);

	/* Init hash array */
	memset(cache->hashtable, 0, sizeof cache->hashtable);
	cache->grphead = NULL;

	/*
	 *	If not set, use pre-defined defaults.
	 */
	if (!passwd_file) {
		passwd_file = PASSWDFILE;
	}

	if ((passwd = fopen(passwd_file, "r")) == NULL) {
		radlog(L_ERR, "HASH:  Can't open file %s: %s",
		    passwd_file, strerror(errno));
		unix_freepwcache(cache);
		return NULL;
	} else {
		while(fgets(buffer, BUFSIZE , passwd) != (char *)NULL) {
			numread++;

			bufptr = buffer;
			/* Get usernames from password file */
			for(ptr = bufptr; *ptr!=':'; ptr++);
			len = ptr - bufptr;
			if((len+1) > MAXUSERNAME) {
				radlog(L_ERR, "HASH:  Username too long in line: %s", buffer);
			}
			strncpy(username, buffer, len);
			username[len] = '\0';

			/* Hash the username */
			hashindex = hashUserName(username);	
			/*printf("%s:%d\n", username, hashindex);*/
	
			/* Allocate space for structure to go in hashtable */
			if((new = (struct mypasswd *)malloc(sizeof(struct mypasswd))) == NULL) {
				radlog(L_ERR, "HASH:  Out of memory!");
				fclose(passwd);
				unix_freepwcache(cache);
				return NULL;
			}
			memset((struct mypasswd *)new, 0, sizeof(struct mypasswd));

			/* Put username into new structure */
			if((new->pw_name = (char *)malloc(strlen(username)+1)) == NULL) {
				radlog(L_ERR, "HASH:  Out of memory!");
				free(new);
				fclose(passwd);
				unix_freepwcache(cache);
				return NULL;
			}
			strncpy(new->pw_name, username, strlen(username)+1);

			/* Put passwords into array, if not shadowed */
			/* Get passwords from password file (shadow comes later) */
			ptr++;
			bufptr = ptr;
			while(*ptr!=':')
				ptr++;

#if !HAVE_SHADOW_H
			/* Put passwords into new structure (*/
			len = ptr - bufptr;

			if (len > 0) {
				new->pw_passwd = (char *)malloc(len+1);
				if(new->pw_passwd == NULL) {
					radlog(L_ERR, "HASH:  Out of memory!");
					free(new->pw_name);
					free(new);
					fclose(passwd);
					unix_freepwcache(cache);
					return NULL;
				}
				strncpy(new->pw_passwd, bufptr, len);
				new->pw_passwd[len] = '\0';
			} else {
				new->pw_passwd = NULL;
			}

#endif /* !HAVE_SHADOW_H */  

			/* 
		    	 * Put uid into structure.  Not sure why, but 
			 * at least we'll have it later if we need it
			 */
			ptr++;
			bufptr = ptr;
			while(*ptr!=':')
				ptr++;
			len = ptr - bufptr;
			strncpy(idtmp, bufptr, len);
			idtmp[len] = '\0';
			new->pw_uid = (uid_t)atoi(idtmp);	

			/* 
		    	 * Put gid into structure.  
			 */
			ptr++;
			bufptr = ptr;
			while(*ptr!=':')
				ptr++;
			len = ptr - bufptr;
			strncpy(idtmp, bufptr, len);
			idtmp[len] = '\0';
			new->pw_gid = (gid_t)atoi(idtmp);	

			/* 
		    	 * Put name into structure.  
			 */
			ptr++;
			bufptr = ptr;
			while(*ptr!=':')
				ptr++;

			len = ptr - bufptr;
			if((new->pw_gecos = (char *)malloc(len+1)) == NULL) {
				radlog(L_ERR, "HASH:  Out of memory!");
				if (new->pw_passwd) free(new->pw_passwd);
				free(new->pw_name);
				free(new);
				fclose(passwd);
				unix_freepwcache(cache);
				return NULL;
			}
			strncpy(new->pw_gecos, bufptr, len);
			new->pw_gecos[len] = '\0';
				
			/* 
			 * We'll skip home dir and shell
			 * as I can't think of any use for storing them
			 */

			/*printf("User:  %s, UID:  %d, GID:  %d\n", new->pw_name, new->pw_uid, new->pw_gid);*/
			/* Store user in the hash */
			storeHashUser(cache, new, hashindex);
		}	/* End while(fgets(buffer, BUFSIZE , passwd) != (char *)NULL) */
	} /* End if */
	fclose(passwd);

#if HAVE_SHADOW_H
	/*
	 *	No shadow file, use pre-compiled default.
	 */
	if (!shadow_file) {
		shadow_file = SHADOWFILE;
	}

	/*
	 *	FIXME: Check for password expiry!
	 */
	if ((shadow = fopen(shadow_file, "r")) == NULL) {
		radlog(L_ERR, "HASH:  Can't open file %s: %s",
		    shadow_file, strerror(errno));
		unix_freepwcache(cache);
		return NULL;
	} else {
		while(fgets(buffer, BUFSIZE , shadow) != (char *)NULL) {

			bufptr = buffer;
			/* Get usernames from shadow file */
			for(ptr = bufptr; *ptr!=':'; ptr++);
			len = ptr - bufptr;
			if((len+1) > MAXUSERNAME) {
				radlog(L_ERR, "HASH:  Username too long in line: %s", buffer);
			}
			strncpy(username, buffer, len);
			username[len] = '\0';
			if((new = findHashUser(cache, username)) == NULL) {
				radlog(L_ERR, "HASH:  Username %s in shadow but not passwd??", username);
				continue;
			}

			/* 
			 * In order to put passwd in correct structure, we have
			 * to skip any struct that has a passwd already for that
			 * user
			 */ 
			cur = new;
			while(new && (strcmp(new->pw_name, username)<=0) 
						&& (new->pw_passwd == NULL)) {
				cur = new;
				new = new->next;
			}		
			/* Go back one, we passed it in the above loop */
			new = cur;

			/*
			 * When we get here, we should be at the last duplicate
			 * user structure in this hash bucket
			 */ 

			/* Put passwords into struct from shadow file */
			ptr++;
			bufptr = ptr;
			while(*ptr!=':')
				ptr++;
			len = ptr - bufptr;

			if (len > 0) {
				new->pw_passwd = (char *)malloc(len+1);
				if (new->pw_passwd == NULL) {
					radlog(L_ERR, "HASH:  Out of memory!");
					fclose(shadow);
					unix_freepwcache(cache);
					return NULL;
				}
				strncpy(new->pw_passwd, bufptr, len);
				new->pw_passwd[len] = '\0';
			} else {
				new->pw_passwd = NULL;
			}
		}
	}
	fclose(shadow);
#endif

	/* log how many entries we stored from the passwd file */
	radlog(L_INFO, "HASH:  Stored %d entries from %s", numread, passwd_file);

	/* The remainder of this function caches the /etc/group file, so it's
	 * one less thing we have to lookup on disk.  it uses getgrent(),
	 * which is quite slow, but the group file is generally small enough
	 * that it won't matter
	 * As a side note, caching the user list per group was a major pain
	 * in the ass, and I won't even need it.  I really hope that somebody
	 * out there needs and appreciates it.
	 */

	/* Make sure to begin at beginning */
	setgrent();

	numread = 0;

	/* Get next entry from the group file */
	while((grp = getgrent()) != NULL) {

		/* Make new mygroup structure in mem */
		if((g_new = (struct mygroup *)malloc(sizeof(struct mygroup))) == NULL) {
			radlog(L_ERR, "HASH:  (buildGrplist) Out of memory!");
			unix_freepwcache(cache);
			return NULL;
		}
		memset((struct mygroup*)g_new, 0, sizeof(struct mygroup));
	
		/* copy grp entries to my structure */
		len = strlen(grp->gr_name);
		if((g_new->gr_name = (char *)malloc(len+1)) == NULL) {
			radlog(L_ERR, "HASH:  (buildGrplist) Out of memory!");
			free(g_new);
			unix_freepwcache(cache);
			return NULL;
		}
		strncpy(g_new->gr_name, grp->gr_name, len);
		g_new->gr_name[len] = '\0';
		
		len = strlen(grp->gr_passwd);
		if((g_new->gr_passwd= (char *)malloc(len+1)) == NULL) {
			radlog(L_ERR, "HASH:  (buildGrplist) Out of memory!");
			free(g_new->gr_name);
			free(g_new);
			unix_freepwcache(cache);
			return NULL;
		}
		strncpy(g_new->gr_passwd, grp->gr_passwd, len);
		g_new->gr_passwd[len] = '\0';

		g_new->gr_gid = grp->gr_gid;	
		
		/* Allocate space for user list, as much as I hate doing groups
	  	 * that way.  
		 */
		for(member = grp->gr_mem; *member!=NULL; member++);
		len = member - grp->gr_mem;
		if((g_new->gr_mem = (char **)malloc((len+1)*sizeof(char **))) == NULL) {
			radlog(L_ERR, "HASH:  (buildGrplist) Out of memory!");
			free(g_new->gr_passwd);
			free(g_new->gr_name);
			free(g_new);
			unix_freepwcache(cache);
			return NULL;
		}
		/* Now go back and copy individual users into it */
		for(member = grp->gr_mem; *member; member++) {
			len2 = strlen(*member);
			idx = member - grp->gr_mem;
			if((g_new->gr_mem[idx] = (char *)malloc(len2+1)) == NULL) {
				radlog(L_ERR, "HASH:  (buildGrplist) Out of memory!");
				for(--idx;idx>=0;--idx) {
					free(g_new->gr_mem[idx]);
				}
				free(g_new->gr_passwd);
				free(g_new->gr_name);
				free(g_new);
				unix_freepwcache(cache);
				return NULL;
			}
			strncpy(g_new->gr_mem[idx], *member, len2);
			g_new->gr_mem[idx][len2] = '\0';
		}
		/* Make sure last entry in user list is 0 so we can loop thru it */
		g_new->gr_mem[len] = 0;

		/* Insert at beginning of list */
		g_new->next = cache->grphead;
		cache->grphead = g_new;

		numread++;
	}

	/* End */
	endgrent();

	radlog(L_INFO, "HASH:  Stored %d entries from /etc/group", numread);

	return cache;
}

void unix_freepwcache(struct pwcache *cache)
{
	int hashindex;
	struct mypasswd *cur, *next;

	struct mygroup *g_cur, *g_next;
	char **member;

	for(hashindex=0; hashindex<HASHTABLESIZE; hashindex++) {
		if(cache->hashtable[hashindex]) {
			cur = cache->hashtable[hashindex];
			while(cur) {
				next = cur->next;
				free(cur->pw_name);
				if (cur->pw_passwd) free(cur->pw_passwd);
				free(cur->pw_gecos);
				free(cur);
				cur = next;
			}
		}
	}	

	g_cur = cache->grphead;

	while(g_cur) {
		g_next = g_cur->next;

		/* Free name, name, member list */
		for(member = g_cur->gr_mem; *member; member++) {
			free(*member);
		}
		free(g_cur->gr_mem);
		free(g_cur->gr_name);
		free(g_cur->gr_passwd);
		free(g_cur);
		g_cur = g_next;
	}                                  

	free(cache);
}

/*
 * Looks up user in hashtable.  If user can't be found, returns 0.  
 * Otherwise returns a pointer to the structure for the user
 */
static struct mypasswd *findHashUser(struct pwcache *cache, const char *user)
{

	struct mypasswd *cur;
	int idx;

	/* first hash the username and get the index into the hashtable */
	idx = hashUserName(user);

	cur = cache->hashtable[idx];

	while((cur != NULL) && (strcmp(cur->pw_name, user))) {
		cur = cur->next;
	}

	if(cur) {
		DEBUG2("  HASH:  user %s found in hashtable bucket %d", user, idx);
		return cur;
	}

	return (struct mypasswd *)0;

}

/* Stores the username sent into the hashtable */
static int storeHashUser(struct pwcache *cache, struct mypasswd *new, int idx)
{

	/* store new record at beginning of list */
	new->next = cache->hashtable[idx];
	cache->hashtable[idx] = new;

	return 1;
}

/* Hashes the username sent to it and returns index into hashtable */
static int hashUserName(const char *s) {
	unsigned long hash = 0;

	while (*s != '\0') {
		hash = hash * 7907 + (unsigned char)*s++;
	}

	return (hash % HASHTABLESIZE);
}              

/*
 *	Emulate the cistron unix_pass function, but do it using 
 *	our hashtable (iow, make it blaze).
 * return  0 on success
 * return -1 on failure
 * return -2 on error (let caller fall back to old method)
 */
int H_unix_pass(struct pwcache *cache, char *name, char *passwd,
		VALUE_PAIR **reply_items)
{
	struct mypasswd	*pwd;
	char *encrypted_pass;
	char *encpw;

	/*
	 *	Get encrypted password from password file
	 */
	if ((pwd = findHashUser(cache, name)) == NULL) {
		/* Default to old way if user isn't hashed */
		return -2;
	}
	encrypted_pass = pwd->pw_passwd;

	/*
	 *	We might have a passwordless account.
	 */
	if(encrypted_pass == NULL) return 0;

	if(mainconfig.do_usercollide) {
		while(pwd) {
			/* 
		 	 * Make sure same user still.  If not, return as if
			 * wrong pass given 
			 */
			if(strcmp(name, pwd->pw_name)) 
				return -1;	
	
			/* 
		 	 * Could still be null passwd
			 */
			encrypted_pass = pwd->pw_passwd;
			if (encrypted_pass == NULL) {
				return 0;
			}
	
			encpw = (char *)crypt(passwd, encrypted_pass);
			/* 
		 	 * Check password
			 */
			if(strcmp(encpw, encrypted_pass) == 0) {
				/* 
				 * Add 'Class' pair here with value of full
				 * name from passwd
				 */
				if(strlen(pwd->pw_gecos))
					pairadd(reply_items, pairmake("Class", pwd->pw_gecos, T_OP_EQ));
				
				return 0;	
			}
			pwd = pwd->next;
		}
		/* 
		 * If we get here, pwd is null, and no users matched 
		 */
		return -1;
	} else {
		/*
		 *	Check encrypted password.
		 */
		encpw = (char *)crypt(passwd, encrypted_pass);

		if (strcmp(encpw, encrypted_pass))
			return -1;

		return 0;
	}
}

/*
 * Emulate groupcmp in files.c, but do it (much) faster
 * return -2 on error (let caller fall back to old method),
 * -1 on match fail, or 0 on success
 */
int H_groupcmp(struct pwcache *cache, VALUE_PAIR *check, char *username)
{
	struct mypasswd *pwd;
	struct mygroup *cur;
	char **member;

	/* get the user from the hash */
	if (!(pwd = findHashUser(cache, username)))
		return -2;

	/* let's find this group */
	if(cache->grphead) {
		cur = cache->grphead;
		while((cur) && (strcmp(cur->gr_name, (char *)check->strvalue))){
			cur = cur->next;	
		}	
		/* found the group, now compare it */
		if(!cur) {
			/* Default to old function if we can't find it */
			return -2;
		} else {
			if(pwd->pw_gid == cur->gr_gid) {
				DEBUG2("  HASH:  matched user %s in group %s", username, cur->gr_name);
				return 0;
			} else {
				for(member = cur->gr_mem; *member; member++) {
					if (strcmp(*member, pwd->pw_name) == 0) {
						DEBUG2("  HASH:  matched user %s in group %s", username, cur->gr_name);
						return 0;
					}
				}
			}
		}
	}

	return -1;
}
