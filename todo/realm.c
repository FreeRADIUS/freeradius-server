/*
 * realm.c	Read and process realm file.
 *
 *
 * Version:	@(#)  realm.c  16-Jul-1998  miquels@cistron.nl
 *
 */

char util_sccsid[] =
"@(#)realm.c	1.0 Copyright 1998 Cistron Internet Services B.V.";

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>

#include	"radiusd.h"

CONF *conf;

struct tpl {
	char	*name;
	int	offset;
};

static struct tpl tpl[] = {
  {  "realm",		offsetof(CONF, realm)		},
  {  "radwtmp", 	offsetof(CONF, radwtmp)		},
  {  "radutmp", 	offsetof(CONF, radutmp)		},
  {  "acctdir", 	offsetof(CONF, acctdir)		},
  {  "acctdir2", 	offsetof(CONF, acctdir2)	},
  {  "authproxy", 	offsetof(CONF, authproxy)	},
  {  "acctproxy", 	offsetof(CONF, acctproxy)	},
  {  "striprealm", 	offsetof(CONF, striprealm)	},
  {  NULL,		-1				},
};

/*
 *	Initialize the config file structs.
 */
static CONF *initconf(void)
{
	conf = (CONF *)malloc(sizeof(CONF));
	memset(conf, 0, sizeof(CONF));

	strcpy(conf->radutmp, RADUTMP);
	strcpy(conf->radutmp, RADWTMP);
	strcpy(conf->confdir, RADIUS_DIR);
	strcpy(conf->acctdir, RADACCT_DIR);
	strcpy(conf->logdir, RADLOG_DIR);
	strcpy(conf->pidfile, RADIUS_PID);
	strcpy(conf->checkrad,  CHECKRAD1);
	strcpy(conf->checkrad2, CHECKRAD2);
	strcpy(conf->striprealm, "yes");

	return conf;
}

/*
 *	Read the config file.
 */
int readconf(char *conffile)
{
	FILE	*fp;
	char	buf[128];
	char	*key, *val;
	char	lineno = 0;
	CONF	*cf, *cf2;
	int	first = 1;

	/*
	 *	Initialize.
	 */
	if ((fp = fopen(conffile, "r")) == NULL) {
		log(L_ERR, "%s: %s", conffile, strerror(errno));
		return -1;
	}
	cf = initconf();

	/*
	 *	Read config file line by line.
	 */
	while(fgets(buf, sizeof(buf), fp)) {
		lineno++;
		/*
		 *	Skip comments and empty lines, and split
		 *	the rest up in key/value pairs.
		 */
		if (buf[0] == '#' || buf[0] == '\n' || buf[0] == 0)
			continue;
		key = strtok(buf, " \t");
		val = strtok(NULL, "\n");
		if (key == NULL || key[0] == 0 ||
		    val == NULL || val[0] == 0) {
			log(L_ERR, "%s[%d]: syntax error", conffile, lineno);
			return -1;
		}

		/*
		 *	The "realm" key is special, we allocate a new
		 *	CONF now _unless_ the "realm" keyword is the
		 *	first keyword in the file.
		 */
		if (strcmp(key, "realm") == 0 && !first) {
			cf2 = (CONF *)malloc(sizeof(CONF));
			memcpy(cf2, cf, sizeof(CONF));
			strcpy(cf2->striprealm, "no");
			cf->next = cf2;
			cf = cf2;
		}
		first = 0;

		/*
		 *	Find the key in our keyword list and
		 *	calculate the offset into the CONF struct
		 *	for the value.
		 */
		for(i = 0; tpl[i].name; i++) {
			if (strcmp(tpl[i].name, key) == 0)
				break;
		}
		if (tpl[i].name == NULL) {
			log(L_ERR, "%s[%d]: unknown keyword %s",
				conffile, lineno, key);
			return -1;
		}
		strcpy((char *)cf + tpl[i].offset, val);
	}
	fclose (fp);

	return 0;
}

/*
 *	Find the configuration for a certain realm.
 *	We modify the username in-place, so this function should
 *	only be called once.
 */
CONF *getconf(char *username)
{
	char	buf[128];
	char	*realm, *user;
	CONF	*cf;

	strncpy(buf, username, 128);
	buf[128] = 0;

	/*
	 *	Split username and realm. We support both
	 *	realm\username and username@realm.
	 */
	if ((realm = strchr(buf, '@')) != NULL) {
		*realm++ = 0;
		user = buf;
	} else if ((user = strchr(buf, '\\')) != NULL) {
		*user++ = 0;
		realm = buf;
	} else
		return conf;

	/*
	 *	Find this realm in the conffile, if not found use
	 *	the default (local) realm and do not strip the realm,
	 *	If found strip realm from username if needed.
	 */
	for (cf = conf; cf; cf = cf->next)
		if (strcasecmp(realm, cf->realm) == 0)
			break;
	if (cf == NULL) {
		cf = conf;
	} else {
		if (strcmp(cf->striprealm, "yes") == 0)
			strcpy(username, user);
	}

	return conf;
}

