/*
 * rlm_files.c	authorization: Find a user in the "users" file.
 *		accounting:    Write the "detail" files.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/stat.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<grp.h>
#include	<time.h>
#include	<ctype.h>
#include	<fcntl.h>

#if HAVE_MALLOC_H
#  include	<malloc.h>
#endif

#include	"radiusd.h"
#include	"modules.h"

#ifdef WITH_DBM
#  include	<dbm.h>
#endif
#ifdef WITH_NDBM
#  include	<ndbm.h>
#endif

#ifdef WITH_NDBM
static DBM	*dbmfile;
#endif

static PAIR_LIST	*users = NULL;
static PAIR_LIST	*acct_users = NULL;

#if defined(WITH_DBM) || defined(WITH_NDBM)
/*
 *	See if a potential DBM file is present.
 */
static int checkdbm(char *users, char *ext)
{
	char buffer[256];
	struct stat st;

	strcpy(buffer, users);
	strcat(buffer, ext);

	return stat(buffer, &st);
}

/*
 *	Find the named user in the DBM user database.
 *	Returns: -1 not found
 *		  0 found but doesn't match.
 *		  1 found and matches.
 */
static int dbm_find(char *name, VALUE_PAIR *request_pairs,
		VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
	datum		named;
	datum		contentd;
	char		*ptr;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	int		ret = 0;

	named.dptr = name;
	named.dsize = strlen(name);
#ifdef WITH_DBM
	contentd = fetch(named);
#endif
#ifdef WITH_NDBM
	contentd = dbm_fetch(dbmfile, named);
#endif
	if(contentd.dptr == NULL)
		return -1;

	check_tmp = NULL;
	reply_tmp = NULL;

	/*
	 *	Parse the check values
	 */
	ptr = contentd.dptr;
	contentd.dptr[contentd.dsize] = '\0';

	if (*ptr != '\n' && userparse(ptr, &check_tmp) != 0) {
		log(L_ERR|L_CONS, "Parse error (check) for user %s", name);
		pairfree(check_tmp);
		return -1;
	}
	while(*ptr != '\n' && *ptr != '\0') {
		ptr++;
	}
	if(*ptr != '\n') {
		log(L_ERR|L_CONS, "Parse error (no reply pairs) for user %s",
			name);
		pairfree(check_tmp);
		return -1;
	}
	ptr++;

	/*
	 *	Parse the reply values
	 */
	if (userparse(ptr, &reply_tmp) != 0) {
		log(L_ERR|L_CONS, "Parse error (reply) for user %s", name);
		pairfree(check_tmp);
		pairfree(reply_tmp);
		return -1;
	}

	/*
	 *	See if the check_pairs match.
	 */
	if (paircmp(request_pairs, check_tmp, reply_pairs) == 0) {
		ret = 1;
		pairmove(reply_pairs, &reply_tmp);
		pairmove2(reply_pairs, &reply_tmp, PW_FALL_THROUGH);
		pairmove(check_pairs, &check_tmp);
	}
	pairfree(reply_tmp);
	pairfree(check_tmp);

	return ret;
}
#endif /* DBM */

/*
 *     See if a VALUE_PAIR list contains Fall-Through = Yes
 */
static int fallthrough(VALUE_PAIR *vp)
{
	VALUE_PAIR *tmp;

	tmp = pairfind(vp, PW_FALL_THROUGH);

	return tmp ? tmp->lvalue : 0;
}

#define DL_FLAG_START	  1
#define DL_FLAG_STOP	  2
#define DL_FLAG_ACCT_ON   4
#define DL_FLAG_ACCT_OFF  8
#define DL_FLAG_ALIVE	 16

typedef struct dyn_log {
	char dir[256];
	char fname[256];
	char fmt[1024];
	char mode[5];
	int flags;
} DYN_LOG;
#define MAX_LOGS 20
static DYN_LOG logcfg[MAX_LOGS];
static int logcnt;

/*
 * Initialize dynamic logging
 */
void file_getline(FILE *f,char * buff,int len)
{
	char tmp[2048];
	int i;

	tmp[0] = '\0';
	while (!feof(f)) {
		fgets(tmp,len,f);
		if (tmp[0] != '#') {
			break;
		}
	}
	i = 0;
	while (tmp[i] != '\n') {
		*buff = tmp[i];
		buff++;
		i++;
	}
}

void file_dynamic_log_init(void )
{
	FILE * f;
	char fn[1024];

	sprintf(fn,"%s/%s",radius_dir,"rlm_files_log.cfg");
	logcnt = 0;
	f = fopen(fn, "r");
	if (f != NULL) {
		log_debug("Loading %s",fn);
		while (logcnt < MAX_LOGS) {
			file_getline(f,logcfg[logcnt].dir,sizeof(logcfg[logcnt].dir));
			file_getline(f,logcfg[logcnt].fname,sizeof(logcfg[logcnt].fname));
			file_getline(f,logcfg[logcnt].fmt,sizeof(logcfg[logcnt].fmt));
			file_getline(f,logcfg[logcnt].mode,sizeof(logcfg[logcnt].mode));
			file_getline(f,fn,sizeof(fn));
			logcfg[logcnt].flags = atoi(fn);
			if ((logcfg[logcnt].flags != 0) &&
			    (strlen(logcfg[logcnt].mode) != 0)) {
				logcnt++;
			} else {
				break;
			}
		}
		log_debug("%d logs configured",logcnt);
		fclose(f);
	} else {
		log_debug("Error loading %s",fn);
	}


}
/*
 *	(Re-)read the "users" file into memory.
 */
static int file_init(int argc, char **argv)
{
	char		fn[1024];
	char		acct_fn[1024];
	char		*ptr;

	file_dynamic_log_init();

	/*
	 *  This really should be fixed to do something better...
	 */
	ptr = argv[0] ? argv[0] : RADIUS_USERS;
	sprintf(fn, "%s/%s", radius_dir, ptr);
	ptr = (argv[0] && argv[1]) ? argv[1] : RADIUS_ACCT_USERS;
	sprintf(acct_fn, "%s/%s", radius_dir, ptr);

#if defined(WITH_DBM) || defined(WITH_NDBM)
	if (!use_dbm &&
	    (checkdbm(ptr, ".dir") == 0 ||
	     checkdbm(ptr, ".db") == 0)) {
		log(L_INFO|L_CONS, "DBM files found but no -b flag "
			"given - NOT using DBM");
	}
#endif

	if (!use_dbm) {
		users = pairlist_read(fn, 1);
		acct_users = pairlist_read(acct_fn, 1);
	}

	/*
	 *	Walk through the 'users' file list, looking for
	 *	check-items in the reply-item lists.
	 */
	if (debug_flag) {
	  int acctfile=0;
	  PAIR_LIST *entry;
	  VALUE_PAIR *vp;

	  entry = users;
	  while (entry) {
	    vp = entry->reply;
	    while (vp) {
	      /*
	       *	If it's NOT a vendor attribute,
	       *	and it's NOT a wire protocol
	       *	and we ignore Fall-Through,
	       *	then bitch about it, giving a good warning message.
	       */
	      if (!(vp->attribute & ~0xffff) &&
		  (vp->attribute > 0xff) &&
		  (vp->attribute != PW_FALL_THROUGH)) {
		log_debug("[%s]:%d WARNING! Found possible check item '%s' in "
			  "the list of reply items for user %s.",
			  acctfile?acct_fn:fn, entry->lineno, vp->name,
			  entry->name);
	      }
	      vp = vp->next;
	    }
	    entry = entry->next;
	    if(!entry && !acctfile) {
	      entry=acct_users;
	      acctfile=1;
	    }
	  }

	}

	return users ? 0 : -1;
}

/*
 *	Find the named user in the database.  Create the
 *	set of attribute-value pairs to check and reply with
 *	for this user from the database. The main code only
 *	needs to check the password, the rest is done here.
 */
static int file_authorize(REQUEST *request,
		VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
	int		nas_port = 0;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	VALUE_PAIR	*tmp, *tmp2;
	PAIR_LIST	*pl;
	int		found = 0;
#if defined(WITH_DBM) || defined(WITH_NDBM)
	int		i, r;
	char		buffer[256];
#endif
	char		*name;

	request_pairs = request->packet->vps;

 	/*
	 *	Grab the canonical user name.
	 */
	name = request->username->strvalue;

	/*
	 *	Find the NAS port ID.
	 */
	if ((tmp = pairfind(request_pairs, PW_NAS_PORT_ID)) != NULL)
		nas_port = tmp->lvalue;

	/*
	 *	Find the entry for the user.
	 */
#if defined(WITH_DBM) || defined(WITH_NDBM)
	/*
	 *	FIXME: move to rlm_dbm.c
	 */
	if (use_dbm) {
		/*
		 *	FIXME: No Prefix / Suffix support for DBM.
		 */
		sprintf(buffer, "%s/%s", radius_dir, RADIUS_USERS);
#ifdef WITH_DBM
		if (dbminit(buffer) != 0)
#endif
#ifdef WITH_NDBM
		if ((dbmfile = dbm_open(buffer, O_RDONLY, 0)) == NULL)
#endif
		{
			log(L_ERR|L_CONS, "cannot open dbm file %s",
				buffer);
			return RLM_AUTZ_FAIL;
		}

		r = dbm_find(name, request_pairs, check_pairs, reply_pairs);
		if (r > 0) found = 1;
		if (r <= 0 || fallthrough(*reply_pairs)) {

			pairdelete(reply_pairs, PW_FALL_THROUGH);

			sprintf(buffer, "DEFAULT");
			i = 0;
			while ((r = dbm_find(buffer, request_pairs,
			       check_pairs, reply_pairs)) >= 0 || i < 2) {
				if (r > 0) {
					found = 1;
					if (!fallthrough(*reply_pairs))
						break;
					pairdelete(reply_pairs,PW_FALL_THROUGH);
				}
				sprintf(buffer, "DEFAULT%d", i++);
			}
		}
#ifdef WITH_DBM
		dbmclose();
#endif
#ifdef WITH_NDBM
		dbm_close(dbmfile);
#endif
	} else
	/*
	 *	Note the fallthrough through the #endif.
	 */
#endif

	for(pl = users; pl; pl = pl->next) {

		if (strcmp(name, pl->name) && strcmp(pl->name, "DEFAULT"))
			continue;

		if (paircmp(request_pairs, pl->check, reply_pairs) == 0) {
			DEBUG2("  users: Matched %s at %d",
			       pl->name, pl->lineno);
			found = 1;
			check_tmp = paircopy(pl->check);
			/*
			 *	Smash the operators to '+=', so that
			 *	pairmove() will do the right thing...
			 */
			for (tmp = check_tmp; tmp; tmp = tmp->next) {
			  tmp->operator = T_OP_ADD;
			}
			reply_tmp = paircopy(pl->reply);
			pairmove(reply_pairs, &reply_tmp);
			pairmove(check_pairs, &check_tmp);
			pairfree(reply_tmp);
			pairfree(check_tmp); /* should be NULL */
			/*
			 *	Fallthrough?
			 */
			if (!fallthrough(pl->reply))
				break;
		}
	}

	/*
	 *	See if we succeeded.
	 */
	if (!found)
		return RLM_AUTZ_NOTFOUND; /* didn't find the user */

	/*
	 *	Add the port number to the Framed-IP-Address if
	 *	vp->addport is set, or if the Add-Port-To-IP-Address
	 *	pair is present.
	 *
	 *	FIXME: this should not happen here, but
	 *	after module_authorize in the main code!
	 */
	if ((tmp = pairfind(*reply_pairs, PW_FRAMED_IP_ADDRESS)) != NULL) {
		tmp2 = pairfind(*reply_pairs, PW_ADD_PORT_TO_IP_ADDRESS);
		if (tmp->addport || (tmp2 && tmp2->lvalue)) {
			tmp->lvalue = htonl(ntohl(tmp->lvalue) + nas_port);
			tmp->addport = 0;
		}
		pairdelete(reply_pairs, PW_ADD_PORT_TO_IP_ADDRESS);
	}

	/*
	 *	Remove server internal parameters.
	 */
	pairdelete(reply_pairs, PW_FALL_THROUGH);

	return RLM_AUTZ_OK;
}

/*
 *	Authentication - unused.
 */
static int file_authenticate(REQUEST *request)
{
	request = request;
	return RLM_AUTH_OK;
}

/*
 * Write the dynamic log files
 */
void file_write_dynamic_log(REQUEST * request)
{
	char fn[1024];
	char buffer[4096];
	int x,y;
	VALUE_PAIR * pair;
	FILE * f;

	pair = pairfind(request->packet->vps,PW_ACCT_STATUS_TYPE);
	for (x = 0; x < logcnt; x++) {
		if (((pair->lvalue == PW_STATUS_START) && (logcfg[x].flags & DL_FLAG_START)) ||
		    ((pair->lvalue == PW_STATUS_STOP) && (logcfg[x].flags & DL_FLAG_STOP)) ||
		    ((pair->lvalue == PW_STATUS_ACCOUNTING_ON) && (logcfg[x].flags & DL_FLAG_ACCT_ON)) ||
		    ((pair->lvalue == PW_STATUS_ACCOUNTING_OFF) && (logcfg[x].flags & DL_FLAG_ACCT_OFF)) ||
		    ((pair->lvalue == PW_STATUS_ALIVE) && (logcfg[x].flags & DL_FLAG_ALIVE))) {
			y = radius_xlat2(fn,sizeof(fn),logcfg[x].dir,request,request->packet->vps);
			(void) mkdir(fn, 0755);
			strcat(fn,"/");
			y++;
			/* FIXME must get the reply packet */
			radius_xlat2(&fn[y],sizeof(fn)-y,logcfg[x].fname,request,request->packet->vps);
			if (strcasecmp(logcfg[x].mode,"d") == 0) {
				remove(fn);
			} else {
				if (fn[y] == '|') {
					f = popen(&fn[y+1],logcfg[x].mode);
				} else {
					f = fopen(fn,logcfg[x].mode);
				}
				if (f) {
					/* FIXME must get the reply packet */
					radius_xlat2(buffer,sizeof(buffer),logcfg[x].fmt,request,request->packet->vps);
					fprintf(f,"%s\n",buffer);
					if (fn[y] == '|') {
						pclose(f);
					} else {
						fclose(f);
					}
				} else {
					if (fn[y] == '|') {
						log_debug("Error opening pipe %s",fn[y+1]);
					} else {
						log_debug("Error opening log %s",fn);
					}
				}
			}
		}


	}
}

/*
 *	Pre-Accounting - read the acct_users file for check_items and
 *	config_items. Reply items are Not Recommended(TM) in acct_users,
 *	except for Fallthrough, which should work
 *
 *	This function is mostly a copy of file_authorize
 */
static int file_preacct(REQUEST *request)
{
	VALUE_PAIR	*namepair;
	const char	*name;
	VALUE_PAIR	*request_pairs;
	VALUE_PAIR	**config_pairs;
	VALUE_PAIR	*reply_pairs=0;
	VALUE_PAIR	*check_tmp;
	VALUE_PAIR	*reply_tmp;
	VALUE_PAIR	*tmp;
	PAIR_LIST	*pl;
	int		found = 0;
#if defined(WITH_DBM) || defined(WITH_NDBM)
	int		i, r;
	char		buffer[256];
#endif

	namepair = pairfind(request->packet->vps, PW_USER_NAME);
	name = namepair?(char *)namepair->strvalue:"NONE";
	request_pairs = request->packet->vps;
	config_pairs = &request->config_items;

	/*
	 *	Find the entry for the user.
	 */
#if defined(WITH_DBM) || defined(WITH_NDBM)
	/*
	 *	FIXME: move to rlm_dbm.c
	 */
	if (use_dbm) {
		/*
		 *	FIXME: No Prefix / Suffix support for DBM.
		 */
		sprintf(buffer, "%s/%s", radius_dir, RADIUS_ACCT_USERS);
#ifdef WITH_DBM
		if (dbminit(buffer) != 0)
#endif
#ifdef WITH_NDBM
		if ((dbmfile = dbm_open(buffer, O_RDONLY, 0)) == NULL)
#endif
		{
			log(L_ERR|L_CONS, "cannot open dbm file %s",
				buffer);
			return RLM_PRAC_FAIL;
		}

		r = dbm_find(name, request_pairs, config_pairs, &reply_pairs);
		if (r > 0) found = 1;
		if (r <= 0 || fallthrough(*reply_pairs)) {

			pairdelete(reply_pairs, PW_FALL_THROUGH);

			sprintf(buffer, "DEFAULT");
			i = 0;
			while ((r = dbm_find(buffer, request_pairs,
			       config_pairs, &reply_pairs)) >= 0 || i < 2) {
				if (r > 0) {
					found = 1;
					if (!fallthrough(*reply_pairs))
						break;
					pairdelete(reply_pairs,PW_FALL_THROUGH);
				}
				sprintf(buffer, "DEFAULT%d", i++);
			}
		}
#ifdef WITH_DBM
		dbmclose();
#endif
#ifdef WITH_NDBM
		dbm_close(dbmfile);
#endif
	} else
	/*
	 *	Note the fallthrough through the #endif.
	 */
#endif

	for(pl = acct_users; pl; pl = pl->next) {

		if (strcmp(name, pl->name) && strcmp(pl->name, "DEFAULT"))
			continue;

		if (paircmp(request_pairs, pl->check, &reply_pairs) == 0) {
			DEBUG2("  acct_users: Matched %s at %d",
			       pl->name, pl->lineno);
			found = 1;
			check_tmp = paircopy(pl->check);
			/*
			 *	Smash the operators to '+=', so that
			 *	pairmove() will do the right thing...
			 */
			for (tmp = check_tmp; tmp; tmp = tmp->next) {
			  tmp->operator = T_OP_ADD;
			}
			reply_tmp = paircopy(pl->reply);
			pairmove(&reply_pairs, &reply_tmp);
			pairmove(config_pairs, &check_tmp);
			pairfree(reply_tmp);
			pairfree(check_tmp); /* should be NULL */
			/*
			 *	Fallthrough?
			 */
			if (!fallthrough(pl->reply))
				break;
		}
	}

	/*
	 *	See if we succeeded.
	 */
	if (!found)
		return RLM_PRAC_OK; /* on to the next module */

	/*
	 *	FIXME: log a warning if there are any reply items other than
	 *	Fallthrough
	 */
	pairfree(reply_pairs); /* Don't need these */

	return RLM_PRAC_OK;
}

/*
 *	Accounting - write the detail files.
 */
static int file_accounting(REQUEST *request)
{
	FILE		*outfd;
	char		nasname[128];
	char		buffer[512];
	char		*s;
	VALUE_PAIR	*pair;
	uint32_t	nas;
	NAS		*cl;
	long		curtime;
	int		ret = RLM_ACCT_OK;
	struct stat	st;

	/*
	 *	See if we have an accounting directory. If not,
	 *	return.
	 */
	if (stat(radacct_dir, &st) < 0) {
		DEBUG("No accounting directory %s", radacct_dir);
		return RLM_ACCT_OK;
	}
	curtime = time(0);

	/*
	 *	Find out the name of this terminal server. We try
	 *	to find the PW_NAS_IP_ADDRESS in the naslist file.
	 *	If that fails, we look for the originating address.
	 *	Only if that fails we resort to a name lookup.
	 */
	cl = NULL;
	nas = request->packet->src_ipaddr;
	if ((pair = pairfind(request->packet->vps, PW_NAS_IP_ADDRESS)) != NULL)
		nas = pair->lvalue;
	if (request->proxy && request->proxy->src_ipaddr)
		nas = request->proxy->src_ipaddr;

	if ((cl = nas_find(nas)) != NULL) {
		if (cl->shortname[0])
			strcpy(nasname, cl->shortname);
		else
			strcpy(nasname, cl->longname);
	}

	if (cl == NULL) {
		s = ip_hostname(nas);
		if (strlen(s) >= sizeof(nasname) || strchr(s, '/'))
			return -1;
		strcpy(nasname, s);
	}

	/*
	 *	Create a directory for this nas.
	 */
	sprintf(buffer, "%s/%s", radacct_dir, nasname);
	(void) mkdir(buffer, 0755);

	/*
	 *	Write Detail file.
	 */
	sprintf(buffer, "%s/%s/%s", radacct_dir, nasname, "detail");
	if ((outfd = fopen(buffer, "a")) == NULL) {
		log(L_ERR, "Acct: Couldn't open file %s", buffer);
		ret = RLM_ACCT_FAIL;
	} else {

		/* Post a timestamp */
		fputs(ctime(&curtime), outfd);

		/* Write each attribute/value to the log file */
		pair = request->packet->vps;
		while (pair) {
			if (pair->attribute != PW_PASSWORD) {
				fputs("\t", outfd);
				fprint_attr_val(outfd, pair);
				fputs("\n", outfd);
			}
			pair = pair->next;
		}

		/*
		 *	Add non-protocol attibutes.
		 */
		fprintf(outfd, "\tTimestamp = %ld\n", curtime);
		if (request->packet->verified)
			fputs("\tRequest-Authenticator = Verified\n", outfd);
		else
			fputs("\tRequest-Authenticator = None\n", outfd);
		fputs("\n", outfd);
		fclose(outfd);
	}
	file_write_dynamic_log(request);
	return ret;
}


/*
 *	Clean up.
 */
static int file_detach(void)
{
	pairlist_free(&users);
	pairlist_free(&acct_users);
	return 0;
}


/* globally exported name */
module_t rlm_files = {
	"files",
	0,				/* type: reserved */
	file_init,			/* initialization */
	file_authorize, 		/* authorization */
	file_authenticate,		/* authentication */
	file_preacct,			/* preaccounting */
	file_accounting,		/* accounting */
	file_detach,			/* detach */
};

