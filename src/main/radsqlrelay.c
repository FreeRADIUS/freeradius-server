/*
 * radsqlrelay.c	This program tails a detail logfile, reads the log
 *			entries, forwards them to a remote sql database
 *			and moves the processed records to another file.
 *
 *			Used to replicate accounting records to one (central)
 *			server - works even if remote server has extended
 *			downtime, and/or if this program is restarted.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001 Cistron Internet Services B.V.
 * Copyright 2002 Simon Ekstrand <simon@routemeister.net>
 * Copyright 2004 Kostas Kalavras <kkalev@noc.ntua.gr>
 *
 */
char radrelay_rcsid[] =
"$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <sys/time.h>
#include <sys/stat.h>

#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>

#include "radiusd.h"
#include "conf.h"
#include "radpaths.h"
#include "missing.h"
#include "conffile.h"
#include "ltdl.h"
#include "modules.h"

#define METHOD_ACCOUNTING 3

#define DEFAULT_SLEEP		25
#define DEFAULT_SLEEP_EVERY	1
#define DEFAULT_BACKOFF		5


const char *progname = "radsqlrelay";

int debug_flag = 0;
const char *radlog_dir = NULL;
const char *radlib_dir = NULL;

const char *radius_dir = NULL;
const char *radacct_dir = NULL;
uint32_t myip = INADDR_ANY;
int log_stripped_names;
struct main_config_t mainconfig;
void *rad_malloc(size_t size);

/*
 *	Possible states for request->state
 */
#define		STATE_EMPTY	0
#define		STATE_BUSY1	1
#define		STATE_BUSY2	2
#define		STATE_FULL	3

/*
 *	Possible states for the loop() function.
 */
#define		STATE_RUN	0
#define		STATE_BACKLOG	1
#define		STATE_WAIT	2
#define		STATE_SHUTDOWN	3

#define		NR_SLOTS	64

/*
 *	A relay request.
 */
struct relay_request {
	int		state;				/* REQ_* state */
	uint32_t	client_ip;			/* Client-IP-Addr */
	REQUEST		*req;				/* Radius request */
};

struct sql_module {
	lt_dlhandle	handle;				/* Sql module handle */
	module_t	*module;			/* Sql module structure */
	void		*modinfo;			/* Private module structure */
};

struct relay_misc {
	uint32_t 		dst_addr;		/* Destination address */
	char			detail[1024];		/* Detail file */
	char			*instance;		/* SQL module instance (if needed) */
	int			sleep_time;		/* Sleep time (ms) between calls to do_send */
	int			backoff_time;		/* Backoff time (ms) between calls to do_send */
	int			sleep_every;		/* Sleep every so many packets sent, default 1 */
	int			records_print;		/* Every how many records should we print out statistics */
	struct sql_module	*sql;			/* SQL module structure */
};

struct relay_stats {
	time_t			startup;
	uint32_t		records_read;		/* Records read */
	uint32_t		records_sent;		/* Records sent */
	uint32_t		last_print_records;	/* Records read on last statistics printout */
};


struct relay_request slots[NR_SLOTS];
int request_head;
int got_sigterm = 0;
int sql_log = 0;


void sigterm_handler(int sig);
void ms_sleep(int msec);
int isdateline(char *d);
int read_one(FILE *fp, struct relay_request *req);
int do_send(struct relay_request *r,struct sql_module *sql);
int detail_move(char *from, char *to);
void loop(struct relay_misc *r_args);
struct sql_module *init_sql(struct relay_misc *r);
void radsqlrelay_usage(void);


void sigterm_handler(int sig)
{
	signal(sig, sigterm_handler);
	got_sigterm = 1;
}


/*
 *	Sleep a number of milli seconds
 */
void inline ms_sleep(int msec)
{
	if (msec){
		struct timeval tv;

		tv.tv_sec  = (msec / 1000);
		tv.tv_usec = (msec % 1000) * 1000;
		select(0, NULL, NULL, NULL, &tv);
	}
	else
		return;
}

/*
 *	Does this (remotely) look like "Tue Jan 23 06:55:48 2001" ?
 */
int inline isdateline(char *d)
{
	int y;

	return sscanf(d, "%*s %*s %*d %*d:%*d:%*d %d", &y);
}


/*
 *	Read one request from the detail file.
 *	Note that the file is locked during the read, and that
 *	we return *with the file locked* if we reach end-of-file.
 *
 *	STATE_EMPTY:	Slot is empty.
 *	STATE_BUSY1:	Looking for start of a detail record (timestamp)
 *	STATE_BUSY2:	Reading the A/V pairs of a detail record.
 *	STATE_FULL:	Read the complete record.
 *
 */
int read_one(FILE *fp, struct relay_request *r_req)
{
	VALUE_PAIR *vp;
	char *s;
	char buf[256];
	char key[32], val[32];
	int skip;
	long fpos;
	int x;
	unsigned int i = 0;

	/* Never happens */
	if (r_req->state == STATE_FULL)
		return 0;

	if (r_req->state == STATE_EMPTY)
		r_req->state = STATE_BUSY1;


	/*
	 * Try to lock the detail-file.
	 * If lockf is used we want to lock the _whole_ file, hence the
	 * fseek to the start of the file.
	 */
	fpos = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	do {
		x = rad_lockfd_nonblock(fileno(fp), 0);
		if (x == -1)
			ms_sleep(25);
	} while (x == -1 && i++ < 80);

	if (x == -1)
		return 0;

redo:
	s = NULL;
	fseek(fp, fpos, SEEK_SET);
	fpos = ftell(fp);
	while ((s = fgets(buf, sizeof(buf), fp)) != NULL) {
		/*
		 * Eek! We've just read a broken attribute.
		 * This does seem to happen every once in a long while
		 * due to some quirk involving threading, multiple processes
		 * going for the detail file lock at once and writes not
		 * being flushed properly. Things should be ok next time
		 * around.
		 */
		if (!strlen(buf)) {
			fprintf(stdout, "%s: read_one: ZERO BYTE\n",progname);
                       fseek(fp, fpos + 1, SEEK_SET);
                       break;
               } else if (buf[strlen(buf) - 1] != '\n') {
			fprintf(stdout, "%s: read_one: BROKEN ATTRIBUTE\n",progname);
			fseek(fp, fpos + strlen(buf), SEEK_SET);
			break;
		}
		if (r_req->state == STATE_BUSY1) {
			if (isdateline(buf)) {
				r_req->state = STATE_BUSY2;
			}
		} else if (r_req->state == STATE_BUSY2) {
			if (buf[0] != ' ' && buf[0] != '\t') {
				r_req->state = STATE_FULL;
				break;
			}
			/*
			 *	Found A/V pair, but we skip non-protocol
			 *	values.
			 */
			skip = 0;
			if (sscanf(buf, "%31s = %31s", key, val) == 2) {
				if (!strcasecmp(key, "Timestamp")) {
					r_req->req->timestamp = atoi(val);
					skip++;
				} else
				if (!strcasecmp(key, "Client-IP-Address")) {
					r_req->client_ip = ip_getaddr(val);
					skip++;
				} else
				if (!strcasecmp(key, "Request-Authenticator"))
					skip++;
			}
			if (!skip) {
				vp = NULL;
				if (userparse(buf, &vp) > 0 &&
				    (vp != NULL) &&
				    (vp->attribute < 256 ||
				     vp->attribute > 65535) &&
				    vp->attribute != PW_VENDOR_SPECIFIC) {
					pairadd(&(r_req->req->packet->vps), vp);
					if (vp->attribute == PW_USER_NAME)
						r_req->req->username = vp;
				} else {
				  pairfree(&vp);
				}
			}
		}
		fpos = ftell(fp);
	}
	clearerr(fp);

	if (r_req->state == STATE_FULL) {
		/*
		 *	w00 - we just completed reading a record in full.
		 */

		/*
		 * Check that we have an Acct-Status-Type attribute. If not
		 * reject the record
		 */
		if (pairfind(r_req->req->packet->vps, PW_ACCT_STATUS_TYPE) == NULL){
			fprintf(stdout, "%s: read_one: No Acct-Status-Type attribute present. Rejecting record.\n",
				progname);
			r_req->state = STATE_BUSY1;
			if (r_req->req->packet->vps != NULL) {
				pairfree(&r_req->req->packet->vps);
				r_req->req->packet->vps = NULL;
			}
			r_req->req->timestamp = 0;
			r_req->client_ip = 0;
			goto redo;
		}
		if (r_req->req->timestamp == 0)
			r_req->req->timestamp = time(NULL);
		if ((vp = pairfind(r_req->req->packet->vps, PW_ACCT_DELAY_TIME)) != NULL) {
			r_req->req->timestamp -= vp->lvalue;
			vp->lvalue = 0;
		}
	}

	if (s == NULL) {
		/*
		 *	Apparently we reached end of file. If we didn't
		 *	partially read a record, we let the caller know
		 *	we're at end of file.
		 */
		if (r_req->state == STATE_BUSY1) {
			r_req->state = STATE_EMPTY;
		}
		if (r_req->state == STATE_EMPTY || r_req->state == STATE_FULL)
			return EOF;
	}

	fpos = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	rad_unlockfd(fileno(fp), 0);
	fseek(fp, fpos, SEEK_SET);

	return 0;
}

/*
 *	Send accounting packet to remote server.
 */
int do_send(struct relay_request *r, struct sql_module *sql)
{
	VALUE_PAIR *vp;
	time_t now;
	int result;

	/*
	 *	Prevent loops.
	 */
	if (r->client_ip == r->req->packet->dst_ipaddr) {
		fprintf(stdout, "%s: do_send: Client-IP == Dest-IP. Droping packet.\n",progname);
		if (r->req->packet->vps != NULL) {
			pairfree(&r->req->packet->vps);
			r->req->packet->vps = NULL;
		}
		r->state = 0;
		r->req->timestamp = 0;
		r->client_ip = 0;
		return 0;
	}

	/*
	 *	Find the Acct-Delay-Time attribute. If it's
	 *	not there, add one.
	 */
	if ((vp = pairfind(r->req->packet->vps, PW_ACCT_DELAY_TIME)) == NULL) {
		vp = paircreate(PW_ACCT_DELAY_TIME, PW_TYPE_INTEGER);
		pairadd(&(r->req->packet->vps), vp);
	}
	now = time(NULL);
	vp->lvalue = (now - r->req->timestamp);

	if (debug_flag)
		fprintf(stderr, "%s: do_send: Calling SQL module Accounting method.\n",progname);

	result = sql->module->methods[METHOD_ACCOUNTING](sql->modinfo,r->req);

	if (debug_flag)
		fprintf(stderr, "%s: do_send: SQL module Accounting method returned: %d\n",progname,result);

	if (result == RLM_MODULE_OK){
		if (r->req->packet->vps){
			pairfree(&r->req->packet->vps);
			r->req->packet->vps = NULL;
		}
		r->state = 0;
		r->req->timestamp = 0;
		r->client_ip = 0;

		return 1;
	}

	return -1;
}

/*
 *	Rename a file, then recreate the old file with the
 *	same permissions and zero size.
 */
int detail_move(char *from, char *to)
{
	struct stat st;
	int n;
	int oldmask;

	if (stat(from, &st) < 0)
		return -1;
	if (rename(from, to) < 0)
		return -1;

	oldmask = umask(0);
	if ((n = open(from, O_CREAT|O_RDWR, st.st_mode)) >= 0)
		close(n);
	umask(oldmask);

	return 0;
}


/*
 *	Open detail file, collect records, send them to the
 *	remote accounting server, yadda yadda yadda.
 *
 *	STATE_RUN:	Reading from detail file, sending to server.
 *	STATE_BACKLOG:	Reading from the detail.work file, for example
 *			after a crash or restart. Sending to server.
 *	STATE_WAIT:	Reached end-of-file, renamed detail to
 *			detail.work, waiting for all outstanding
 *			requests to be answered.
 */
void loop(struct relay_misc *r_args)
{
	FILE *fp = NULL;
	struct relay_request *r;
	char work[1030];
	time_t now, last_rename = 0;
	struct relay_stats stats;
	int retrans_delay = 0;
	int retrans_num = 0;
	int i, n, ret;
	int fd;
	int state = STATE_RUN;
	long fpos;

	strNcpy(work, r_args->detail, sizeof(work) - 6);
	strcat(work, ".work");

	memset(&stats,0,sizeof(struct relay_stats));
	stats.startup = time(NULL);

	/*
	 * Initialize all our slots, might as well do this right away.
	 */
	for (i = 0; i < NR_SLOTS; i++) {
		if ((slots[i].req = request_alloc()) == NULL) {
			librad_perror("radsqlrelay");
			exit(1);
		}
		if ((slots[i].req->packet = rad_alloc(1)) == NULL){
			librad_perror("radsqlrelay");
			exit(1);
		}
		slots[i].state = 0;
		slots[i].client_ip = 0;
		slots[i].req->packet->dst_ipaddr = r_args->dst_addr;
		slots[i].req->packet->code = PW_ACCOUNTING_REQUEST;
		slots[i].req->packet->vps = NULL;
	}

	if (debug_flag)
		fprintf(stderr, "%s: loop: Initialized slots. Moving to process requests.\n",progname);

	while(1) {
		if (got_sigterm) state = STATE_SHUTDOWN;

		/*
		 *	Open detail file - if needed, and if we can.
		 */
		if (state == STATE_RUN && fp == NULL) {
			if ((fp = fopen(work, "r+")) != NULL)
				state = STATE_BACKLOG;
			else
				fp = fopen(r_args->detail, "r+");
			if (fp == NULL) {
				fprintf(stderr, "%s: Unable to open detail file - %s\n", progname,r_args->detail);
				perror("fopen");
				return;
			}
			fd = fileno(fp);
		}

		/*
		 *	If "request_head" points to a free or not-completely-
		 *	filled slot, we can read from the detail file.
		 */
		r = &slots[request_head];
		if (fp && state != STATE_WAIT && state != STATE_SHUTDOWN &&
		    r->state != STATE_FULL) {
			if (read_one(fp, r) == EOF) do {

				/*
				 *	End of file. See if the file has
				 *	any size, and if we renamed less
				 *	than 10 seconds ago or not.
				 */
				now = time(NULL);
				if (ftell(fp) == 0 || now < last_rename + 10) {
					fpos = ftell(fp);
					fseek(fp, 0L, SEEK_SET);
					rad_unlockfd(fd, 0);
					fseek(fp, fpos, SEEK_SET);
					state = STATE_WAIT;
					break;
				}
				last_rename = now;

				/*
				 *	We rename the file
				 *	to <file>.work and create an
				 *	empty new file.
				 */
				if (state == STATE_RUN &&
				    detail_move(r_args->detail, work) == 0)
					state = STATE_WAIT;
				else if (state == STATE_BACKLOG)
					state = STATE_WAIT;
				fpos = ftell(fp);
				fseek(fp, 0L, SEEK_SET);
				fseek(fp, fpos, SEEK_SET);
				rad_unlockfd(fd, 0);
			} while(0);
			if (r_args->records_print && state == STATE_RUN){
				stats.records_read++;
				if (stats.last_print_records - stats.records_read >= r_args->records_print){
					now = time(NULL);
					fprintf(stderr, "%s: Running and Processing Records.\n",progname);
					fprintf(stderr, "Seconds since startup: %d\n",now - stats.startup);
					fprintf(stderr, "Records Read: %d\n",stats.records_read);
					fprintf(stderr, "Records Sent: %d\n",stats.records_sent);
					fprintf(stderr, "Records Read Rate since startup: %.2f\n",
						stats.records_read / (now - stats.startup));
					fprintf(stderr, "Records Sent Rate since startup: %.2f\n",
						stats.records_sent / (now - stats.startup));
					stats.last_print_records = stats.records_read;
				}
			}
			if (r->state == STATE_FULL)
				request_head = (request_head + 1) % NR_SLOTS;
		}

		/*
		 *	If we're in STATE_WAIT and all slots are
		 *	finally empty, we can copy the <detail>.work file
		 *	to the definitive detail file and resume.
		 */
		if (state == STATE_WAIT || state == STATE_SHUTDOWN) {
			for (i = 0; i < NR_SLOTS; i++)
				if (slots[i].state != STATE_EMPTY)
					break;
			if (i == NR_SLOTS) {

				if (fp) fclose(fp);
				fp = NULL;
				unlink(work);
				if (state == STATE_SHUTDOWN) {
					for (i = 0; i < NR_SLOTS; i++) {
						rad_free(&slots[i].req);
					}
					exit(0);
				}
				ms_sleep(600);
				state = STATE_RUN;
				
			}
		}

		/*
		 *	See if there's anything to send.
		 */
		n=0;
		for (i = 0; i < NR_SLOTS; i++) {
			if (slots[i].state == STATE_FULL) {
				ret = do_send(&slots[i], r_args->sql);
				if (ret == -1){
					/*
					 * Packet sending failed. We sleep for 1 sec and then break
					 * If a failure happened for one packet it will probably
					 * happen for the rest. If it continues to happen
					 * increase the sleep time up to 20 secs
					 */
					retrans_delay += 1 + (1 * retrans_num);
					retrans_num++;
					if (retrans_delay > 20)
						retrans_delay = 20;
					sleep(retrans_delay);
					break;
				}
				if (ret == 1 && retrans_delay){
					retrans_delay = 0;
					retrans_num = 0;
				}
				if (ret > 0)
					n += ret;
				/*
				 * On first send we sleep for sleep_time
				 * If we send more packets we sleep for
				 * sleep_time + (backoff_time * packets_sent)
				 * If we are sending many packets we are either
				 * at program start or recovering from a sql
				 * server timeout/failue. We don't want to bog down
				 * the sql server with many requests
				 */
				if (n && (n % r_args->sleep_every) == 0)
					ms_sleep(r_args->sleep_time + (r_args->backoff_time * (n - 1)));
				if (n > NR_SLOTS / 2)
					break;
			}
		}
		if (r_args->records_print)
			stats.records_sent++;
	}
}

struct sql_module *init_sql(struct relay_misc *r)
{
	struct sql_module *inst = NULL;
	const char *module_name = "rlm_sql";
	char *name2;
	char *server;
	CONF_SECTION *maincs,*cs,*subcs = NULL;

	/*
	 *      Ensure that the configuration is initialized.
	 */
	memset(&mainconfig, 0, sizeof(mainconfig));

	/*
	 * Hack to make DEBUG/DEBUG2 work
	 */
	mainconfig.radlog_dest = RADLOG_STDOUT;

	if ((maincs = read_radius_conf_file()) == NULL) {
		fprintf(stderr, "%s: Error reading radiusd.conf\n",progname);
		return NULL;
	}

	/*
	 * Find the first 'client' section.
	 */
	cs = cf_section_sub_find(maincs, "modules");
	if (cs == NULL){
		fprintf(stderr, "%s: Cannot find a 'modules' section in the configuration file.\n",progname);
		return NULL;
	}
	while((subcs = cf_subsection_find_next(cs,subcs,"sql")) != NULL){
		if (r->instance){
			name2 = cf_section_name2(subcs);
			if (!strcmp(name2,r->instance))
				break;
		}
		else
			break;
	}
	if (subcs == NULL){
		fprintf(stderr, "%s: Cannot find a corresponding 'sql' section in the configuration file.\n",progname);
		return NULL;
	}
	server = cf_section_value_find(subcs, "server");
	if (server){
		r->dst_addr = ip_getaddr(server);
		if (r->dst_addr == 0) {
			fprintf(stderr, "%s: Unknown destination host in 'server' directive.\n",progname);
			return NULL;
		}
	}
	else{
		fprintf(stderr, "%s: No 'server' directive found. Loop detection won't work!!\n",progname);
		return NULL;
	}

	inst = (struct sql_module *) rad_malloc(sizeof(struct sql_module));
	LTDL_SET_PRELOADED_SYMBOLS();

	if (lt_dlinit() != 0) {
		fprintf(stderr, "%s: Failed to initialize libraries: %s\n",progname,lt_dlerror());
		return NULL;
	}
	if (radlib_dir){
		fprintf(stderr, "%s: Setting library directory to '%s'\n",progname,radlib_dir);
		lt_dlsetsearchpath(radlib_dir);
	}

	inst->handle = lt_dlopenext(module_name);
	if (inst->handle == NULL){
		fprintf(stderr, "%s: Failed to link to module '%s': %s\n",progname,module_name,lt_dlerror());
		free(inst);
		return NULL;
	}
	
	inst->module = (module_t *) lt_dlsym(inst->handle, module_name);
	if (!inst->module) {
		fprintf(stderr, "%s: Failed linking to 'sql' structure: %s\n",progname,lt_dlerror());
		lt_dlclose(inst->handle);       /* ignore any errors */
		free(inst);
		return NULL;
	}

	/* call the modules initialization */
	if (inst->module->init && (inst->module->init)() < 0) {
		fprintf(stderr, "%s: Module initialization failed.\n",progname);
		lt_dlclose(inst->handle);       /* ignore any errors */
		free(inst);
		return NULL;
	}

	if (inst->module->instantiate && inst->module->instantiate(subcs,&inst->modinfo) < 0){
		fprintf(stderr, "%s: Module instantiation failed.\n",progname);
		lt_dlclose(inst->handle);
		free(inst);
		return NULL;
	}

	fprintf(stderr, "%s: SQL Module Initialized.\n",progname);
	
	return inst;	
}

void radsqlrelay_usage(void)
{
	fprintf(stderr, "Usage: %s [-a accounting_dir] [-d radius_dir]\n",progname);
	fprintf(stderr, "[-fx] [-s records] [-b backoff_time (ms)] [-i sleep_time (ms)]\n");
	fprintf(stderr, "[-e sleep_every packets] [-M sql_module_instance] detailfile\n");
	fprintf(stderr, " -a accounting_dir	Base accounting directory.\n");
	fprintf(stderr, " -d radius_dir	 	Base radius (raddb) directory.\n");
	fprintf(stderr, " -f		    	Stay in the foreground (don't fork).\n");
	fprintf(stderr, " -s records		If we are in foreground print out statistical information every\n");
	fprintf(stderr, "			so many <records>.\n");
	fprintf(stderr, " -h		    	This help.\n");
	fprintf(stderr, " -i sleep_time		Time to sleep (in ms) between calls to the accounting routine.\n");
	fprintf(stderr, "			The default value is %d ms.\n",DEFAULT_SLEEP);
	fprintf(stderr, " -b backoff_time	Apart from sleep_time if we have more than one outstanding requests\n");
	fprintf(stderr, "			we also sleep for backoff_time * packets_sent between calls to the\n");
	fprintf(stderr, "			accounting routine. That way we don't increase the load on the sql\n");
	fprintf(stderr, "			server on program startup and after sql server failures.\n");
	fprintf(stderr, "			The default value is %d ms.\n",DEFAULT_BACKOFF); 
	fprintf(stderr, " -e sleep_every	Only sleep every so many packets sent, not every time. Default: %d.\n",				DEFAULT_SLEEP_EVERY);
	fprintf(stderr, " -M sql_module_name	Use this specific sql module instance.\n");
	fprintf(stderr, " -x			Debug mode (-xx gives more debugging).\n");

	exit(1);
}

int main(int argc, char **argv)
{
	int c;
	int dontfork = 0;
	struct relay_misc r_args;

	memset(&r_args,0,sizeof(struct relay_misc));
	memset(librad_errstr,0,10);

	r_args.sleep_time = DEFAULT_SLEEP;
	r_args.backoff_time = DEFAULT_BACKOFF;
	r_args.sleep_every = DEFAULT_SLEEP_EVERY;

	progname = argv[0];

	memset((char *) r_args.detail, 0, 1024);

	radius_dir = strdup(RADIUS_DIR);

	librad_debug = 0;

	/*
	 *	Make sure there are stdin/stdout/stderr fds.
	 */
	while ((c = open("/dev/null", O_RDWR)) < 3 && c >= 0);
	if (c >= 3) close(c);

	/*
	 *	Process the options.
	 */
	while ((c = getopt(argc, argv, "a:d:fh:M:i:b:e:x:s")) != EOF) switch(c) {
		case 'a':
		       if (strlen(optarg) > 1021) {
				fprintf(stderr, "%s: acct_dir too long\n",progname);
				exit(1);
			}     
			strncpy(r_args.detail, optarg, 1021);
			break;
		case 'd':
			if (radius_dir)
				free(radius_dir);
			radius_dir = strdup(optarg);
			break;
		case 'f':
			dontfork = 1;
			break;
		case 's':
			if (!dontfork){
				fprintf(stderr, "%s: -f should be set first for -s to work.\n",progname);
				radsqlrelay_usage();
			}
			r_args.records_print = atoi(optarg);
			break;
		case 'i':
			r_args.sleep_time = atoi(optarg);
			break;
		case 'b':
			r_args.backoff_time = atoi(optarg);
			break;
		case 'e':
			r_args.sleep_every = atoi(optarg);
			break;
		case 'M':
			r_args.instance = strdup(optarg);
			break;
		case 'x':
			/*
			 * If -x is called once we enable internal radrelay
			 * debugging, if it's called twice we also active
			 * lib_rad debugging (fairly verbose).
			 */
			if (debug_flag == 1)
				librad_debug = 1;
			debug_flag++;
			dontfork = 1;
			break;
		case 'h':
		default:
			radsqlrelay_usage();
			break;
	}
	if (r_args.instance && strlen(r_args.instance) == 0)
		r_args.instance = NULL;



	/*
	 *	No detail file: die.
	 */
	if (argc == optind) {
		radsqlrelay_usage();
	}

	argc -= (optind - 1);
	argv += (optind - 1);

	/*
	 * Find what detail file to read from.
	 *
	 * FIXME: We should be able to expand dates etc. based on the pathname,
	 * just like the detail module does.
	 */
	if (r_args.detail[0] == '\0') {
		if (strlen(RADIR) > 1021) {
			fprintf(stderr, "%s: acct_dir too long\n",progname);
			exit(1);
		}
		strncpy(r_args.detail, RADIR, 1021);
	}
	if (chdir(r_args.detail) == -1) {
		perror("chdir");
		exit(1);
	}

	if (strlen(argv[1]) + strlen(r_args.detail) > 1023) {
		fprintf(stderr, "%s: Detail file path too long",progname);
		exit(1);
	} else {
		if (r_args.detail[strlen(r_args.detail) - 1] != '/')
			r_args.detail[strlen(r_args.detail)] = '/';
		strncat (r_args.detail, argv[1], 1023 - strlen(r_args.detail));
	}

	r_args.sql = init_sql(&r_args);
	if (r_args.sql == NULL){
		fprintf(stderr, "%s: SQL module initialization failed.\n",progname);
		exit(1);
	}

	signal(SIGTERM, sigterm_handler);

	if (!dontfork) {
		if (fork() != 0)
			exit(0);
		close(0);
		close(1);
		close(2);
		(void)open("/dev/null", O_RDWR);
		dup(0);
		dup(0);
		signal(SIGHUP,  SIG_IGN);
		signal(SIGINT,  SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
#ifdef HAVE_SETSID
		setsid();
#endif
	}

	if (debug_flag)
		fprintf(stderr, "%s: Going to call loop()\n",progname);

	/*
	 *	Call main processing loop.
	 */
	loop(&r_args);

	return 0;
}

