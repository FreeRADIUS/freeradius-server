/*
 * radrelay.c	This program tails a detail logfile, reads the log
 *		entries, forwards them to a remote radius server,
 *		and moves the processed records to another file.
 *
 *		Used to replicate accounting records to one (central)
 *		server - works even if remote server has extended
 *		downtime, and/or if this program is restarted.
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
 *
 */
char radrelay_rcsid[] =
"$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

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

const char *progname;

int debug_flag = 0;
const char *radlog_dir = NULL;
radlog_dest_t radlog_dest = RADLOG_FILES;

const char *radius_dir = NULL;
const char *radacct_dir = NULL;
const char *radlib_dir = NULL;
int auth_port = 0;
int acct_port;
uint32_t myip = INADDR_ANY;
int log_stripped_names;
struct main_config_t mainconfig;

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
	time_t		retrans;			/* when to retrans */
	time_t		timestamp;			/* orig recv time */
	uint32_t	client_ip;			/* Client-IP-Addr */
	RADIUS_PACKET	*req;				/* Radius request */
};

struct relay_misc {
	int		sockfd;				/* Main socket descriptor */
	uint32_t 	dst_addr;			/* Destination address */
	short 		dst_port;			/* Destination port */
	uint32_t	src_addr;			/* Source address */
	char		detail[1024];			/* Detail file */
	char 		*secret;			/* Secret */
	char		f_secret[256];			/* File secret */
};

/*
 * Used for reading the client configurations from the config files.
 */
char *c_secret = NULL;
char *c_shortname = NULL;

struct relay_request slots[NR_SLOTS];
char id_map[256];
int request_head;
int got_sigterm = 0;
int debug = 0;


int get_radius_id(void);
void sigterm_handler(int sig);
void ms_sleep(int msec);
int isdateline(char *d);
int read_one(FILE *fp, struct relay_request *req);
int do_recv(struct relay_misc *r_args);
int do_send(struct relay_request *r, char *secret);
int detail_move(char *from, char *to);
void loop(struct relay_misc *r_args);
int find_shortname(char *shortname, char **host, char **secret);
void usage(void);


/*
 * Get a radius id which is not
 * currently being used (outstanding request)
 * Since NR_SLOTS < 256 we can't
 * have more outstanding requests than radius ids
 */
int get_radius_id()
{
	unsigned int id = 0;

	for(id = 0; id < 256; id++){
		if (id_map[id] == 0)
			break;
	}
	if (id == 255 && id_map[id] != 0){
		fprintf(stdout, "get_radius_id(): No IDs available. Something is very wrong\n");
		return -1;
	}
	id_map[id] = 1;
	fprintf(stdout, "get_radius_id(): Assign RADIUS ID = %d\n",id);

	return id;
}

void sigterm_handler(int sig)
{
	signal(sig, sigterm_handler);
	got_sigterm = 1;
}


/*
 *	Sleep a number of milli seconds
 */
void ms_sleep(int msec)
{
	struct timeval tv;

	tv.tv_sec  = (msec / 1000);
	tv.tv_usec = (msec % 1000) * 1000;
	select(0, NULL, NULL, NULL, &tv);
}

/*
 *	Does this (remotely) look like "Tue Jan 23 06:55:48 2001" ?
 */
int isdateline(char *d)
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

	if (r_req->state == STATE_EMPTY) {
		r_req->state = STATE_BUSY1;
	}

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
		if (buf[strlen(buf) - 1] != '\n') {
			fprintf(stdout, "read_one: BROKEN ATTRIBUTE\n");
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
					r_req->timestamp = atoi(val);
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
				    (vp->attribute < 256 ||
				     vp->attribute > 65535) &&
				    vp->attribute != PW_VENDOR_SPECIFIC) {
					pairadd(&(r_req->req->vps), vp);
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
		if (r_req->timestamp == 0)
			r_req->timestamp = time(NULL);
		if ((vp = pairfind(r_req->req->vps, PW_ACCT_DELAY_TIME)) != NULL) {
			r_req->timestamp -= vp->lvalue;
			vp->lvalue = 0;
		}
		r_req->req->id = get_radius_id();
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
 *	Receive answers from the remote server.
 */
int do_recv(struct relay_misc *r_args)
{
	RADIUS_PACKET *rep;
	struct relay_request *r;
	int i;

	/*
	 *	Receive packet and validate it's length.
	 */
	rep = rad_recv(r_args->sockfd);
	if (rep == NULL) {
		librad_perror("radrelay:");
		return -1;
	}

	/*
	 *	Must be an accounting response.
	 *	FIXME: check if this is the right server!
	 */
	if (rep->code != PW_ACCOUNTING_RESPONSE)
		return -1;

	/*
	 *	Decode packet into radius attributes.
	 */

	/*
	 *	Now find it in the outstanding requests.
	 */
	for (i = 0; i < NR_SLOTS; i++) {
		r = slots + i;
		if (r->state == STATE_FULL && r->req->id == rep->id) {
			if (rad_decode(rep, r->req, r_args->secret) != 0) {
				librad_perror("rad_decode");
				return -1;
			}
			/*
			 *	Got it. Clear slot.
			 *	FIXME: check reponse digest ?
			 */
			id_map[r->req->id] = 0;
			fprintf(stdout, "do_recv: Free RADIUS ID = %d\n",r->req->id);
			if (r->req->vps != NULL) {
				pairfree(&r->req->vps);
				r->req->vps = NULL;
			}
			if (r->req->data != NULL) {
				free (r->req->data);
				r->req->data = NULL;
			}
			r->state = 0;
			r->retrans = 0;
			r->timestamp = 0;
			r->client_ip = 0;
			break;
		}
	}

	rad_free(&rep);

	return 0;
}

/*
 *	Send accounting packet to remote server.
 */
int do_send(struct relay_request *r, char *secret)
{
	VALUE_PAIR *vp;
	time_t now;

	/*
	 *	Prevent loops.
	 */
	if (r->client_ip == r->req->dst_ipaddr) {
		fprintf(stdout, "do_send: Client-IP == Dest-IP. Droping packet.\n");
		fprintf(stdout, "do_send: Free RADIUS ID = %d\n",r->req->id);
		id_map[r->req->id] = 0;
		if (r->req->vps != NULL) {
			pairfree(&r->req->vps);
			r->req->vps = NULL;
		}
		if (r->req->data != NULL) {
			free (r->req->data);
			r->req->data = NULL;
		}
		r->state = 0;
		r->retrans = 0;
		r->timestamp = 0;
		r->client_ip = 0;
		return 0;
	}

	/*
	 *	Has the time come for this packet ?
	 */
	now = time(NULL);
	if (r->retrans > now)
		return 0;
	/*
	 * If we are resending a packet we *need* to
	 * change the radius packet id since the request
	 * authenticator is different (due to different
	 * Acct-Delay-Time value).
	 * Otherwise the radius server may consider the
	 * packet a duplicate and we 'll get caught in a
	 * loop. 
	 */
	if (r->retrans > 0){
		id_map[r->req->id] = 0;
		r->req->id = get_radius_id();
		if (r->req->data != NULL){
			free(r->req->data);
			r->req->data = NULL;
		}
	}
	r->retrans = now + 3;

	/*
	 *	Find the Acct-Delay-Time attribute. If it's
	 *	not there, add one.
	 */
	if ((vp = pairfind(r->req->vps, PW_ACCT_DELAY_TIME)) == NULL) {
		vp = paircreate(PW_ACCT_DELAY_TIME, PW_TYPE_INTEGER);
		pairadd(&(r->req->vps), vp);
	}
	vp->lvalue = (now - r->timestamp);

	/*
	 *	Rebuild the entire packet every time from
	 *	scratch - the signature changed because
	 *	Acct-Delay-Time changed.
	 */
	rad_send(r->req, NULL, secret);

	return 1;
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
	struct timeval tv;
	fd_set readfds;
	char work[1030];
	time_t now, last_rename = 0;
	int i, n;
	int state = STATE_RUN;
	int id;
	long fpos;

	strNcpy(work, r_args->detail, sizeof(work) - 6);
	strcat(work, ".work");

	id = ((int)getpid() & 0xff);

	/*
	 * Initialize all our slots, might as well do this right away.
	 */
	for (i = 0; i < NR_SLOTS; i++) {
		if ((slots[i].req = rad_alloc(1)) == NULL) {
			librad_perror("radclient");
			exit(1);
		}
		slots[i].state = 0;
		slots[i].retrans = 0;
		slots[i].timestamp = 0;
		slots[i].client_ip = 0;
		slots[i].req->sockfd = r_args->sockfd;
		slots[i].req->dst_ipaddr = r_args->dst_addr;
		slots[i].req->dst_port = r_args->dst_port;
		slots[i].req->src_ipaddr = r_args->src_addr;
		slots[i].req->code = PW_ACCOUNTING_REQUEST;
		slots[i].req->vps = NULL;
		slots[i].req->data = NULL;
	}

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
				fprintf(stderr, "%s: Unable to open detail file - %s\n", progname, r_args->detail);
				perror("fopen");
				return;
			}

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
					rad_unlockfd(fileno(fp), 0);
					fseek(fp, fpos, SEEK_SET);
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
				rad_unlockfd(fileno(fp), 0);
			} while(0);
			if (r->state == STATE_FULL)
				request_head = (request_head + 1) % NR_SLOTS;
		}

		/*
		 *	Perhaps we can receive something.
		 */
		tv.tv_sec = 0;
		tv.tv_usec = 25000;
		FD_ZERO(&readfds);
		FD_SET(r_args->sockfd, &readfds);
		n = 0;
		while (select(r_args->sockfd + 1, &readfds, NULL, NULL, &tv) > 0) {
			do_recv(r_args);
			if (n++ >= NR_SLOTS) break;
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
				state = STATE_RUN;
			}
		}

		/*
		 *	See if there's anything to send.
		 */
		n=0;
		for (i = 0; i < NR_SLOTS; i++) {
			if (slots[i].state == STATE_FULL) {
				n += do_send(&slots[i], r_args->secret);
				ms_sleep(140);
				if (n > NR_SLOTS / 2)
					break;
			}
		}
	}
}

/*
 * Search through the "client" config sections (usually in clients.conf).
 * This is an easy way to find a secret and an host.
 */
int find_shortname(char *shortname, char **host, char **secret)
{
	CONF_SECTION *maincs, *cs;

	/*
	 *	Ensure that the configuration is initialized.
	 */
	memset(&mainconfig, 0, sizeof(mainconfig));

	if ((maincs = read_radius_conf_file()) == NULL) {
		fprintf(stderr, "Error reading radiusd.conf\n");
		exit(1);
	}

	/*
	 * Find the first 'client' section.
	 */
	cs = cf_section_sub_find(maincs, "client");
	if (cs) {
		c_shortname = cf_section_value_find(cs, "shortname");
		c_secret = cf_section_value_find(cs, "secret");
		/*
		 * Keep searching for 'client' sections until they run out
		 * or we find one that matches.
		 */
		while (cs && strcmp(shortname, c_shortname)) {
			free(c_shortname);
			free(c_secret);
			cs = cf_subsection_find_next(cs, cs, "client");
			if (cs) {
				c_shortname = cf_section_value_find(cs, "shortname");
				c_secret = cf_section_value_find(cs, "secret");
			}
		};
	};

	if (cs) {
		*host = cf_section_name2(cs);
		*secret = c_secret;
		if (host && secret)
			return 0;
	}

	return -1;
}

void usage(void)
{
	fprintf(stderr, "Usage: radrelay [-a accounting_dir] [-d radius_dir] [-i local_ip] [-s secret]\n");
	fprintf(stderr, "[-S secret_file] [-fx] <[-n shortname] [-r remote-server[:port]]> detailfile\n");
	fprintf(stderr, " -a accounting_dir     Base accounting directory.\n");
	fprintf(stderr, " -d radius_dir         Base radius (raddb) directory.\n");
	fprintf(stderr, " -f                    Stay in the foreground (don't fork).\n");
	fprintf(stderr, " -h                    This help.\n");
	fprintf(stderr, " -i local_ip           Use local_ip as source address.\n");
	fprintf(stderr, " -n shortname          Use the [shortname] entry from clients.conf for\n");
	fprintf(stderr, "                       ip-adress and secret.\n");
	fprintf(stderr, " -r remote-server      The destination address/hostname.\n");
	fprintf(stderr, " -s secret             Server secret.\n");
	fprintf(stderr, " -S secret_file        Read server secret from file.\n");
	fprintf(stderr, " -x                    Debug mode (-xx gives more debugging).\n");

	exit(1);
}

int main(int argc, char **argv)
{
	struct servent *svp;
	char *server_name;
	char *shortname;
	char *p;
	int c;
	int i;
	int dontfork = 0;
	struct relay_misc r_args;
	FILE *sfile_fp;

	progname = argv[0];

	r_args.sockfd = -1;
	r_args.dst_addr = 0;
	r_args.dst_port = 0;
	r_args.src_addr = 0;
	memset((char *) r_args.detail, 0, 1024);
	memset((char *) r_args.f_secret, 0, 256);
	r_args.secret = NULL;

	shortname = NULL;
	server_name = NULL;

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
	while ((c = getopt(argc, argv, "a:d:fhi:n:r:s:S:x")) != EOF) switch(c) {
		case 'a':
			if (strlen(optarg) > 1021) {
				fprintf(stderr, "%s: acct_dir to long\n", progname);
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
		case 'n':
			shortname = optarg;
			break;
		case 'r':
			server_name = optarg;
			break;
		case 's':
			r_args.secret = optarg;
			break;
		case 'x':
			/*
			 * If -x is called once we enable internal radrelay
			 * debugging, if it's called twice we also active
			 * lib_rad debugging (fairly verbose).
			 */
			if (debug == 1)
				librad_debug = 1;
			debug = 1;
			dontfork = 1;
			break;
		case 'S':
			sfile_fp = fopen(optarg, "r");
			if (sfile_fp == NULL) {
				fprintf(stderr, "Error opening %s: %s\n",
				        optarg, strerror(errno));
				exit(1);
			}

			if (fgets(r_args.f_secret, 256, sfile_fp) == NULL) {
				fprintf(stderr, "Error reading from %s: %s\n",
				        optarg, strerror(errno));
				fclose(sfile_fp);
				exit(1);
			}
			fclose(sfile_fp);

			for (c = 0; c < strlen(r_args.f_secret); c++)
				if (r_args.f_secret[c] == ' ' ||
				    r_args.f_secret[c] == '\n')
					r_args.f_secret[c] = '\0';

			if (strlen(r_args.f_secret) < 2) {
				fprintf(stderr, "Secret in %s is to short\n",
				        optarg);
				exit(1);
			}

			r_args.secret = r_args.f_secret;
			break;
		case 'i':
			if ((r_args.src_addr = ip_getaddr(optarg)) == 0) {
				fprintf(stderr, "%s: unknown host %s\n",
					progname, optarg);
				exit(1);
			}
			break;
		case 'h':
		default:
			usage();
			break;
	}

	/*
	 *	No detail file: die.
	 */
	if (argc == optind) {
		usage();
	}

	argc -= (optind - 1);
	argv += (optind - 1);
	if (shortname && server_name)
		usage();
	if (!shortname && !server_name)
		usage();
	if (r_args.secret != NULL && shortname != NULL)
		usage();

	/*
	 * If we've been given a shortname, try to fetch the secret and
	 * adress from the config files.
	 */
	if (shortname != NULL) {
		if (find_shortname(shortname, &server_name, &r_args.secret) == -1) {
			fprintf(stderr, "Couldn't find %s in configuration files.\n", shortname);
			exit(1);
		}
	}

	/*
	 * server_name should already be set either by the -r or the -s
	 * commandline argument.
	 */
	if ((p = strrchr(server_name, ':')) != NULL) {
		*p = 0;
		p++;
		r_args.dst_port = ntohs(atoi(p));
	}
	if (r_args.dst_port == 0) {
		svp = getservbyname ("radacct", "udp");
		r_args.dst_port = svp ? ntohs(svp->s_port) : PW_ACCT_UDP_PORT;
	} else {
		r_args.dst_port = ntohs(r_args.dst_port);
	}
	r_args.dst_addr = ip_getaddr(server_name);
	if (r_args.dst_addr == 0) {
		fprintf(stderr, "%s: unknown host\n",
			server_name);
		exit(1);
	}

	if (r_args.secret == NULL || r_args.secret[0] == 0) {
		fprintf(stderr, "No secret available for server %s\n",
			server_name);
		exit(1);
	}

	/*
	 * Find what detail file to read from.
	 *
	 * FIXME: We should be able to expand dates etc. based on the pathname,
	 * just like the detail module does.
	 */
	if (r_args.detail[0] == '\0') {
		if (strlen(RADIR) > 1021) {
			fprintf(stderr, "acct_dir to long\n");
			exit(1);
		}
		strncpy(r_args.detail, RADIR, 1021);
	}
	if (chdir(r_args.detail) == -1) {
		perror("chdir");
		exit(1);
	}

	if (strlen(argv[1]) + strlen(r_args.detail) > 1023) {
		fprintf(stderr, "Detail file path to long");
		exit(1);
	} else {
		if (r_args.detail[strlen(r_args.detail) - 1] != '/')
			r_args.detail[strlen(r_args.detail)] = '/';
		strncat (r_args.detail, argv[1], 1023 - strlen(r_args.detail));
	}

	/*
	 *	Initialize dictionary.
	 */
	if (dict_init(radius_dir, RADIUS_DICTIONARY) < 0) {
		librad_perror("radrelay");
		exit(1);
	}

	/*
	 *	Open a socket to the remote server.
	 */
	if ((r_args.sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fprintf(stderr, "Error opening socket: %s", strerror(errno));
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
#if HAVE_SETSID
		setsid();
#endif
	}

	/*
	 * Initialize the radius id map
	 */
	for(i=0;i<256;i++)
		id_map[i] = 0;

	/*
	 *	Call main processing loop.
	 */
	loop(&r_args);

	return 0;
}

