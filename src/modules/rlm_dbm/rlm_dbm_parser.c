/*
 * rlm_dbm_parser.c :    Create dbm file from plain text
 *
 * Version:     $Id$
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2001 Koulik Andrei, Sandy Service
 */


char sccsid[] =
"$Id$ sandy module project\n Copyright 2001 Sandy Service\nCopyright 2001 Koulik Andrei";

#include <freeradius-devel/radiusd.h>
#include <fcntl.h>

#ifdef HAVE_NDBM_H
#include <ndbm.h>
#endif

#ifdef HAVE_GDBM_NDBM_H
#include <gdbm/ndbm.h>
#endif

#ifdef HAVE_GDBMNDBM_H
#include <gdbm-ndbm.h>
#endif

#include <ctype.h>

#include <freeradius-devel/conf.h>
#include <freeradius-devel/radpaths.h>

#define	MAX_BUFF_SIZE	1024

#define DOUT1	if( fr_debug_flag > 0 ) printf
#define DOUT2	if( fr_debug_flag > 5 ) printf

typedef enum sm_parse_state_t {
	SMP_INVALID = 0,
	SMP_USER,
	SMP_PATTERN,
	SMP_ACTION,
	SMP_PATTERN_OR_USER
} sm_parse_state_t;




const char * progname;

unsigned long 	st_errors = 0,
		st_warns  = 0,
		st_lines  = 0,
		st_users  = 0,
		st_skiped = 0,
		st_loaded = 0;


/*  test

int dumplist(VALUE_PAIR *vp)
{
	char buffer[1024];
	while (vp != NULL) {
		vp_prints(buffer, sizeof(buffer), vp);

		printf("\t%s\n", buffer);
		vp = vp -> next;
	}
	return 0;
}

*/


char content[4096];
int  concntr = 0;
int  oflags = O_RDWR | O_CREAT;
DBM * pdb = NULL;


static int open_storage(const char * fname) {

  if ( (pdb = dbm_open(fname, oflags, 0600 )) == NULL ) {
	perror("Couldn't open database");
	return 1;
  }
  return 0;
}

static void  close_storage(void){
  dbm_close(pdb);
}

static int  addlinetocontent(VALUE_PAIR *vp) {

	int outlen = sizeof(content) - concntr - 1;
	int lendiv;

	if ( outlen < 4 ) return -1;
	if ( vp == NULL ) { /* add empty line */
		content[concntr++] = '\n';
		content[concntr] = '\0';
	} else {
		while ( vp != NULL ){
			lendiv = vp_prints(&content[concntr],outlen,vp);
			if ( lendiv > 0 ) {
				outlen -= lendiv;

				if (outlen > 3)  {
					strcat(content,", ");
					concntr += lendiv + 2;
					outlen -= 2;
				} else {
					concntr = 0;
					return -1;
				}
			}
			vp = vp -> next;
		}

		if ( concntr > 2 ) {  /* remove trailing ',' */
			content[--concntr] = '\0';
			content[concntr - 1] = '\n';
		}
	}

	return 0;
}

static int storecontent (const char * username) {

	 datum d,k;
	 int res;

	if ( pdb == NULL || concntr < 2 ) return 1;

	DOUT2("store:\n%s\ncontent:\n%s",username,content);

	d.dptr = content;
	d.dsize = concntr + 1;

	k.dptr = username;
	k.dsize = strlen(username) + 1;

	res = dbm_store(pdb, k, d, DBM_INSERT);
	if ( res == 1 ) dbm_store(pdb, k, d, DBM_REPLACE);
	if ( res < 0 ) {
	  perror("Couldn't insert record");
	  st_errors++;
	  st_skiped++;
	}  else st_loaded++;

	concntr = 0;
	*content = '\0';
	return 0;
}

static int getuname(char **p,char *u,int n) {
	int	i;

	for(i=0 ; ( i < n-1 ) && ( **p ) && (! isspace((int) **p) ) ; (*p)++ )
	    u[i++] = **p;
	u[i] = '\0';
	return ( i == 0) ? 1:0;
}

static int sm_parse_file(FILE*fp,const char* fname) {
        FR_TOKEN tok;
        VALUE_PAIR *vp = NULL;
	sm_parse_state_t  parse_state = SMP_USER;
	unsigned long lino  = 0;
	char *p;
	char buff[MAX_BUFF_SIZE];
	char username[256];


	while( parse_state != SMP_INVALID && fgets(buff, sizeof(buff), fp) != NULL ) {

		lino ++;
		st_lines++;
		if ( strchr(buff, '\n') == NULL) {
			fprintf(stderr,"%s: %s[%lu]:Warning: line too long or not closed by \\n character. Skiped\n",progname,fname,lino);
			st_warns++;
			st_skiped++; /* _LINE_ skiped */
			continue;
		}

		DOUT2("Parseline: %s",buff);
		for ( p = buff; isspace((int) *p); p++);

		if ( *p == '#' || *p == 0 ) continue;

		/* userparse hack */
		if (  *p == ';' ) *p = '\n';
		p = buff;

		/* try to decide is this line new user or new pattern */
		if ( parse_state == SMP_PATTERN_OR_USER ) {
		     if ( isspace((int) buff[0]) ) parse_state = SMP_PATTERN;
		     	else {
		     		parse_state = SMP_USER;
		     		storecontent(username);
		     		st_users++;
		     	}
		 }

		if ( parse_state == SMP_USER ) {
		    tok = getuname(&p,username,sizeof(username));

		    /* check: is it include. not implemented */

		    if ( tok ) {
			fprintf(stderr ,"%s: %s[%lu]: error while expecting user name\n",progname,fname,lino);
			parse_state = SMP_INVALID;
			st_errors++;
		    } else {
		    	parse_state = SMP_PATTERN;
		    	DOUT1("Found user: %s\n",username);

		    }
		}
		if ( parse_state == SMP_PATTERN || parse_state == SMP_ACTION ) {

		    /* check for empty line */
		    while( *p && isspace((int) *p) ) p++;

		    if ( *p && ( *p != ';' ) ) tok = userparse(p,&vp);
		    else tok = T_EOL;  /* ';' - signs empty line */

		    switch(tok) {
		    	case T_EOL: /* add to content */
		    			addlinetocontent(vp);
		    			pairfree(&vp);
		    			if ( parse_state == SMP_PATTERN )
		    				parse_state = SMP_ACTION;
		    			else parse_state = SMP_PATTERN_OR_USER;

		    	case T_COMMA: break;  /* parse next line */
		    	default: /* error: we do  not expect anything else */
		    			fprintf(stderr ,"%s: %s[%lu]: syntax error\n",progname,fname,lino);
		    			fr_perror("Error");
		    			parse_state = SMP_INVALID;
		    			st_errors++;
		    }
		}
	}
	if ( feof(fp) ) switch (parse_state ) {
		case  SMP_USER: /* file is empty, last line is comment  */
			   			break;
		case  SMP_PATTERN: /* only username ?*/
				fprintf(stderr ,"%s: %s[%lu]: EOF while pattern line are expecting\n",progname,fname,lino);
				st_errors++;
				parse_state = SMP_INVALID;
				break;
		case  SMP_ACTION: /* looking for reply line */
				fprintf(stderr ,"%s: %s[%lu]: EOF while reply line are expecting\n",progname,fname,lino);
				st_errors++;
				parse_state = SMP_INVALID;
				break;
		case  SMP_PATTERN_OR_USER:
				storecontent(username);
				st_users++;
				break;
		default:break;
	} else if ( parse_state != SMP_INVALID ) {  /* file read error */
		fprintf(stderr ,"%s: error file reading from file\n",progname);
	}
	pairfree(&vp);

	return (parse_state == SMP_INVALID)?-1:0;
}


static void sm_usage(void) {
	fprintf(stderr, "Usage: %s [-c] [-d raddb] [-i inputfile] [-o outputfile] [-x] [-v] [-q] [username1 [username2] ...]\n\n",progname);

	fprintf(stderr, "-c	create new database.\n");
	fprintf(stderr, "-x	debug mode.\n");
	fprintf(stderr, "-q	do not print statistic\n");
	fprintf(stderr, "-v	print version\n");
	fprintf(stderr, "-r	remove user(s) from database\n");

}

int main(int n,char **argv) {

	const char *fname = NULL;
	const char *ofile = NULL;
	FILE 	*fp;
	int	print_stat = 1;
	int 	ch;
	const char  *sm_radius_dir = NULL;

	progname = argv[0];

	fr_debug_flag = 0;

	while ((ch = getopt(n, argv, "d:i:xo:qvc")) != -1)
	 	switch (ch) {
	 		case 'd':
	 			sm_radius_dir = optarg;
				break;
			case 'i':
				fname = optarg;
				break;
			case 'x':
				fr_debug_flag++;
			case 'o':
				ofile = optarg;
				break;
			case 'q':
				print_stat = 0;
				break;
			case 'v':
				printf("%s: $Id$ \n",progname);
				exit(0);
			case 'c':
				oflags = O_CREAT | O_TRUNC | O_RDWR;
				break;
			default: sm_usage();exit(1);
	 	}




	if ( sm_radius_dir == NULL ) sm_radius_dir = RADDBDIR;

	DOUT1("Use dictionary in: %s\n",sm_radius_dir);
	if (dict_init(sm_radius_dir, RADIUS_DICTIONARY) < 0 ) {
       		fr_perror("parser: init dictionary:");
                exit(1);
        }

	if ( fname == NULL || fname[0] == '-') {
		fp = stdin;
		fname = "STDIN";
	} else if ( ( fp = fopen(fname, "r") ) == NULL ) {
		fprintf( stderr,"%s: Couldn't open source file\n", progname);
		exit(1);
	}

	if ( ofile == NULL ) ofile = "sandy_db" ;
	if ( open_storage(ofile) ) {
	 	exit (1);
	}

	sm_parse_file(fp,fname);

	close_storage();

	if ( print_stat )
	  fprintf(stderr,"\nRecord loaded: %lu\nLines parsed: %lu\nRecord skiped: %lu\nWarnings: %lu\nErrors: %lu\n"
	  	,st_loaded,st_lines,st_skiped,st_warns,st_errors);

        return 0;
}
