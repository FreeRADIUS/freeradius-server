/*
 * rlm_dbm_cat.c :    List rlm_dbm DBM file
 *
 * Version:     $Id$
 *
 *  This program is is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2 if the
 *  License as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *
 *  Copyright 2001 Koulik Andrei, Sandy Service
 */

#include "autoconf.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_NDBM_H
#include <ndbm.h>
#endif

#ifdef HAVE_GDBM_NDBM_H
#include <gdbm/ndbm.h>
#endif

#ifdef HAVE_GDBMNDBM_H
#include <gdbm-ndbm.h>
#endif

#include <unistd.h>
#include <ctype.h>

#define LOTSTUP	20
#define WRAPLEN 40


int wraplen = WRAPLEN, needwrap = 0, lotstup = LOTSTUP;
char const * progname;

static void dump_record(datum key,datum data)
{
	int i,j;
	char *p;
	for(i = 0, p = key.dptr; i < key.dsize; i++, p++)
	  putchar(*p); 
	if ( i < lotstup ) while( i++ <= lotstup) putchar(' ');
		else putchar(' ');
	
	for(j = 0, p = data.dptr ; j < data.dsize && *p ; i++, p++ ) {
		putchar(*p);
		if ( needwrap && *p == ',' && i > wraplen ) putchar('\n');
		if ( *p == '\n' || ( needwrap && *p == ',' && i > wraplen ) ) {
			for(i = 0; i < lotstup; i++) putchar(' ');
			i = 0;
		}
	}
	   
	putchar('\n');
}

static void usage(){
	fprintf(stderr, "Usage: %s: [-f file] [-w] [-i number] [-l number] [-v]\n\n",progname);
	
	exit(1);
}
int main(int n, char **argv) {

	char 	*fname = NULL;
	DBM  	*pdb;
	datum	k,d;
	char 	ch;
	int 	i;
	
	progname = argv[0];
	
	
	
	while ((ch = getopt(n, argv, "i:l:wf:v")) != -1)
		switch (ch) {
			case 'i': 	if (!isdigit((int) *optarg)) usage();
					lotstup = atoi(optarg);
					break;
			case 'l':	if (!isdigit((int) *optarg)) usage();
					wraplen = atoi(optarg);
					break;
			case 'w':	needwrap = 1; 
					break;
			case 'f':	fname = optarg;
					break;
			case 'v':	printf("%s: $Id$\n",progname);
					exit(0);
					break;
			default : usage(); exit(1); break;
			
		}
	n -= (optind - 1);
	argv += (optind -1);
	
	if ( fname == NULL) fname = "sandy_db";

	if ( ( pdb = dbm_open(fname, O_RDONLY, 0777) ) == NULL ) {
		perror("Couldn't open database");
		exit(1);
	}
	if ( n > 1 ) {
		for ( i = 1 ; i < n ; i++ ) {
			printf(" Check: %s\n",argv[i]);
			k.dptr  = argv[i];
			k.dsize = strlen(argv[i]) + 1; 
			if ( (d = dbm_fetch(pdb,k)).dptr == NULL ) {
				printf("Not found\n");
			} else dump_record(k, d);
		}
	} else {
		for ( k = dbm_firstkey(pdb) ; k.dptr != NULL ; k = dbm_nextkey(pdb) ) 
			if ( (d = dbm_fetch(pdb,k)).dptr == NULL ) {
				perror("Couldn't fetch user record");
				exit(1);
			} else dump_record(k, d);
	}
	dbm_close(pdb);
	fflush(stdout);			
	
	return 0;
	
}
