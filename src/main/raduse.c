/*
 * raduse.c	Shows the usage of the modem lines on a terminal server.
 *
 * Version:	$Id$
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
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 */

#include "autoconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "sysutmp.h"
#include "conf.h"
#include "radpaths.h"
#include "libradius.h"

#ifdef HAVE_UTMPX_H
#  undef ut_time
#  define ut_time ut_xtime
#endif

#define UTSIZE (sizeof(struct utmp))

#define HOURS 19

#define MAXLINES 64

struct line {
  time_t lastout;
  time_t inuse;
  char hour[HOURS];
};
struct line lines[MAXLINES];
int nrlines = 35;

/*
 *	List the terminal servers in the logfile.
 */
static void listnas(void)
{
  FILE *fp;
  FILE *pp;
  time_t now, stop;
  struct utmp ut;
  char *p;
  int first = 1;
  char buf[128];
  int found = 0;

  /* Open the sort pipe. */
  pp = popen("sort -u", "w");

  /* Go back max. 1 day. */
  time(&now);
  stop = now - 3600 * HOURS;

  /* Open wtmp file. */
  if ((fp = fopen(RADWTMP, "r")) == NULL) {
	perror(RADWTMP);
	exit(1);
  }
  fseek(fp, -UTSIZE, SEEK_END);

  /* Read structs backwards. */
  while(1) {
	/* Rewind if needed. */
	if (!first && fseek(fp, -2 * UTSIZE, SEEK_CUR) < 0) break;
	first = 0;

	/* Read struct and see if we have to stop. */
	if (ftell(fp) < (long)UTSIZE) break;
	fread(&ut, UTSIZE, 1, fp);
	if (ut.ut_time < stop) break;

	memset(buf, 0, sizeof(buf));
	strncpy(buf, ut.ut_line, sizeof(ut.ut_line));

	/* Get terminal server name. */
	if ((p = strchr(buf, ':')) != NULL)
		p++;
	else
		p = buf + 2;
	fprintf(pp, "%s\n", p);
	found = 1;
  }
  fclose(fp);
  pclose(pp);

  if (found == 0)
	printf("raduse: no data found over the last 24 hours.\n");
}

/*
 * Find out the usage of the ttys defined in
 * struct line lines[] for the last 21 hours.
 */
static int fillstruct(int offset, const char *nas)
{
  FILE *fp;
  time_t now, stop;
  struct utmp ut;
  int i, n, port;
  int beg, end;
  char *p;
  int first = 1;
  char buf[128];
  int found = 0;

  /* Go back max. 1 day. */
  time(&now);
  stop = now - 3600 * HOURS;

  /* Open wtmp file. */
  if ((fp = fopen(RADWTMP, "r")) == NULL) {
	perror(RADWTMP);
	exit(1);
  }
  fseek(fp, -UTSIZE, SEEK_END);

  /* Read structs backwards. */
  while(1) {
	/* Rewind if needed. */
	if (!first && fseek(fp, -2 * UTSIZE, SEEK_CUR) < 0) break;
	first = 0;

	/* Read struct and see if we have to stop. */
	if (ftell(fp) < (long)UTSIZE) break;
	fread(&ut, UTSIZE, 1, fp);
	if (ut.ut_time < stop) break;

	memset(buf, 0, sizeof(buf));
	strncpy(buf, ut.ut_line, sizeof(ut.ut_line));

	/* Compare terminal server name. */
	if ((p = strchr(buf, ':')) != NULL)
		p++;
	else
		p = buf + 2;
	if (strcmp(p, nas) != 0)
		continue;

	found = 1;

	/* Now see which tty this was. */
	if ((p = strchr(buf, ':')) != NULL)
		*p = 0;
	else
		buf[2] = 0;

	port = atoi(buf);
	if (port == 0 && buf[0] != '0')
		continue;
	if (port < offset || port > offset + nrlines)
		continue;

	i = port - offset;

	/* Login or logout? */
	if (ut.ut_user[0] == 0) {
		lines[i].lastout = ut.ut_time;
		continue;
	}

	/* Skip type LOGIN */
	if (strncmp(ut.ut_user, "LOGIN", 5) == 0)
		continue;

	/* A login. Fill out the hour string. */
	beg = (now - ut.ut_time) / 3600;
	if (lines[i].lastout == 0) {
		lines[i].inuse = 1;
		end = 0;
	} else
		end = (now - lines[i].lastout) / 3600;
	if (beg >= HOURS) beg = HOURS - 1;
	if (end >= HOURS) end = HOURS - 1;

	for(n = end; n <= beg; n++)
		lines[i].hour[n] = lines[i].lastout ? '*' : '@';

  }
  fclose(fp);

  return found ? 0 : -1;
}

/*
 * Draw something that vaguely resembles a graph showing the
 * usage of the tty lines over the last 21 hours.
 */
static void drawit(int wide, int offset)
{
  time_t now;
  int i, n, hour;
  struct tm *tm;
  int thishour;
  int star;

  /* Find out current time. */
  time(&now);
  tm = localtime(&now);
  thishour = tm->tm_hour;

  /* Change lower spaces to dots. */
  for(i = 0; i < nrlines; i++) {
	n = 0;
	for(hour = 0; hour < HOURS; hour++) {
		if (lines[i].hour[hour]) {
			n = 1;
		} else if (n)
			lines[i].hour[hour] = '.';
	}
  }

  /* Prefix (show if line is in use now) */
  printf("now|");
  for(i = 0; i < nrlines; i++) {
	if (wide)
		printf(" %c ", lines[i].inuse ? '@' : ' ');
	else
		printf("%c ", lines[i].inuse ? '@' : ' ');
  }
  printf("\n");

  /* Last 21 hours. */
  for(hour = 0; hour < HOURS; hour++) {
	printf("%02d |", thishour);
	thishour--;
	if (thishour < 0) thishour = 23;

	for(i = 0; i < nrlines; i++) {
		star = ' ';
		if (lines[i].hour[hour])
			star = lines[i].hour[hour];
		if (wide)
			printf(" %c ", star);
		else
			printf("%c ", star);
	}
	/* EOL */
	printf("\n");
  }

  /* Print a short suffix. */
  printf("---+");
  for(i = 0; i < nrlines; i++)
	printf(wide ? "---" : "--");
  printf("\n   |");
  for(i = 0; i < nrlines; i++) {
	if (wide)
		printf("%02d|", i + offset);
	else
		printf("%d|", (i + offset) / 10);
  }
  if (!wide) {
	printf("\n   |");
	for(i = 0; i < nrlines; i++)
		printf("%d|", (i + offset) % 10);
  }
  printf("\n");
}

static void usage(void)
{
  fprintf(stderr, "Usage: raduse [-w] [-o offset] terminal-server\n");
  fprintf(stderr, "       use raduse -l to find out a list of terminal servers\n");
  exit(1);
}

int main(int argc, char **argv)
{
  int wide = 0;
  int c;
  int offset = 0;
  int list = 0;

  while((c = getopt(argc, argv, "lwo:")) != EOF) switch(c) {
	case 'w':
		wide = 1;
		break;
	case 'o':
		offset = atoi(optarg);
		break;
	case 'l':
		list = 1;
		break;
	default:
		usage();
		break;
  }

  if (list) {
	listnas();
	exit(0);
  }

  if (wide) nrlines = 25;

  if (optind >= argc) usage();

  if (fillstruct(offset, argv[optind]) < 0) {
	fprintf(stderr,
   "raduse: %s: no data found (over the last 24 hours) (try raduse -l).\n",
		argv[optind]);
	return 1;
  }
  drawit(wide, offset);

  return 0;
}

