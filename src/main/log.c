/*
 * log.c	Logging module.
 *
 */

char log_sccsid[] =
"@(#)log.c      1.3 Copyright 1999 Cistron Internet Services B.V,";

#include	"autoconf.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<stdarg.h>
#include	<time.h>
#include	"radiusd.h"

extern char	*radlog_dir;


/*
 *	Log the message to the logfile. Include the severity and
 *	a time stamp.
 */
static int do_log(int lvl, char *fmt, va_list ap)
{
	FILE	*msgfd;
	unsigned char	*s = ": ";
	char	buffer[2048];
	time_t	timeval;
	int	len;

	if ((lvl & L_CONS) || radlog_dir == NULL || debug_flag) {
		lvl &= ~L_CONS;
		if (!debug_flag) fprintf(stderr, "%s: ", progname);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	}
	if (radlog_dir == NULL || debug_flag) return 0;

	if (strcmp(radlog_dir, "stdout") != 0) {
		sprintf(buffer, "%s/%s", radlog_dir, RADIUS_LOG);
		if((msgfd = fopen(buffer, "a")) == NULL) {
			fprintf(stderr, "%s: Couldn't open %s for logging\n",
					progname, buffer);
			return -1;
		}
	} else {
		msgfd = stdout;
	}

	timeval = time(0);
	strcpy(buffer, ctime(&timeval));
	switch(lvl) {
		case L_DBG:
			s = ": Debug: ";
			break;
		case L_AUTH:
			s = ": Auth: ";
			break;
		case L_PROXY:
			s = ": Proxy: ";
			break;
		case L_INFO:
			s = ": Info: ";
			break;
		case L_ERR:
			s = ": Error: ";
			break;
	}
	strcpy(buffer + 24, s);
	len = strlen(buffer);

	vsprintf(buffer + len, fmt, ap);

	/*
	 *	Filter out characters not in Latin-1.
	 */
	for (s = buffer; *s; s++) {
		if (*s == '\r' || *s == '\n')
			*s = ' ';
		else if (*s < 32 || (*s >= 128 && *s <= 160))
			*s = '?';
	}
	strcat(buffer, "\n");

	fputs(buffer, msgfd);
	if (msgfd != stdout) fclose(msgfd);

	return 0;
}

int log_debug(char *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = do_log(L_DBG, msg, ap);
	va_end(ap);

	return r;
}

int log(int lvl, char *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = do_log(lvl, msg, ap);
	va_end(ap);

	return r;
}

