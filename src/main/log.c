/*
 * log.c	Logging module.
 *
 * Version:	$Id$
 */

static const char rcsid[] = "$Id$";

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
static int do_log(int lvl, const char *fmt, va_list ap)
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
		sprintf(buffer, "%.1000s/%.1000s", radlog_dir, RADIUS_LOG);
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

#ifdef HAVE_VSNPRINTF
	vsnprintf(buffer + len, sizeof(buffer) - len -1, fmt, ap);
#else
	vsprintf(buffer + len, fmt, ap);
	if (strlen(buffer) >= sizeof(buffer) - 1)
		/* What can we do? */
		_exit(42);
#endif

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
	if (msgfd != stdout)
	  fclose(msgfd);
	else
	  fflush(stdout);

	return 0;
}

int log_debug(const char *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = do_log(L_DBG, msg, ap);
	va_end(ap);

	return r;
}

int log(int lvl, const char *msg, ...)
{
	va_list ap;
	int r;

	va_start(ap, msg);
	r = do_log(lvl, msg, ap);
	va_end(ap);

	return r;
}

