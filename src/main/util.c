/*
 * util.c	Various utility functions.
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>

#include <sys/stat.h>
#include <fcntl.h>

#if HAVE_UNISTD_H
#	include <unistd.h>
#endif

#include "radiusd.h"

/*
 *	The signal() function in Solaris 2.5.1 sets SA_NODEFER in
 *	sa_flags, which causes grief if signal() is called in the
 *	handler before the cause of the signal has been cleared.
 *	(Infinite recursion).
 *
 *	The same problem appears on HPUX, so we avoid it, if we can.
 *
 *	Using sigaction() to reset the signal handler fixes the problem,
 *	so where available, we prefer that solution.
 */
void (*reset_signal(int signo, void (*func)(int)))(int)
{
#ifdef HAVE_SIGACTION
	struct sigaction act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
#ifdef  SA_INTERRUPT		/* SunOS */
	act.sa_flags |= SA_INTERRUPT;
#endif
	if (sigaction(signo, &act, &oact) < 0)
		return SIG_ERR;
	return oact.sa_handler;
#else
	
	/*
	 *	re-set by calling the 'signal' function, which
	 *	may cause infinite recursion and core dumps due to
	 *	stack growth.
	 *
	 *	However, the system is too dumb to implement sigaction(),
	 *	so we don't have a choice.
	 */
	signal(signo, func);
#endif
}


/*
 *	Free a REQUEST struct.
 */
void request_free(REQUEST **request_ptr)
{
	REQUEST *request;
	
	if (request_ptr == NULL) 
		return;
	request = *request_ptr;

	if (request->packet) 
		rad_free(&request->packet);

	if (request->proxy) 
		rad_free(&request->proxy);

	if (request->reply) 
		rad_free(&request->reply);

	if (request->proxy_reply) 
		rad_free(&request->proxy_reply);

	if (request->config_items) 
		pairfree(&request->config_items);

	request->username = NULL;
	request->password = NULL;

#ifndef NDEBUG
	request->magic = 0x01020304;	/* set the request to be nonsense */
	strcpy(request->secret, "REQUEST-DELETED");
	strcpy(request->proxysecret, "REQUEST-DELETED");
#endif
	free(request);

	*request_ptr = NULL;
}

/*
 *	Check a filename for sanity.
 *
 *	Allow only uppercase/lowercase letters, numbers, and '-_/.'
 */
int rad_checkfilename(const char *filename)
{
	if (strspn(filename, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/.") == strlen(filename)) {
		return 0;
	}

	return -1;
}

/*
 *	Create possibly many directories.
 *
 *	Note that the input directory name is NOT a constant!
 *	This is so that IF an error is returned, the 'directory' ptr
 *	points to the name of the file which caused the error.
 */
int rad_mkdir(char *directory, int mode)
{
	int rcode;
	char *p;
	struct stat st;

	/*
	 *	If the directory exists, don't do anything.
	 */
	if (stat(directory, &st) == 0) {
		return 0;
	}

	/*
	 *	Look for the LAST directory name.  Try to create that,
	 *	failing on any error.
	 */
	p = strrchr(directory, '/');
	if (p != NULL) {
		*p = '\0';
		rcode = rad_mkdir(directory, mode);

		/*
		 *	On error, we leave the directory name as the
		 *	one which caused the error.
		 */
		if (rcode < 0) {
			return rcode;
		}

		/*
		 *	Reset the directory delimiter, and go ask
		 *	the system to make the directory.
		 */
		*p = '/';
	} else {
		return 0;
	}

	/*
	 *	Having done everything successfully, we do the
	 *	system call to actually go create the directory.
	 */
	return mkdir(directory, mode);
}


/*
 *	Module malloc() call, which does stuff if the malloc fails.
 *
 *	This call ALWAYS succeeds!
 */
void *rad_malloc(size_t size)
{
	void *ptr = malloc(size);
	
	if (ptr == NULL) {
		radlog(L_ERR|L_CONS, "no memory");
		exit(1);
	}

	return ptr;
}

void xfree(const char *ptr)
{
	free((char *)ptr);
}

/*
 *	Logs an error message and aborts the program
 *
 */

void rad_assert_fail (const char *file, unsigned int line)
{
	radlog(L_ERR|L_CONS, "Assertion failed in %s, line %u", file, line);
	abort();
}
