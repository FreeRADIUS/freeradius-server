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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *

 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/stats.h>
#include <freeradius-devel/server/util.h>

#include <freeradius-devel/util/misc.h>

#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>

static bool suid_down_permanent = false;	//!< Record whether we've permanently dropped privilledges

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

	memset(&act, 0, sizeof(act));
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

	return NULL;
#endif
}

/** Create possibly many directories.
 *
 * @note that the input directory name is NOT treated as a constant. This is so that
 *	 if an error is returned, the 'directory' ptr points to the name of the file
 *	 which caused the error.
 *
 * @param dir path to directory to create.
 * @param mode for new directories.
 * @param uid to set on new directories, may be -1 to use effective uid.
 * @param gid to set on new directories, may be -1 to use effective gid.
 * @return
 *	- 0 on success.
 *	- -1 on failure. Error available as errno.
 */
int rad_mkdir(char *dir, mode_t mode, uid_t uid, gid_t gid)
{
	int rcode, fd;
	char *p;

	/*
	 *	Try to make the dir.  If it exists, chmod it.
	 *	If a path doesn't exist, that's OK.  Otherwise
	 *	return with an error.
	 *
	 *	Directories permissions are initially set so
	 *	that only we should have access. This prevents
	 *	an attacker removing them and swapping them
	 *	out for a link to somewhere else.
	 *	We change them to the correct permissions later.
	 */
	rcode = mkdir(dir, 0700);
	if (rcode < 0) {
		switch (errno) {
		case EEXIST:
			return 0; /* don't change permissions */

		case ENOENT:
			break;

		default:
			return rcode;
		}

		/*
		 *	A component in the dir path doesn't
		 *	exist.  Look for the LAST dir name.  Try
		 *	to create that.  If there's an error, we leave
		 *	the dir path as the one at which the
		 *	error occured.
		 */
		p = strrchr(dir, FR_DIR_SEP);
		if (!p || (p == dir)) return -1;

		*p = '\0';
		rcode = rad_mkdir(dir, mode, uid, gid);
		if (rcode < 0) return rcode;

		/*
		 *	Reset the dir path, and try again to
		 *	make the dir.
		 */
		*p = FR_DIR_SEP;
		rcode = mkdir(dir, 0700);
		if (rcode < 0) return rcode;
	} /* else we successfully created the dir */

	/*
	 *	Set the permissions on the directory we created
	 *	this should never fail unless there's a race.
	 */
	fd = open(dir, O_DIRECTORY);
	if (fd < 0) return -1;

	rcode = fchmod(fd, mode);
	if (rcode < 0) {
		close(fd);
		return rcode;
	}

	if ((uid != (uid_t)-1) || (gid != (gid_t)-1)) {
		rad_suid_up();
		rcode = fchown(fd, uid, gid);
		rad_suid_down();
	}
	close(fd);

	return rcode;
}

/** Ensures that a filename cannot walk up the directory structure
 *
 * Also sanitizes control chars.
 *
 * @param request Current request (may be NULL).
 * @param out Output buffer.
 * @param outlen Size of the output buffer.
 * @param in string to escape.
 * @param arg Context arguments (unused, should be NULL).
 */
size_t rad_filename_make_safe(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	char const *q = in;
	char *p = out;
	size_t left = outlen;

	while (*q) {
		if (*q != '/') {
			if (left < 2) break;

			/*
			 *	Smash control characters and spaces to
			 *	something simpler.
			 */
			if (*q < ' ') {
				*(p++) = '_';
				q++;
				continue;
			}

			*(p++) = *(q++);
			left--;
			continue;
		}

		/*
		 *	For now, allow slashes in the expanded
		 *	filename.  This allows the admin to set
		 *	attributes which create sub-directories.
		 *	Unfortunately, it also allows users to send
		 *	attributes which *may* end up creating
		 *	sub-directories.
		 */
		if (left < 2) break;
		*(p++) = *(q++);

		/*
		 *	Get rid of ////../.././///.///..//
		 */
	redo:
		/*
		 *	Get rid of ////
		 */
		if (*q == '/') {
			q++;
			goto redo;
		}

		/*
		 *	Get rid of /./././
		 */
		if ((q[0] == '.') &&
		    (q[1] == '/')) {
			q += 2;
			goto redo;
		}

		/*
		 *	Get rid of /../../../
		 */
		if ((q[0] == '.') && (q[1] == '.') &&
		    (q[2] == '/')) {
			q += 3;
			goto redo;
		}
	}
	*p = '\0';

	return (p - out);
}

/** Escapes the raw string such that it should be safe to use as part of a file path
 *
 * This function is designed to produce a string that's still readable but portable
 * across the majority of file systems.
 *
 * For security reasons it cannot remove characters from the name, and must not allow
 * collisions to occur between different strings.
 *
 * With that in mind '-' has been chosen as the escape character, and will be double
 * escaped '-' -> '--' to avoid collisions.
 *
 * Escaping should be reversible if the original string needs to be extracted.
 *
 * @note function takes additional arguments so that it may be used as an xlat escape
 *	function but it's fine to call it directly.
 *
 * @note OSX/Unix/NTFS/VFAT have a max filename size of 255 bytes.
 *
 * @param request Current request (may be NULL).
 * @param out Output buffer.
 * @param outlen Size of the output buffer.
 * @param in string to escape.
 * @param arg Context arguments (unused, should be NULL).
 */
size_t rad_filename_escape(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, UNUSED void *arg)
{
	size_t freespace = outlen;

	while (*in != '\0') {
		size_t utf8_len;

		/*
		 *	Encode multibyte UTF8 chars
		 */
		utf8_len = fr_utf8_char((uint8_t const *) in, -1);
		if (utf8_len > 1) {
			if (freespace <= (utf8_len * 3)) break;

			switch (utf8_len) {
			case 2:
				snprintf(out, freespace, "-%x-%x", in[0], in[1]);
				break;

			case 3:
				snprintf(out, freespace, "-%x-%x-%x", in[0], in[1], in[2]);
				break;

			case 4:
				snprintf(out, freespace, "-%x-%x-%x-%x", in[0], in[1], in[2], in[3]);
				break;
			}

			freespace -= (utf8_len * 3);
			out += (utf8_len * 3);
			in += utf8_len;

			continue;
		}

		/*
		 *	Safe chars
		 */
		if (((*in >= 'A') && (*in <= 'Z')) ||
		    ((*in >= 'a') && (*in <= 'z')) ||
		    ((*in >= '0') && (*in <= '9')) ||
		    (*in == '_')) {
		    	if (freespace <= 1) break;

		 	*out++ = *in++;
		 	freespace--;
		 	continue;
		}
		if (freespace <= 2) break;

		/*
		 *	Double escape '-' (like \\)
		 */
		if (*in == '-') {
			*out++ = '-';
			*out++ = '-';

			freespace -= 2;
			in++;
			continue;
		}

		/*
		 *	Unsafe chars
		 */
		*out++ = '-';
		fr_bin2hex(out, (uint8_t const *)in++, 1);
		out += 2;
		freespace -= 3;
	}
	*out = '\0';

	return outlen - freespace;
}

/** Converts data stored in a file name back to its original form
 *
 * @param out Where to write the unescaped string (may be the same as in).
 * @param outlen Length of the output buffer.
 * @param in Input filename.
 * @param inlen Length of input.
 * @return
 *	- Number of bytes written to output buffer
 *	- offset where parse error occurred on failure.
 */
ssize_t rad_filename_unescape(char *out, size_t outlen, char const *in, size_t inlen)
{
	char const *p, *end = in + inlen;
	size_t freespace = outlen;

	for (p = in; p < end; p++) {
		if (freespace <= 1) break;

		if (((*p >= 'A') && (*p <= 'Z')) ||
		    ((*p >= 'a') && (*p <= 'z')) ||
		    ((*p >= '0') && (*p <= '9')) ||
		    (*p == '_')) {
		 	*out++ = *p;
		 	freespace--;
		 	continue;
		}

		if (p[0] == '-') {
			/*
			 *	End of input, '-' needs at least one extra char after
			 *	it to be valid.
			 */
			if ((end - p) < 2) return in - p;
			if (p[1] == '-') {
				p++;
				*out++ = '-';
				freespace--;
				continue;
			}

			/*
			 *	End of input, '-' must be followed by <hex><hex>
			 *	but there aren't enough chars left
			 */
			if ((end - p) < 3) return in - p;

			/*
			 *	If hex2bin returns 0 the next two chars weren't hexits.
			 */
			if (fr_hex2bin((uint8_t *) out, 1, in, 1) == 0) return in - (p + 1);
			in += 2;
			out++;
			freespace--;
		}

		return in - p; /* offset we found the bad char at */
	}
	*out = '\0';

	return outlen - freespace;	/* how many bytes were written */
}

/** talloc a buffer to hold the concatenated value of all elements of argv
 *
 * @param ctx to allocate buffer in.
 * @param argv array of substrings.
 * @param argc length of array.
 * @param c separation character. Optional, may be '\0' for no separator.
 * @return the concatenation of the elements of argv, separated by c.
 */
char *rad_ajoin(TALLOC_CTX *ctx, char const **argv, int argc, char c)
{
	char *buff, *p;
	int i;
	size_t total = 0, freespace;

	if (!*argv) {
		goto null;
	}

	for (i = 0; i < argc; i++) total += (strlen(argv[i]) + ((c == '\0') ? 0 : 1));
	if (!total) {
	null:
		return talloc_zero_array(ctx, char, 1);
	}

	if (c == '\0') total++;

	freespace = total;
	buff = p = talloc_array(ctx, char, total);
	for (i = 0; i < argc; i++) {
		size_t len;

		len = strlcpy(p, argv[i], freespace);
		p += len;
		freespace -= len;

		*p++ = c;
		freespace--;
	}
	buff[total] = '\0';

	return buff;
}

/*
 *	Copy a quoted string.
 */
static int rad_copy_string(char *to, char const *from)
{
	int length = 0;
	char quote = *from;

	do {
		if (*from == '\\') {
			*(to++) = *(from++);
			length++;
		}
		*(to++) = *(from++);
		length++;
	} while (*from && (*from != quote));

	if (*from != quote) return -1; /* not properly quoted */

	*(to++) = quote;
	length++;
	*to = '\0';

	return length;
}

/*
 *	Copy a quoted string but without the quotes. The length
 *	returned is the number of chars written; the number of
 *	characters consumed is 2 more than this.
 */
static int rad_copy_string_bare(char *to, char const *from)
{
	int length = 0;
	char quote = *from;

	from++;
	while (*from && (*from != quote)) {
		if (*from == '\\') {
			*(to++) = *(from++);
			length++;
		}
		*(to++) = *(from++);
		length++;
	}

	if (*from != quote) return -1; /* not properly quoted */

	*to = '\0';

	return length;
}


/*
 *	Copy a %{} string.
 */
static int rad_copy_variable(char *to, char const *from)
{
	int length = 0;
	int sublen;

	*(to++) = *(from++);
	length++;

	while (*from) {
		switch (*from) {
		case '"':
		case '\'':
			sublen = rad_copy_string(to, from);
			if (sublen < 0) return sublen;
			from += sublen;
			to += sublen;
			length += sublen;
			break;

		case '}':	/* end of variable expansion */
			*(to++) = *(from++);
			*to = '\0';
			length++;
			return length; /* proper end of variable */

		case '\\':
			*(to++) = *(from++);
			*(to++) = *(from++);
			length += 2;
			break;

		case '%':	/* start of variable expansion */
			if (from[1] == '{') {
				*(to++) = *(from++);
				length++;

				sublen = rad_copy_variable(to, from);
				if (sublen < 0) return sublen;
				from += sublen;
				to += sublen;
				length += sublen;
				break;
			} /* else FIXME: catch %%{ ?*/

			/* FALL-THROUGH */
		default:
			*(to++) = *(from++);
			length++;
			break;
		}
	} /* loop over the input string */

	/*
	 *	We ended the string before a trailing '}'
	 */

	return -1;
}

uint32_t rad_pps(uint32_t *past, uint32_t *present, time_t *then, struct timeval *now)
{
	uint32_t pps;

	if (*then != now->tv_sec) {
		*then = now->tv_sec;
		*past = *present;
		*present = 0;
	}

	/*
	 *	Bootstrap PPS by looking at a percentage of
	 *	the previous PPS.  This lets us take a moving
	 *	count, without doing a moving average.  If
	 *	we're a fraction "f" (0..1) into the current
	 *	second, we can get a good guess for PPS by
	 *	doing:
	 *
	 *	PPS = pps_now + pps_old * (1 - f)
	 *
	 *	It's an instantaneous measurement, rather than
	 *	a moving average.  This will hopefully let it
	 *	respond better to sudden spikes.
	 *
	 *	Doing the calculations by thousands allows us
	 *	to not overflow 2^32, AND to not underflow
	 *	when we divide by USEC.
	 */
	pps = USEC - now->tv_usec; /* useconds left in previous second */
	pps /= 1000;		   /* scale to milliseconds */
	pps *= *past;		   /* multiply by past count to get fraction */
	pps /= 1000;		   /* scale to usec again */
	pps += *present;	   /* add in current count */

	return pps;
}

/** Split string into words and expand each one
 *
 * @param request Current request.
 * @param cmd string to split.
 * @param max_argc the maximum number of arguments to split into.
 * @param argv Where to write the pointers into argv_buf.
 * @param can_fail If false, stop processing if any of the xlat expansions fail.
 * @param argv_buflen size of argv_buf.
 * @param argv_buf temporary buffer we used to mangle/expand cmd.
 *	Pointers to offsets of this buffer will be written to argv.
 * @return argc or -1 on failure.
 */

int rad_expand_xlat(REQUEST *request, char const *cmd,
		    int max_argc, char const *argv[], bool can_fail,
		    size_t argv_buflen, char *argv_buf)
{
	char const *from;
	char *to;
	int argc = -1;
	int i;
	int left;

	if (strlen(cmd) > (argv_buflen - 1)) {
		fr_strerror_printf("Expansion string is too long for output buffer");
		return -1;
	}

	/*
	 *	Check for bad escapes.
	 */
	if (cmd[strlen(cmd) - 1] == '\\') {
		fr_strerror_printf("Expansion string ends with a trailing backslash - invalid escape sequence");
		return -1;
	}

	strlcpy(argv_buf, cmd, argv_buflen);

	/*
	 *	Split the string into argv's BEFORE doing xlat_eval...
	 */
	from = cmd;
	to = argv_buf;
	argc = 0;
	while (*from) {
		int length;

		/*
		 *	Skip spaces.
		 */
		if ((*from == ' ') || (*from == '\t')) {
			from++;
			continue;
		}

		argv[argc] = to;
		argc++;

		if (argc >= (max_argc - 1)) break;

		/*
		 *	Copy the argv over to our buffer.
		 */
		while (*from && (*from != ' ') && (*from != '\t')) {
			if (to >= argv_buf + argv_buflen - 1) {
				fr_strerror_printf("Expansion string is too long for output buffer");
				return -1;
			}

			switch (*from) {
			case '"':
			case '\'':
				length = rad_copy_string_bare(to, from);
				if (length < 0) {
					fr_strerror_printf("Invalid quoted string in expansion");
					return -1;
				}
				from += length+2;
				to += length;
				break;

			case '%':
				if (from[1] == '{') {
					*(to++) = *(from++);

					length = rad_copy_variable(to, from);
					if (length < 0) {
						fr_strerror_printf("Invalid variable in expansion");
						return -1;
					}
					from += length;
					to += length;
				} else { /* FIXME: catch %%{ ? */
					*(to++) = *(from++);
				}
				break;

			case '\\':
				if (from[1] == ' ') from++;
				/* FALL-THROUGH */

			default:
				*(to++) = *(from++);
			}
		} /* end of string, or found a space */

		*(to++) = '\0';	/* terminate the string */
	}

	/*
	 *	We have to have SOMETHING, at least.
	 */
	if (argc <= 0) {
		fr_strerror_printf("Expansion string is empty");
		return -1;
	}

	/*
	 *	Expand each string, as appropriate.
	 */
	left = argv_buf + argv_buflen - to;
	for (i = 0; i < argc; i++) {
		int sublen;

		/*
		 *	Don't touch argv's which won't be translated.
		 */
		if (strchr(argv[i], '%') == NULL) continue;

		if (!request) continue;

		sublen = xlat_eval(to, left - 1, request, argv[i], NULL, NULL);
		if (sublen <= 0) {
			if (can_fail) {
				/*
				 *	Fail to be backwards compatible.
				 *
				 *	It's yucky, but it won't break anything,
				 *	and it won't cause security problems.
				 */
				sublen = 0;
			} else {
				fr_strerror_printf("Failed expanding substring");
				return -1;
			}
		}

		argv[i] = to;
		to += sublen;
		*(to++) = '\0';
		left -= sublen;
		left--;

		if (left <= 0) {
			fr_strerror_printf("Ran out of space while expanding arguments");
			return -1;
		}
	}
	argv[argc] = NULL;

	return argc;
}

/** Return the default log dir
 *
 * This is set at build time from --prefix
 * @return the value of LOGDIR
 */
char const *rad_default_log_dir(void)
{
	return LOGDIR;
}

/** Return the default lib dir
 *
 * This is set at build time from --prefix
 * @return the value of LIBDIR
 */
char const *rad_default_lib_dir(void)
{
	return LIBDIR;
}

/** Return the default raddb dir
 *
 * This is set at build time from --prefix
 * @return the value of RADDBDIR
 */
char const *rad_default_raddb_dir(void)
{
	return RADDBDIR;
}

/** Return the default run dir
 *
 * This is set at build time from --prefix
 * @return the value of RUNDIR
 */
char const *rad_default_run_dir(void)
{
	return RUNDIR;
}

/** Return the default sbin dir
 *
 * This is set at build time from --prefix
 * @return the value of SBINDIR
 */
char const *rad_default_sbin_dir(void)
{
	return SBINDIR;
}

/** Return the default radacct dir
 *
 * This is set at build time from --prefix
 * @return the value of RADIR
 */
char const *rad_default_radacct_dir(void)
{
	return RADIR;
}

/** Convert mode_t into humanly readable permissions flags
 *
 * @author Jonathan Leffler.
 *
 * @param mode to convert.
 * @param out Where to write the string to, must be exactly 10 bytes long.
 */
void rad_mode_to_str(char out[static 10], mode_t mode)
{
	static char const *rwx[] = {"---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"};

	strcpy(&out[0], rwx[(mode >> 6) & 0x07]);
	strcpy(&out[3], rwx[(mode >> 3) & 0x07]);
	strcpy(&out[6], rwx[(mode & 7)]);
	if (mode & S_ISUID) out[2] = (mode & 0100) ? 's' : 'S';
	if (mode & S_ISGID) out[5] = (mode & 0010) ? 's' : 'l';
	if (mode & S_ISVTX) out[8] = (mode & 0100) ? 't' : 'T';
	out[9] = '\0';
}

void rad_mode_to_oct(char out[static 5], mode_t mode)
{
	out[0] = '0' + ((mode >> 9) & 0x07);
	out[1] = '0' + ((mode >> 6) & 0x07);
	out[2] = '0' + ((mode >> 3) & 0x07);
	out[3] = '0' + (mode & 0x07);
	out[4] = '\0';
}

/** Resolve a uid to a passwd entry
 *
 * Resolves a uid to a passwd entry. The memory to hold the
 * passwd entry is talloced under ctx, and must be freed when no
 * longer required.
 *
 * @param ctx to allocate passwd entry in.
 * @param out Where to write pointer to entry.
 * @param uid to resolve.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rad_getpwuid(TALLOC_CTX *ctx, struct passwd **out, uid_t uid)
{
	static size_t len;
	uint8_t *buff;
	int ret;

	*out = NULL;

	/*
	 *	We assume this won't change between calls,
	 *	and that the value is the same, so races don't
	 *	matter.
	 */
	if (len == 0) {
#ifdef _SC_GETPW_R_SIZE_MAX
		long int sc_len;

		sc_len = sysconf(_SC_GETPW_R_SIZE_MAX);
		if (sc_len <= 0) sc_len = 1024;
		len = (size_t)sc_len;
#else
		len = 1024;
#endif
	}

	buff = talloc_array(ctx, uint8_t, sizeof(struct passwd) + len);
	if (!buff) return -1;

	/*
	 *	In some cases we may need to dynamically
	 *	grow the string buffer.
	 */
	while ((ret = getpwuid_r(uid, (struct passwd *)buff, (char *)(buff + sizeof(struct passwd)),
				 talloc_array_length(buff) - sizeof(struct passwd), out)) == ERANGE) {
		MEM(buff = talloc_realloc_size(ctx, buff, talloc_array_length(buff) * 2));
	}

	if ((ret != 0) || !*out) {
		fr_strerror_printf("%s", (errno != 0) ? fr_syserror(ret) : "Non-existent user");
		talloc_free(buff);
		errno = ret;
		return -1;
	}

	talloc_set_type(buff, struct passwd);
	*out = (struct passwd *)buff;

	return 0;
}

/** Resolve a username to a passwd entry
 *
 * Resolves a username to a passwd entry. The memory to hold the
 * passwd entry is talloced under ctx, and must be freed when no
 * longer required.
 *
 * @param ctx to allocate passwd entry in.
 * @param out Where to write pointer to entry.
 * @param name to resolve.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rad_getpwnam(TALLOC_CTX *ctx, struct passwd **out, char const *name)
{
	static size_t len;
	uint8_t *buff;
	int ret;

	*out = NULL;

	/*
	 *	We assume this won't change between calls,
	 *	and that the value is the same, so races don't
	 *	matter.
	 */
	if (len == 0) {
#ifdef _SC_GETPW_R_SIZE_MAX
		long int sc_len;

		sc_len = sysconf(_SC_GETPW_R_SIZE_MAX);
		if (sc_len <= 0) sc_len = 1024;
		len = (size_t)sc_len;
#else
		sc_len = 1024;
#endif
	}

	buff = talloc_array(ctx, uint8_t, sizeof(struct passwd) + len);
	if (!buff) return -1;

	/*
	 *	In some cases we may need to dynamically
	 *	grow the string buffer.
	 */
	while ((ret = getpwnam_r(name, (struct passwd *)buff, (char *)(buff + sizeof(struct passwd)),
				 talloc_array_length(buff) - sizeof(struct passwd), out)) == ERANGE) {
		MEM(buff = talloc_realloc_size(ctx, buff, talloc_array_length(buff) * 2));
	}

	if ((ret != 0) || !*out) {
		fr_strerror_printf("%s", (errno != 0) ? fr_syserror(ret) : "Non-existent user");
		talloc_free(buff);
		errno = ret;
		return -1;
	}

	talloc_set_type(buff, struct passwd);
	*out = (struct passwd *)buff;

	return 0;
}

/** Resolve a gid to a group database entry
 *
 * Resolves a gid to a group database entry. The memory to hold the
 * group entry is talloced under ctx, and must be freed when no
 * longer required.
 *
 * @param ctx to allocate passwd entry in.
 * @param out Where to write pointer to entry.
 * @param gid to resolve.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rad_getgrgid(TALLOC_CTX *ctx, struct group **out, gid_t gid)
{
	static size_t len;
	uint8_t *buff;
	int ret;

	*out = NULL;

	/*
	 *	We assume this won't change between calls,
	 *	and that the value is the same, so races don't
	 *	matter.
	 */
	if (len == 0) {
#ifdef _SC_GETGR_R_SIZE_MAX
		long int sc_len;

		sc_len = sysconf(_SC_GETGR_R_SIZE_MAX);
		if (sc_len <= 0) sc_len = 1024;
		len = (size_t)sc_len;
#else
		sc_len = 1024;
#endif
	}

	buff = talloc_array(ctx, uint8_t, sizeof(struct group) + len);
	if (!buff) return -1;

	/*
	 *	In some cases we may need to dynamically
	 *	grow the string buffer.
	 */
	while ((ret = getgrgid_r(gid, (struct group *)buff, (char *)(buff + sizeof(struct group)),
				 talloc_array_length(buff) - sizeof(struct group), out)) == ERANGE) {
		MEM(buff = talloc_realloc_size(ctx, buff, talloc_array_length(buff) * 2));
	}

	if ((ret != 0) || !*out) {
		fr_strerror_printf("%s", (ret != 0) ? fr_syserror(ret) : "Non-existent group");
		talloc_free(buff);
		errno = ret;
		return -1;
	}

	talloc_set_type(buff, struct group);
	*out = (struct group *)buff;

	return 0;
}

/** Resolve a group name to a group database entry
 *
 * Resolves a group name to a group database entry.
 * The memory to hold the group entry is talloced under ctx,
 * and must be freed when no longer required.
 *
 * @param ctx to allocate passwd entry in.
 * @param out Where to write pointer to entry.
 * @param name to resolve.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rad_getgrnam(TALLOC_CTX *ctx, struct group **out, char const *name)
{
	static size_t len;
	uint8_t *buff;
	int ret;

	*out = NULL;

	/*
	 *	We assume this won't change between calls,
	 *	and that the value is the same, so races don't
	 *	matter.
	 */
	if (len == 0) {
#ifdef _SC_GETGR_R_SIZE_MAX
		long int sc_len;

		sc_len = sysconf(_SC_GETGR_R_SIZE_MAX);
		if (sc_len <= 0) sc_len = 1024;
		len = (size_t)sc_len;
#else
		len = 1024;
#endif
	}

	buff = talloc_array(ctx, uint8_t, sizeof(struct group) + len);
	if (!buff) return -1;

	/*
	 *	In some cases we may need to dynamically
	 *	grow the string buffer.
	 */
	while ((ret = getgrnam_r(name, (struct group *)buff, (char *)(buff + sizeof(struct group)),
				 talloc_array_length(buff) - sizeof(struct group), out)) == ERANGE) {
		MEM(buff = talloc_realloc_size(ctx, buff, talloc_array_length(buff) * 2));
	}

	if ((ret != 0) || !*out) {
		fr_strerror_printf("%s", (ret != 0) ? fr_syserror(ret) : "Non-existent group");
		talloc_free(buff);
		errno = ret;
		return -1;
	}

	talloc_set_type(buff, struct group);
	*out = (struct group *)buff;

	return 0;
}

/** Resolve a group name to a GID
 *
 * @param ctx TALLOC_CTX for temporary allocations.
 * @param name of group.
 * @param out where to write gid.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rad_getgid(TALLOC_CTX *ctx, gid_t *out, char const *name)
{
	int ret;
	struct group *result;

	ret = rad_getgrnam(ctx, &result, name);
	if (ret < 0) return -1;

	*out = result->gr_gid;
	talloc_free(result);
	return 0;
}

/** Print uid to a string
 *
 * @param ctx TALLOC_CTX for temporary allocations.
 * @param uid to resolve.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
char *rad_asprint_uid(TALLOC_CTX *ctx, uid_t uid)
{
	struct passwd *result;
	char *out;

	if (rad_getpwuid(ctx, &result, uid) < 0) return NULL;
	out = talloc_typed_strdup(ctx, result->pw_name);
	talloc_free(result);

	return out;
}

/** Print gid to a string
 *
 * @param ctx TALLOC_CTX for temporary allocations.
 * @param gid to resolve.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
char *rad_asprint_gid(TALLOC_CTX *ctx, uid_t gid){
	struct group *result;
	char *out;

	if (rad_getgrgid(ctx, &result, gid) < 0) return NULL;
	out = talloc_typed_strdup(ctx, result->gr_name);
	talloc_free(result);

	return out;
}

/** Write a file access error to the fr_strerror buffer, including euid/egid
 *
 * @note retrieve error with fr_strerror()
 *
 * @param num Usually errno, unless the error is returned by the function.
 */
void rad_file_error(int num)
{
	char const	*error;
	struct passwd	*user = NULL;
	struct group	*group = NULL;

	error = fr_syserror(num);

	if (rad_getpwuid(NULL, &user, geteuid()) < 0) goto finish;
	if (rad_getgrgid(NULL, &group, getegid()) < 0) goto finish;

	fr_strerror_printf("Effective user/group - %s:%s: %s", user->pw_name, group->gr_name, error);
finish:
	talloc_free(user);
	talloc_free(group);
}

#ifdef HAVE_SETUID
static bool doing_setuid = false;
static uid_t suid_down_uid = (uid_t)-1;

/** Set the uid and gid used when dropping privileges
 *
 * @note if this function hasn't been called, rad_suid_down will have no effect.
 *
 * @param uid to drop down to.
 */
void rad_suid_set_down_uid(uid_t uid)
{
	suid_down_uid = uid;
	doing_setuid = true;
}

#  if defined(HAVE_SETRESUID) && defined (HAVE_GETRESUID)
void rad_suid_up(void)
{
	uid_t ruid, euid, suid;

	if (getresuid(&ruid, &euid, &suid) < 0) {
		ERROR("Failed getting saved UID's");
		fr_exit_now(1);
	}

	if (setresuid(-1, suid, -1) < 0) {
		ERROR("Failed switching to privileged user");
		fr_exit_now(1);
	}

	if (geteuid() != suid) {
		ERROR("Switched to unknown UID");
		fr_exit_now(1);
	}
}

void rad_suid_down(void)
{
	if (!doing_setuid) return;

	if (setresuid(-1, suid_down_uid, geteuid()) < 0) {
		struct passwd *passwd;
		char const *name;

		name = (rad_getpwuid(NULL, &passwd, suid_down_uid) < 0) ? "unknown" : passwd->pw_name;
		ERROR("Failed switching to uid %s: %s", name, fr_syserror(errno));
		talloc_free(passwd);
		fr_exit_now(1);
	}

	if (geteuid() != suid_down_uid) {
		ERROR("Failed switching uid: UID is incorrect");
		fr_exit_now(1);
	}

	fr_reset_dumpable();
}

void rad_suid_down_permanent(void)
{
	if (!doing_setuid) return;

	if (setresuid(suid_down_uid, suid_down_uid, suid_down_uid) < 0) {
		struct passwd *passwd;
		char const *name;

		name = (rad_getpwuid(NULL, &passwd, suid_down_uid) < 0) ? "unknown" : passwd->pw_name;
		ERROR("Failed in permanent switch to uid %s: %s", name, fr_syserror(errno));
		talloc_free(passwd);
		fr_exit_now(1);
	}

	if (geteuid() != suid_down_uid) {
		ERROR("Switched to unknown uid");
		fr_exit_now(1);
	}

	fr_reset_dumpable();

	suid_down_permanent = true;
}
#  else
/*
 *	Much less secure...
 */
void rad_suid_up(void)
{
	if (!doing_setuid) return;

	if (seteuid(0) < 0) {
		ERROR("Failed switching up to euid 0: %s", fr_syserror(errno));
		fr_exit_now(1);
	}

}

void rad_suid_down(void)
{
	if (!doing_setuid) return;

	if (geteuid() == suid_down_uid) return;

	if (seteuid(suid_down_uid) < 0) {
		struct passwd *passwd;
		char const *name;

		name = (rad_getpwuid(NULL, &passwd, suid_down_uid) < 0) ? "unknown": passwd->pw_name;
		ERROR("Failed switching to euid %s: %s", name, fr_syserror(errno));
		talloc_free(passwd);
		fr_exit_now(1);
	}

	fr_reset_dumpable();
}

void rad_suid_down_permanent(void)
{
	if (!doing_setuid) return;

	/*
	 *	Already done.  Don't do anything else.
	 */
	if (getuid() == suid_down_uid) return;

	/*
	 *	We're root, but running as a normal user.  Fix that,
	 *	so we can call setuid().
	 */
	if (geteuid() == suid_down_uid) {
		rad_suid_up();
	}

	if (setuid(suid_down_uid) < 0) {
		struct passwd *passwd;
		char const *name;

		name = (rad_getpwuid(NULL, &passwd, suid_down_uid) < 0) ? "unknown": passwd->pw_name;
		ERROR("Failed switching permanently to uid %s: %s", name, fr_syserror(errno));
		talloc_free(passwd);
		fr_exit_now(1);
	}

	fr_reset_dumpable();

	suid_down_permanent = true;
}
#  endif /* HAVE_SETRESUID && HAVE_GETRESUID */
#else  /* HAVE_SETUID */
void rad_suid_set_down_uid(uid_t uid)
{
}

void rad_suid_up(void)
{
}

void rad_suid_down(void)
{
	fr_reset_dumpable();
}

void rad_suid_down_permanent(void)
{
	fr_reset_dumpable();
}
#endif /* HAVE_SETUID */

/** Return whether we've permanently dropped root privileges
 *
 * @return
 *	- true if root privileges have been dropped.
 *	- false if root privileges have not been dropped.
 */
bool rad_suid_is_down_permanent(void)
{
	return suid_down_permanent;
}

/** Alter the effective user id
 *
 * @param uid to set
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rad_seuid(uid_t uid)
{
	if (seteuid(uid) < 0) {
		int sete_errno = errno;	/* errno sets overwritten by rad_getpwuid */
		struct passwd *passwd;

		if (rad_getpwuid(NULL, &passwd, uid) < 0) return -1;
		fr_strerror_printf("%s", fr_syserror(sete_errno));
		talloc_free(passwd);

		return -1;
	}
	return 0;
}

/** Alter the effective user id
 *
 * @param gid to set
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rad_segid(gid_t gid)
{
	if (setegid(gid) < 0) {
		int sete_errno = errno;	/* errno sets overwritten by rad_getgrgid */
		struct group *group;

		if (rad_getgrgid(NULL, &group, gid) < 0) return -1;
		fr_strerror_printf("%s", fr_syserror(sete_errno));
		talloc_free(group);

		return -1;
	}
	return 0;
}
