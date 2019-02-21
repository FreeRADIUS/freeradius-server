/*
 *   Permission to use, copy, modify, and distribute this software for any
 *   purpose with or without fee is hereby granted, provided that the above
 *   copyright notice and this permission notice appear in all copies.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/** Local implementation of the libgen (basename_r, dirname_r)
 *
 * @file src/lib/util/libgen.c
 *
 */
RCSID("$Id$")

#include <string.h>
#include <freeradius-devel/util/libgen.h>

#ifndef MIN
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

/* 
 * special thread-safe
 *
 * if 'buf' is NULL, 'buflen' is ignored and the length of the result is returned
 * otherwise, place result in 'buffer'
 *
 * at most buflen-1 characters written, plus a terminating zero
 *
 * return length of result.
 */
int fr_dirname(const char *path, char *buf, size_t buflen) {
	const char *endp;
	size_t len;

	/*
	 * If `path' is a null pointer or points to an empty string,
	 * return a pointer to the string ".".
	 */
	if (path == NULL || *path == '\0') {
		path = ".";
		len = 1;
		goto out;
	}

	/* Strip trailing slashes, if any. */
	endp = path + strlen(path) - 1;
	while (endp != path && *endp == '/')
		endp--;

	/* Find the start of the dir */
	while (endp > path && *endp != '/')
		endp--;

	if (endp == path) {
		path = *endp == '/' ? "/" : ".";
		len = 1;
		goto out;
	}

	do
		endp--;
	while (endp > path && *endp == '/');

	len = endp - path + 1;
out:
	if (buf != NULL && buflen != 0) {
		buflen = MIN(len, buflen - 1);
		if (buf != path)
			memcpy(buf, path, buflen);
		buf[buflen] = '\0';
	}
	return len;
}


int fr_basename(const char *path, char *buf, size_t buflen) {
	const char *startp, *endp;
	size_t len;

	/*
	 * If `path' is a null pointer or points to an empty string,
	 * return a pointer to the string ".".
	 */
	if (path == NULL || *path == '\0') {
		startp = ".";
		len = 1;
		goto out;
	}

	/* Strip trailing slashes, if any. */
	endp = path + strlen(path) - 1;
	while (endp != path && *endp == '/')
		endp--;

	/* Only slashes -> "/" */
	if (endp == path && *endp == '/') {
		startp = "/";
		len = 1;
		goto out;
	}

	/* Now find the beginning of this (final) component. */
	for (startp = endp; startp > path && *(startp - 1) != '/'; startp--)
		continue;

	/* ...and copy the result into the result buffer. */
	len = (endp - startp) + 1 /* last char */;
out:
	if (buf != NULL && buflen != 0) {
		buflen = MIN(len, buflen - 1);
		memcpy(buf, startp, buflen);
		buf[buflen] = '\0';
	}
	return len;
}

#if defined (TEST_LIBGEN)
int main(int argc, char *argv[]) {
	char *arg = argv[1];
	char buf[64];

	fr_dirname(arg, buf, sizeof(buf));
	printf("fr_dirname(\"%s\")  = '%s'\n", arg, buf);

	fr_basename(arg, buf, sizeof(buf));
	printf("fr_basename(\"%s\") = '%s'\n", arg, buf);

	return 0;
}
#endif
