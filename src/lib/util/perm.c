/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Implementation of filed semaphores that release on exit
 *
 * @file src/lib/util/perm.c
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/perm.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>

/** Convert mode_t into humanly readable permissions flags
 *
 * @author Jonathan Leffler.
 *
 * @param mode to convert.
 * @param out Where to write the string to, must be exactly 10 bytes long.
 */
char const *fr_perm_mode_to_str(char out[static 10], mode_t mode)
{
	static char const *rwx[] = {"---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"};

	strcpy(&out[0], rwx[(mode >> 6) & 0x07]);
	strcpy(&out[3], rwx[(mode >> 3) & 0x07]);
	strcpy(&out[6], rwx[(mode & 7)]);
	if (mode & S_ISUID) out[2] = (mode & 0100) ? 's' : 'S';
	if (mode & S_ISGID) out[5] = (mode & 0010) ? 's' : 'l';
	if (mode & S_ISVTX) out[8] = (mode & 0100) ? 't' : 'T';
	out[9] = '\0';

	return out;
}

char const *fr_perm_mode_to_oct(char out[static 5], mode_t mode)
{
	out[0] = '0' + ((mode >> 9) & 0x07);
	out[1] = '0' + ((mode >> 6) & 0x07);
	out[2] = '0' + ((mode >> 3) & 0x07);
	out[3] = '0' + (mode & 0x07);
	out[4] = '\0';

	return out;
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
int fr_perm_getpwuid(TALLOC_CTX *ctx, struct passwd **out, uid_t uid)
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
		buff = talloc_realloc_size(ctx, buff, talloc_array_length(buff) * 2);
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
int fr_perm_getpwnam(TALLOC_CTX *ctx, struct passwd **out, char const *name)
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
		buff = talloc_realloc_size(ctx, buff, talloc_array_length(buff) * 2);
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
int fr_perm_getgrgid(TALLOC_CTX *ctx, struct group **out, gid_t gid)
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
		buff = talloc_realloc_size(ctx, buff, talloc_array_length(buff) * 2);
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
int fr_perm_getgrnam(TALLOC_CTX *ctx, struct group **out, char const *name)
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
		buff = talloc_realloc_size(ctx, buff, talloc_array_length(buff) * 2);
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

/** Resolve a user name to a GID
 *
 * @param[in] ctx	TALLOC_CTX for temporary allocations.
 * @param[in] out	where to write gid.
 * @param[in] name	of user.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_perm_uid_from_str(TALLOC_CTX *ctx, uid_t *out, char const *name)
{
	int ret;
	struct passwd *result;

	ret = fr_perm_getpwnam(ctx, &result, name);
	if (ret < 0) return -1;

	*out = result->pw_uid;
	talloc_free(result);
	return 0;
}

/** Resolve a group name to a GID
 *
 * @param[in] ctx	TALLOC_CTX for temporary allocations.
 * @param[in] out	where to write gid.
 * @param[in] name	of group.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_perm_gid_from_str(TALLOC_CTX *ctx, gid_t *out, char const *name)
{
	int ret;
	struct group *result;

	ret = fr_perm_getgrnam(ctx, &result, name);
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
char *fr_perm_uid_to_str(TALLOC_CTX *ctx, uid_t uid)
{
	struct passwd *result;
	char *out;

	if (fr_perm_getpwuid(ctx, &result, uid) < 0) return NULL;
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
char *fr_perm_gid_to_str(TALLOC_CTX *ctx, uid_t gid){
	struct group *result;
	char *out;

	if (fr_perm_getgrgid(ctx, &result, gid) < 0) return NULL;
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
void fr_perm_file_error(int num)
{
	char const	*error;
	struct passwd	*user = NULL;
	struct group	*group = NULL;

	error = fr_syserror(num);

	if (fr_perm_getpwuid(NULL, &user, geteuid()) < 0) goto finish;
	if (fr_perm_getgrgid(NULL, &group, getegid()) < 0) goto finish;

	fr_strerror_printf("Effective user/group - %s:%s: %s", user->pw_name, group->gr_name, error);
finish:
	talloc_free(user);
	talloc_free(group);
}
