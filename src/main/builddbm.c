/*
 * builddbm	Build a DBM file from an ASCII users file.
 *
 * Version:	@(#)builddbm  2.2  10-Aug-1999  miquels@cistron.nl
 *
 */
char sccsid[] =
"@(#)builddbm.c	2.2 Copyright 1999 Cistron Internet Services";

#include	"autoconf.h"

#include	<sys/types.h>
#include	<sys/time.h>
#include	<sys/stat.h>

#include	<stdio.h>
#include	<strings.h>
#include	<fcntl.h>
#include	<stdlib.h>
#include	<unistd.h>
#ifdef WITH_DBM
#  include	<dbm.h>
#endif
#ifdef WITH_NDBM
#  include	<ndbm.h>
#endif

#include	"radiusd.h"

char		*progname;
int		debug_flag;
char		*radius_dir;
char		*radlog_dir;

FILE		*userfd;


/*
 *	Print a list of VALUE_PAIRS into a string,
 *	separated by comma's and closed off with a newline.
 */
void makelist(char *out, int outlen, VALUE_PAIR *vp)
{
	char		*ptr;
	int		len;

	ptr = out;
	ptr[0] = 0;

	while (vp && outlen > 3) {
		vp_prints(ptr, outlen, vp);
		strcat(ptr, ", ");
		len = strlen(ptr);
		outlen -= len + 2;
		ptr += len;
		vp = vp->next;
	}
	strcat(ptr, "\n");
}


int main(int argc, char **argv)
{
	PAIR_LIST	*users;
	char		name[MAX_STRING_LEN];
	char		content[4096];
	int		len;
	datum		named;
	datum		contentd;
	int		defno = 0;
#ifdef WITH_DBM
	int		fd;
#endif
#ifdef WITH_NDBM
	DBM	*dbm;
#endif

	progname = argv[0];
	radius_dir = ".";
	librad_dodns = 0;

	if (dict_init(RADDBDIR, RADIUS_DICTIONARY) < 0) {
		librad_perror("builddbm");
		return 1;
	}

	/*
	 *	Read the "users" file.
	 */
	if ((users = pairlist_read(RADIUS_USERS, 1)) == NULL)
		exit(1);

	/*
	 *	Initialize a new, empty database.
	 */
	umask(077);
#ifdef WITH_DBM
	if ((fd = open("users.pag", O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
		fprintf(stderr, "%s: Couldn't open users.pag for writing\n",
			progname);
		exit(1);
	}
	close(fd);
	if ((fd = open("users.dir", O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0) {
		fprintf(stderr, "%s: Couldn't open users.dir for writing\n",
			progname);
		exit(1);
	}
	close(fd);
	if (dbminit("users") != 0) {
		fprintf(stderr, "%s: ", progname);
		perror("dbminit(users)");
		exit(1);
	}
#endif
#ifdef WITH_NDBM
	if ((dbm = dbm_open("users", O_RDWR|O_CREAT|O_TRUNC, 0600)) == NULL) {
		fprintf(stderr, "%s: ", progname);
		perror("dbm_open(users)");
		exit(1);
	}
#endif

	while (users) {

		makelist(content, sizeof(content), users->check);
		len = strlen(content);
		makelist(content + len, sizeof(content) - len, users->reply);

		strNcpy(name, users->name, sizeof(name));
		if (strcmp(name, "DEFAULT") == 0) {
			if (defno > 0)
				sprintf(name, "DEFAULT%d", defno);
			defno++;
		}
		named.dptr = name;
		named.dsize = strlen(name);
		contentd.dptr = content;
		contentd.dsize = strlen(content);
#ifdef WITH_DBM
		if (store(named, contentd) != 0)
#endif
#ifdef WITH_NDBM
		if (dbm_store(dbm, named, contentd, DBM_INSERT) != 0)
#endif
		{
			fprintf(stderr, "%s: Couldn't store datum for %s\n",
				progname, name);
			exit(1);
		}
		users = users->next;
	}
#ifdef WITH_DBM
	dbmclose();
#endif
#ifdef WITH_NDBM
	dbm_close(dbm);
#endif
	return 0;
}

