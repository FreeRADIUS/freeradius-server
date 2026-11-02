/*
 *   This program is free software; you can redistribute it and/or modify
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

/**
 * @file src/listen/ldap_sync/sync_touch.c
 *
 * @brief Test utility that touches entries, so LDAP sync clients re-process them.
 *
 * Replaces an attribute with its current values, which OpenLDAP records as a
 * modification (other servers may not), and skips entries without the attribute.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

USES_APPLE_DEPRECATED_API

#include <freeradius-devel/autoconf.h>

#include <ldap.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

typedef struct {
	char const	*uri;		//!< LDAP server to connect to.
	bool		start_tls;	//!< Whether to use the StartTLS extended operation.
	char const	*bind_dn;	//!< Distinguished Name (DN) to bind as.  NULL for an anonymous bind.
	char const	*bind_pw;	//!< Password to bind with.
	char const	*base_dn;	//!< Where to start the search.
	int		scope;		//!< LDAP_SCOPE_* value for the search.
	char const	*filter;	//!< Search filter that selects the entries to touch.
	char const	*attr;		//!< Attribute to replace with the current values of the attribute.
	bool		dry_run;	//!< Print the entries that sync_touch would touch, without modifying the entries.
	int		verbose;	//!< 1 prints each entry.  2 or more also prints libldap debug output.
} sync_touch_conf_t;

static NEVER_RETURNS void usage(int status)
{
	FILE *fp = status ? stderr : stdout;

	fprintf(fp, "Usage: sync_touch [options] <attribute> [<filter>]\n");
	fprintf(fp, "Replace <attribute> with the current values of <attribute> in every entry\n");
	fprintf(fp, "matching <filter>, so that LDAP sync clients see the entries as changed.\n");
	fprintf(fp, "<filter> defaults to (objectClass=*).\n\n");
	fprintf(fp, "  -H <uri>          LDAP server URI (default ldap://localhost).\n");
	fprintf(fp, "  -Z                Use StartTLS.\n");
	fprintf(fp, "  -D <dn>           DN to bind as (default anonymous).\n");
	fprintf(fp, "  -w <password>     Password to bind with.\n");
	fprintf(fp, "  -y <file>         Read the password from the first line of <file>.\n");
	fprintf(fp, "  -b <dn>           Search base (required).\n");
	fprintf(fp, "  -s <scope>        base, one, or sub (default sub).\n");
	fprintf(fp, "  -n                Dry run.  List the entries that sync_touch would touch.\n");
	fprintf(fp, "  -v                Print each entry.  Use -vv to also print libldap debug output.\n");
	fprintf(fp, "  -h                Print this help.\n");

	exit(status);
}

/** Read the bind password from the first line of a file
 *
 * @param[in] path	of the file.
 * @return the password, or NULL on error.  The caller must free() the password.
 */
static char *password_from_file(char const *path)
{
	FILE	*fp;
	char	buff[1024];
	size_t	len;

	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "sync_touch: Failed opening %s\n", path);
		return NULL;
	}

	if (!fgets(buff, sizeof(buff), fp)) {
		fprintf(stderr, "sync_touch: Failed reading %s\n", path);
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	len = strlen(buff);
	while ((len > 0) && ((buff[len - 1] == '\n') || (buff[len - 1] == '\r'))) {
		buff[--len] = '\0';
	}

	return strdup(buff);
}

/** Touch one entry by replacing an attribute with the current values of the attribute
 *
 * @param[in] ld	connection to the directory.
 * @param[in] conf	search and touch options.
 * @param[in] entry	from the search.
 * @return
 *	- 1 if the entry was touched.
 *	- 0 if the entry was skipped, because the entry does not have the attribute.
 *	- -1 on error.
 */
static int touch_entry(LDAP *ld, sync_touch_conf_t const *conf, LDAPMessage *entry)
{
	char		*dn;
	struct berval	**values;
	LDAPMod		mod;
	LDAPMod		*mods[2];
	int		ret;

	dn = ldap_get_dn(ld, entry);
	if (!dn) {
		fprintf(stderr, "sync_touch: Failed getting DN of entry\n");
		return -1;
	}

	values = ldap_get_values_len(ld, entry, conf->attr);
	if (!values) {
		if (conf->verbose) printf("skipped %s (no %s)\n", dn, conf->attr);
		ldap_memfree(dn);
		return 0;
	}

	if (conf->dry_run) {
		printf("would touch %s\n", dn);
		ldap_value_free_len(values);
		ldap_memfree(dn);
		return 1;
	}

	mod = (LDAPMod) {
		.mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES,
		.mod_type = UNCONST(char *, conf->attr),
		.mod_bvalues = values
	};
	mods[0] = &mod;
	mods[1] = NULL;

	ret = ldap_modify_ext_s(ld, dn, mods, NULL, NULL);
	ldap_value_free_len(values);

	if (ret != LDAP_SUCCESS) {
		fprintf(stderr, "sync_touch: Failed touching %s: %s\n", dn, ldap_err2string(ret));
		ldap_memfree(dn);
		return -1;
	}

	if (conf->verbose) printf("touched %s\n", dn);
	ldap_memfree(dn);

	return 1;
}

int main(int argc, char **argv)
{
	sync_touch_conf_t	conf = {
		.uri = "ldap://localhost",
		.scope = LDAP_SCOPE_SUBTREE,
		.filter = "(objectClass=*)"
	};
	char			*pw_from_file = NULL;
	char			*attrs[2];
	LDAP			*ld = NULL;
	LDAPMessage		*result = NULL, *entry;
	struct berval		cred;
	int			c, ret, version = LDAP_VERSION3;
	int			touched = 0, skipped = 0, failed = 0;
	int			status = EXIT_FAILURE;

	while ((c = getopt(argc, argv, "b:D:hH:ns:vw:y:Z")) != -1) switch (c) {
	case 'b':
		conf.base_dn = optarg;
		break;

	case 'D':
		conf.bind_dn = optarg;
		break;

	case 'h':
		usage(EXIT_SUCCESS);

	case 'H':
		conf.uri = optarg;
		break;

	case 'n':
		conf.dry_run = true;
		break;

	case 's':
		if (strcmp(optarg, "base") == 0) {
			conf.scope = LDAP_SCOPE_BASE;
		} else if (strcmp(optarg, "one") == 0) {
			conf.scope = LDAP_SCOPE_ONELEVEL;
		} else if (strcmp(optarg, "sub") == 0) {
			conf.scope = LDAP_SCOPE_SUBTREE;
		} else {
			fprintf(stderr, "sync_touch: Invalid scope \"%s\"\n", optarg);
			usage(EXIT_FAILURE);
		}
		break;

	case 'v':
		conf.verbose++;
		break;

	case 'w':
		conf.bind_pw = optarg;
		break;

	case 'y':
		free(pw_from_file);
		pw_from_file = password_from_file(optarg);
		if (!pw_from_file) exit(EXIT_FAILURE);
		conf.bind_pw = pw_from_file;
		break;

	case 'Z':
		conf.start_tls = true;
		break;

	default:
		usage(EXIT_FAILURE);
	}
	argc -= optind;
	argv += optind;

	if ((argc < 1) || (argc > 2)) usage(EXIT_FAILURE);
	conf.attr = argv[0];
	if (argc == 2) conf.filter = argv[1];

	if (!conf.base_dn) {
		fprintf(stderr, "sync_touch: A search base (-b) is required\n");
		usage(EXIT_FAILURE);
	}

	if (conf.verbose > 1) {
		int debug = -1;

		ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
	}

	ret = ldap_initialize(&ld, conf.uri);
	if (ret != LDAP_SUCCESS) {
		fprintf(stderr, "sync_touch: Failed initialising connection to %s: %s\n",
			conf.uri, ldap_err2string(ret));
		goto finish;
	}
	ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

	if (conf.start_tls) {
		ret = ldap_start_tls_s(ld, NULL, NULL);
		if (ret != LDAP_SUCCESS) {
			fprintf(stderr, "sync_touch: StartTLS failed: %s\n", ldap_err2string(ret));
			goto finish;
		}
	}

	cred = (struct berval) {
		.bv_val = UNCONST(char *, conf.bind_pw),
		.bv_len = conf.bind_pw ? strlen(conf.bind_pw) : 0
	};
	ret = ldap_sasl_bind_s(ld, conf.bind_dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
	if (ret != LDAP_SUCCESS) {
		fprintf(stderr, "sync_touch: Bind failed: %s\n", ldap_err2string(ret));
		goto finish;
	}

	/*
	 *	Only fetch the attribute we replace.
	 */
	attrs[0] = UNCONST(char *, conf.attr);
	attrs[1] = NULL;

	ret = ldap_search_ext_s(ld, conf.base_dn, conf.scope, conf.filter, attrs, 0,
				NULL, NULL, NULL, LDAP_NO_LIMIT, &result);
	if ((ret != LDAP_SUCCESS) && (ret != LDAP_SIZELIMIT_EXCEEDED)) {
		fprintf(stderr, "sync_touch: Search failed: %s\n", ldap_err2string(ret));
		goto finish;
	}
	if (ret == LDAP_SIZELIMIT_EXCEEDED) {
		fprintf(stderr, "sync_touch: Server size limit reached, not all matching entries will be touched\n");
	}

	for (entry = ldap_first_entry(ld, result); entry; entry = ldap_next_entry(ld, entry)) {
		switch (touch_entry(ld, &conf, entry)) {
		case 1:
			touched++;
			break;

		case 0:
			skipped++;
			break;

		default:
			failed++;
			break;
		}
	}

	printf("%s %i, skipped %i, failed %i\n", conf.dry_run ? "would touch" : "touched", touched, skipped, failed);

	/*
	 *	Matching nothing is a failure, as the caller wanted
	 *	something to be re-synced.
	 */
	if ((failed == 0) && (touched > 0)) status = EXIT_SUCCESS;

finish:
	if (result) ldap_msgfree(result);
	if (ld) ldap_unbind_ext_s(ld, NULL, NULL);
	free(pw_from_file);

	return status;
}
