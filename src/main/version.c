/*
 * version.c	Print version number and exit.
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 1999-2019  The FreeRADIUS server project
 * Copyright 2012  Alan DeKok <aland@ox.org>
 * Copyright 2000  Chris Parker <cparker@starnetusa.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

static uint64_t	libmagic = RADIUSD_MAGIC_NUMBER;
char const	*radiusd_version_short = RADIUSD_VERSION_STRING;

#ifdef HAVE_OPENSSL_CRYPTO_H
#  include <openssl/crypto.h>
#  include <openssl/opensslv.h>

static long ssl_built = OPENSSL_VERSION_NUMBER;

/** Check built and linked versions of OpenSSL match
 *
 * OpenSSL version number consists of:
 * MNNFFPPS: major minor fix patch status
 *
 * Where status >= 0 && < 10 means beta, and status 10 means release.
 *
 *	https://wiki.openssl.org/index.php/Versioning
 *
 * Startup check for whether the linked version of OpenSSL matches the
 * version the server was built against.
 *
 * @return 0 if ok, else -1
 */
int ssl_check_consistency(void)
{
	long ssl_linked;

	ssl_linked = SSLeay();

	/*
	 *	Major mismatch, that's bad.
	 */
	if ((ssl_linked & 0xff000000) != (ssl_built & 0xff000000)) goto mismatch;

	/*
	 *	For OpenSSL 3, the minor versions are API/ABI compatible.
	 *
	 *	https://openssl-library.org/policies/releasestrat/index.html
	 */
	if ((ssl_linked & 0xff000000) >= 0x30000000) return 0;

	/*
	 *	For other versions of OpenSSL, the minor versions have
	 *	to match, too.
	 */
	if ((ssl_linked & 0xfff00000) != (ssl_built & 0xfff00000)) goto mismatch;

	/*
	 *	1.1.0 and later export all of the APIs we need, so we
	 *	don't care about mismatches in fix / patch / status
	 *	fields.  If the major && minor fields match, that's
	 *	good enough.
	 */
	if ((ssl_linked & 0xfff00000) >= 0x10100000) return 0;

	/*
	 *	Before 1.1.0, we need all kinds of stupid checks to
	 *	see if it might work.
	 */

	/*
	 *	Status mismatch always triggers error.
	 */
	if ((ssl_linked & 0x0000000f) != (ssl_built & 0x0000000f)) {
	mismatch:
		ERROR("libssl version mismatch.  built: %lx linked: %lx",
		      (unsigned long) ssl_built,
		      (unsigned long) ssl_linked);

		return -1;
	}

	/*
	 *	Use the OpenSSH approach and relax fix checks after version
	 *	1.0.0 and only allow moving backwards within a patch
	 *	series.
	 */
	if (ssl_built & 0xf0000000) {
		if ((ssl_built & 0xfffff000) != (ssl_linked & 0xfffff000) ||
		    (ssl_built & 0x00000ff0) > (ssl_linked & 0x00000ff0)) goto mismatch;
	/*
	 *	Before 1.0.0 we require the same major minor and fix version
	 *	and ignore the patch number.
	 */
	} else if ((ssl_built & 0xfffff000) != (ssl_linked & 0xfffff000)) goto mismatch;

	return 0;
}

/** Convert a version number to a text string
 *
 * @note Not thread safe.
 *
 * @param v version to convert.
 * @return pointer to a static buffer containing the version string.
 */
char const *ssl_version_by_num(uint32_t v)
{
	/* 2 (%s) + 1 (.) + 2 (%i) + 1 (.) + 2 (%i) + 1 (c) + 8 (%s) + \0 */
	static char buffer[18];
	char *p = buffer;

	p += sprintf(p, "%u.%u.%u",
		     (0xf0000000 & v) >> 28,
		     (0x0ff00000 & v) >> 20,
		     (0x000ff000 & v) >> 12);

	if ((0x00000ff0 & v) >> 4) {
		*p++ =  (char) (0x60 + ((0x00000ff0 & v) >> 4));
	}

	*p++ = ' ';

	/*
	 *	Development (0)
	 */
	if ((0x0000000f & v) == 0) {
		strcpy(p, "dev");
	/*
	 *	Beta (1-14)
	 */
	} else if ((0x0000000f & v) <= 14) {
		sprintf(p, "beta %u", 0x0000000f & v);
	} else {
		strcpy(p, "release");
	}

	return buffer;
}

/** Return the linked SSL version number as a string
 *
 * @return pointer to a static buffer containing the version string.
 */
char const *ssl_version_num(void)
{
	long ssl_linked;

	ssl_linked = SSLeay();
	return ssl_version_by_num((uint32_t)ssl_linked);
}

/** Convert two openssl version numbers into a range string
 *
 * @note Not thread safe.
 *
 * @param low version to convert.
 * @param high version to convert.
 * @return pointer to a static buffer containing the version range string.
 */
char const *ssl_version_range(uint32_t low, uint32_t high)
{
	/* 12 (version) + 3 ( - ) + 12 (version) */
	static char buffer[28];
	char *p = buffer;

	p += strlcpy(p, ssl_version_by_num(low), sizeof(buffer));
	p += strlcpy(p, " - ", sizeof(buffer) - (p - buffer));
	strlcpy(p, ssl_version_by_num(high), sizeof(buffer) - (p - buffer));

	return buffer;
}

/** Print the current linked version of Openssl
 *
 * Print the currently linked version of the OpenSSL library.
 *
 * @note Not thread safe.
 * @return pointer to a static buffer containing libssl version information.
 */
char const *ssl_version(void)
{
	static char buffer[256];

	uint32_t v = SSLeay();

	snprintf(buffer, sizeof(buffer), "%s 0x%.8x (%s)",
		 SSLeay_version(SSLEAY_VERSION),		/* Not all builds include a useful version number */
		 v,
		 ssl_version_by_num(v));

	return buffer;
}
#  else
int ssl_check_consistency(void) {
	return 0;
}

char const *ssl_version_num(void)
{
	return "not linked";
}

char const *ssl_version(void)
{
	return "not linked";
}
#endif /* ifdef HAVE_OPENSSL_CRYPTO_H */

/** Check if the application linking to the library has the correct magic number
 *
 * @param magic number as defined by RADIUSD_MAGIC_NUMBER
 * @returns 0 on success, -1 on prefix mismatch, -2 on version mismatch -3 on commit mismatch.
 */
int rad_check_lib_magic(uint64_t magic)
{
	if (MAGIC_PREFIX(magic) != MAGIC_PREFIX(libmagic)) {
		ERROR("Application and libfreeradius-server magic number (prefix) mismatch."
		      "  application: %x library: %x",
		      MAGIC_PREFIX(magic), MAGIC_PREFIX(libmagic));
		return -1;
	}

	if (MAGIC_VERSION(magic) != MAGIC_VERSION(libmagic)) {
		ERROR("Application and libfreeradius-server magic number (version) mismatch."
		      "  application: %lx library: %lx",
		      (unsigned long) MAGIC_VERSION(magic), (unsigned long) MAGIC_VERSION(libmagic));
		return -2;
	}

	if (MAGIC_COMMIT(magic) != MAGIC_COMMIT(libmagic)) {
		ERROR("Application and libfreeradius-server magic number (commit) mismatch."
		      "  application: %lx library: %lx",
		      (unsigned long) MAGIC_COMMIT(magic), (unsigned long) MAGIC_COMMIT(libmagic));
		return -3;
	}

	return 0;
}

/** Add a feature flag to the main configuration
 *
 * Add a feature flag (yes/no) to the 'feature' subsection
 * off the main config.
 *
 * This allows the user to create configurations that work with
 * across multiple environments.
 *
 * @param cs to add feature pair to.
 * @param name of feature.
 * @param enabled Whether the feature is present/enabled.
 * @return 0 on success else -1.
 */
int version_add_feature(CONF_SECTION *cs, char const *name, bool enabled)
{
	if (!cs) return -1;

	if (!cf_pair_find(cs, name)) {
		CONF_PAIR *cp;

		cp = cf_pair_alloc(cs, name, enabled ? "yes" : "no",
				   T_OP_SET, T_BARE_WORD, T_BARE_WORD);
		if (!cp) return -1;
		cf_pair_add(cs, cp);
	}

	return 0;
}

/** Add a library/server version pair to the main configuration
 *
 * Add a version number to the 'version' subsection off the main
 * config.
 *
 * Because of the optimisations in the configuration parser, these
 * may be checked using regular expressions without a performance
 * penalty.
 *
 * The version pairs are there primarily to work around defects
 * in libraries or the server.
 *
 * @param cs to add feature pair to.
 * @param name of library or feature.
 * @param version Humanly readable version text.
 * @return 0 on success else -1.
 */
int version_add_number(CONF_SECTION *cs, char const *name, char const *version)
{
	CONF_PAIR *old;

	if (!cs) return -1;

	old = cf_pair_find(cs, name);
	if (!old) {
		CONF_PAIR *cp;

		cp = cf_pair_alloc(cs, name, version, T_OP_SET, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
		if (!cp) return -1;

		cf_pair_add(cs, cp);
	} else {
		WARN("Replacing user version.%s (%s) with %s", name, cf_pair_value(old), version);

		cf_pair_replace(cs, old, version);
	}

	return 0;
}


/** Initialise core feature flags
 *
 * @param cs Where to add the CONF_PAIRS, if null pairs will be added
 *	to the 'feature' section of the main config.
 */
void version_init_features(CONF_SECTION *cs)
{
	version_add_feature(cs, "accounting",
#ifdef WITH_ACCOUNTING
				true
#else
				false
#endif
				);

	version_add_feature(cs, "authentication", true);

	version_add_feature(cs, "ascend-binary-attributes",
#ifdef WITH_ASCEND_BINARY
				true
#else
				false
#endif
				);

	version_add_feature(cs, "coa",
#ifdef WITH_COA
				true
#else
				false
#endif
				);


	version_add_feature(cs, "recv-coa-from-home-server",
#ifdef WITH_COA_TUNNEL
			        true
#else
				false
#endif
				);

	version_add_feature(cs, "control-socket",
#ifdef WITH_COMMAND_SOCKET
				true
#else
				false
#endif
				);


	version_add_feature(cs, "detail",
#ifdef WITH_DETAIL
				true
#else
				false
#endif
				);

	version_add_feature(cs, "dhcp",
#ifdef WITH_DHCP
				true
#else
				false
#endif
				);

	version_add_feature(cs, "dynamic-clients",
#ifdef WITH_DYNAMIC_CLIENTS
				true
#else
				false
#endif
				);

	version_add_feature(cs, "osfc2",
#ifdef OSFC2
				true
#else
				false
#endif
				);

	version_add_feature(cs, "proxy",
#ifdef WITH_PROXY
				true
#else
				false
#endif
				);

	version_add_feature(cs, "regex-pcre",
#ifdef HAVE_PCRE
				true
#else
				false
#endif
				);

	version_add_feature(cs, "regex-pcre2",
#ifdef HAVE_PCRE2
				true
#else
				false
#endif
				);

#if !defined(HAVE_PCRE) && !defined(HAVE_PCRE2) && defined(HAVE_REGEX)
	version_add_feature(cs, "regex-posix", true);
	version_add_feature(cs, "regex-posix-extended",
#  ifdef HAVE_REG_EXTENDED
				true
#  else
				false
#  endif
				);
#else
	version_add_feature(cs, "regex-posix", false);
	version_add_feature(cs, "regex-posix-extended", false);
#endif

	version_add_feature(cs, "session-management",
#ifdef WITH_SESSION_MGMT
				true
#else
				false
#endif
				);

	version_add_feature(cs, "stats",
#ifdef WITH_STATS
				true
#else
				false
#endif
				);

	version_add_feature(cs, "systemd",
#ifdef HAVE_SYSTEMD
				true
#else
				false
#endif
				);

	version_add_feature(cs, "tcp",
#ifdef WITH_TCP
				true
#else
				false
#endif
				);

	version_add_feature(cs, "threads",
#ifdef WITH_THREADS
				true
#else
				false
#endif
				);

	version_add_feature(cs, "tls",
#ifdef WITH_TLS
				true
#else
				false
#endif
				);

	version_add_feature(cs, "unlang",
#ifdef WITH_UNLANG
				true
#else
				false
#endif
				);

	version_add_feature(cs, "vmps",
#ifdef WITH_VMPS
				true
#else
				false
#endif
				);

	version_add_feature(cs, "developer",
#ifndef NDEBUG
				true
#else
				false
#endif
				);
}

/** Initialise core version flags
 *
 * @param cs Where to add the CONF_PAIRS, if null pairs will be added
 *	to the 'version' section of the main config.
 */
void version_init_numbers(CONF_SECTION *cs)
{
	char buffer[128];

	version_add_number(cs, "freeradius-server", radiusd_version_short);

	snprintf(buffer, sizeof(buffer), "%i.%i.*", talloc_version_major(), talloc_version_minor());
	version_add_number(cs, "talloc", buffer);

#ifdef OPENSSL_FULL_VERSION_STR
	version_add_number(cs, "ssl", OPENSSL_FULL_VERSION_STR);
#else
	version_add_number(cs, "ssl", ssl_version_num());
#endif

#if defined(HAVE_REGEX) && defined(HAVE_PCRE)
	version_add_number(cs, "pcre", pcre_version());
#endif
}

static char const *spaces = "                                    ";	/* 40 */

/*
 *	Display the revision number for this program
 */
void version_print(void)
{
	CONF_SECTION *features, *versions;
	CONF_ITEM *ci;
	CONF_PAIR *cp;

	if (DEBUG_ENABLED3) {
		int max = 0, len;

		MEM(features = cf_section_alloc(NULL, "feature", NULL));
		version_init_features(features);

		MEM(versions = cf_section_alloc(NULL, "version", NULL));
		version_init_numbers(versions);

		DEBUG2("Server was built with: ");

		for (ci = cf_item_find_next(features, NULL);
		     ci;
		     ci = cf_item_find_next(features, ci)) {
			len = talloc_array_length(cf_pair_attr(cf_item_to_pair(ci)));
			if (max < len) max = len;
		}

		for (ci = cf_item_find_next(versions, NULL);
		     ci;
		     ci = cf_item_find_next(versions, ci)) {
			len = talloc_array_length(cf_pair_attr(cf_item_to_pair(ci)));
			if (max < len) max = len;
		}


		for (ci = cf_item_find_next(features, NULL);
		     ci;
		     ci = cf_item_find_next(features, ci)) {
		     	char const *attr;

			cp = cf_item_to_pair(ci);
			attr = cf_pair_attr(cp);

			DEBUG2("  %s%.*s : %s", attr,
			       (int)(max - talloc_array_length(attr)), spaces,  cf_pair_value(cp));
		}

		talloc_free(features);

		DEBUG2("Server core libs:");

		for (ci = cf_item_find_next(versions, NULL);
		     ci;
		     ci = cf_item_find_next(versions, ci)) {
		     	char const *attr;

			cp = cf_item_to_pair(ci);
			attr = cf_pair_attr(cp);

			DEBUG2("  %s%.*s : %s", attr,
			       (int)(max - talloc_array_length(attr)), spaces,  cf_pair_value(cp));
		}

		talloc_free(versions);

		DEBUG2("Endianness:");
#if defined(FR_LITTLE_ENDIAN)
		DEBUG2("  little");
#elif defined(FR_BIG_ENDIAN)
		DEBUG2("  big");
#else
		DEBUG2("  unknown");
#endif

		DEBUG2("Compilation flags:");
#ifdef BUILT_WITH_CPPFLAGS
		DEBUG2("  cppflags : " BUILT_WITH_CPPFLAGS);
#endif
#ifdef BUILT_WITH_CFLAGS
		DEBUG2("  cflags   : " BUILT_WITH_CFLAGS);
#endif
#ifdef BUILT_WITH_LDFLAGS
		DEBUG2("  ldflags  : " BUILT_WITH_LDFLAGS);
#endif
#ifdef BUILT_WITH_LIBS
		DEBUG2("  libs     : " BUILT_WITH_LIBS);
#endif
		DEBUG2("  ");
	}
	INFO("FreeRADIUS Version " RADIUSD_VERSION_STRING);
	INFO("Copyright (C) 1999-2025 The FreeRADIUS server project and contributors");
	INFO("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A");
	INFO("PARTICULAR PURPOSE");
	INFO("You may redistribute copies of FreeRADIUS under the terms of the");
	INFO("GNU General Public License");
	INFO("For more information about these matters, see the file named COPYRIGHT");
	INFO("");
	INFO("FreeRADIUS is developed, maintained, and supported by InkBridge Networks.");
	INFO("For commercial support, please email sales@inkbridgenetworks.com");
	INFO("https://inkbridgenetworks.com/");

	fflush(NULL);
}

