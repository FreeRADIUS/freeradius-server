/*
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
 */

/**
 * $Id$
 * @file src/lib/server/dependency.c
 * @brief Check version numbers of dependencies.
 *
 * @copyright 1999-2014 The FreeRADIUS server project
 * @copyright 2012 Alan DeKok (aland@freeradius.org)
 * @copyright 2000 Chris Parker (cparker@starnetusa.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

static uint64_t	libmagic = RADIUSD_MAGIC_NUMBER;
char const	*radiusd_version_short = RADIUSD_VERSION_STRING;

static CONF_SECTION *default_feature_cs;		//!< Default configuration section to add features to.
static CONF_SECTION *default_version_cs;		//!< Default configuration section to add features to.

#ifdef HAVE_OPENSSL_CRYPTO_H
#  include <openssl/crypto.h>
#  include <openssl/opensslv.h>
#  include <openssl/engine.h>

#ifdef HAVE_VALGRIND_H
#  include <valgrind.h>
#endif

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
 * @return
 *	- 0 if ok.
 *	- -1 if not ok.
 */
int ssl_check_consistency(void)
{
	long ssl_linked;

	ssl_linked = SSLeay();

	/*
	 *	Major and minor versions mismatch, that's bad.
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
	/* 18 (version) + 3 ( - ) + 18 (version) */
	static char buffer[40];
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

char const *ssl_version()
{
	return "not linked";
}
#endif /* ifdef HAVE_OPENSSL_CRYPTO_H */

/** Check if the application linking to the library has the correct magic number
 *
 * @param magic number as defined by RADIUSD_MAGIC_NUMBER
 * @returns
 *	- 0 on success.
 *	- -1 on prefix mismatch.
 *	- -2 on version mismatch.
 *	- -3 on commit mismatch.
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
 * @param[in] cs		to add feature pair to. May be NULL
 *				in which case the cs passed to
 *				dependency_feature_init() is used.
 * @param[in] name		of feature.
 * @param[in] enabled		Whether the feature is present/enabled.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int dependency_feature_add(CONF_SECTION *cs, char const *name, bool enabled)
{
	if (!cs) cs = default_feature_cs;
	if (!fr_cond_assert_msg(cs, "dependency_features_init() must be called before calling %s", __FUNCTION__)) {
		return -1;
	}

	if (!cf_pair_find(cs, name)) {
		CONF_PAIR *cp;

		cp = cf_pair_alloc(cs, name, enabled ? "yes" : "no",
				   T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
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
 * @param[in] cs		to add feature pair to. May be NULL
 *				in which case the cs passed to
 *				dependency_feature_init() is used.
 * @param[in] name		of library or feature.
 * @param[in] version Humanly	readable version text.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int dependency_version_number_add(CONF_SECTION *cs, char const *name, char const *version)
{
	CONF_PAIR *old;

	if (!cs) cs = default_version_cs;
	if (!fr_cond_assert_msg(cs, "dependency_version_numbers_init() must be called before calling %s", __FUNCTION__)) {
		return -1;
	}

	old = cf_pair_find(cs, name);
	if (!old) {
		CONF_PAIR *cp;

		cp = cf_pair_alloc(cs, name, version, T_OP_EQ, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
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
void dependency_features_init(CONF_SECTION *cs)
{
	default_feature_cs = cs;

	dependency_feature_add(cs, "accounting",
#ifdef WITH_ACCOUNTING
				true
#else
				false
#endif
				);

	dependency_feature_add(cs, "authentication", true);

	dependency_feature_add(cs, "coa",
#ifdef WITH_COA
				true
#else
				false
#endif
				);

	dependency_feature_add(cs, "proxy",
#ifdef WITH_PROXY
				true
#else
				false
#endif
				);

	dependency_feature_add(cs, "regex-pcre",
#ifdef HAVE_REGEX_PCRE
				true
#else
				false
#endif
				);

	dependency_feature_add(cs, "regex-pcre2",
#ifdef HAVE_REGEX_PCRE2
				true
#else
				false
#endif
				);

#ifdef HAVE_REGEX_POSIX
	dependency_feature_add(cs, "regex-posix", true);
	dependency_feature_add(cs, "regex-posix-extended",
#  ifdef HAVE_REG_EXTENDED
				true
#  else
				false
#  endif
				);
#else
	dependency_feature_add(cs, "regex-posix", false);
	dependency_feature_add(cs, "regex-posix-extended", false);
#endif

#if defined(HAVE_REGNEXEC) || defined(HAVE_REGEX_PCRE) || defined(HAVE_REGEX_PCRE2)
	dependency_feature_add(cs, "regex-binsafe", true);
#else
	dependency_feature_add(cs, "regex-binsafe", false);
#endif

	dependency_feature_add(cs, "stats",
#ifdef WITH_STATS
				true
#else
				false
#endif
				);

	dependency_feature_add(cs, "systemd",
#ifdef HAVE_SYSTEMD
				true
#else
				false
#endif
				);

	dependency_feature_add(cs, "tls",
#ifdef WITH_TLS
				true
#else
				false
#endif
				);


	dependency_feature_add(cs, "tls-key-agility",
#ifdef WITH_TLS
				true
#else
				false
#endif
				);

	dependency_feature_add(cs, "socket-timestamps",
#ifdef SO_TIMESTAMP
				true
#else
				false
#endif
				);

	dependency_feature_add(cs, "developer",
#ifndef NDEBUG
				true
#else
				false
#endif
				);

	dependency_feature_add(cs, "address-sanitizer",
#ifdef __SANITIZE_ADDRESS__
				true
#else
				false
#endif
				);

#ifdef HAVE_SANITIZER_COMMON_INTERFACE_DEFS_H
	/*
	 *	Are we running under Leak Sanitizer
	 */
	dependency_feature_add(cs, "runtime-lsan", (fr_get_lsan_state() == 1));
#endif

#ifdef HAVE_VALGRIND_H
	/*
	 *	Are we running under valgrind
	 */
	dependency_feature_add(cs, "runtime-valgrind", RUNNING_ON_VALGRIND);
#endif

	/*
	 *	Are we running under a debugger
	 */
	dependency_feature_add(cs, "runtime-debugger", (fr_get_debug_state() == 1));
}

/** Initialise core version flags
 *
 * @param cs Where to add the CONF_PAIRS, if null pairs will be added
 *	to the 'version' section of the main config.
 */
void dependency_version_numbers_init(CONF_SECTION *cs)
{
	char buffer[128];

	default_version_cs = cs;

	dependency_version_number_add(cs, "freeradius-server", radiusd_version_short);

	snprintf(buffer, sizeof(buffer), "%i.%i.*", talloc_version_major(), talloc_version_minor());
	dependency_version_number_add(cs, "talloc", buffer);

	dependency_version_number_add(cs, "ssl", ssl_version_num());

#ifdef HAVE_REGEX
#  ifdef HAVE_REGEX_PCRE2
	snprintf(buffer, sizeof(buffer), "%i.%i (%s) - retrieved at build time", PCRE2_MAJOR, PCRE2_MINOR, STRINGIFY(PCRE2_DATE));
	dependency_version_number_add(cs, "pcre2", buffer);
#  elif defined(HAVE_REGEX_PCRE)
	dependency_version_number_add(cs, "pcre", pcre_version());
#  endif
#endif
}

static char const *spaces = "                                    ";	/* 40 */

/*
 *	Display the revision number for this program
 */
void dependency_version_print(void)
{
	CONF_SECTION *features, *versions;
	CONF_ITEM *ci;
	CONF_PAIR *cp;

	if (DEBUG_ENABLED3) {
#ifdef WITH_TLS
		ENGINE *engine;
		char const *engine_id;
#endif
		int max = 0, len;

		MEM(features = cf_section_alloc(NULL, NULL, "feature", NULL));
		dependency_features_init(features);

		MEM(versions = cf_section_alloc(NULL, NULL, "version", NULL));
		dependency_version_numbers_init(versions);

		DEBUG2("Server was built with:");

		for (ci = cf_item_next(features, NULL);
		     ci;
		     ci = cf_item_next(features, ci)) {
			len = talloc_array_length(cf_pair_attr(cf_item_to_pair(ci)));
			if (max < len) max = len;
		}

		for (ci = cf_item_next(versions, NULL);
		     ci;
		     ci = cf_item_next(versions, ci)) {
			len = talloc_array_length(cf_pair_attr(cf_item_to_pair(ci)));
			if (max < len) max = len;
		}

#ifdef WITH_TLS
		for (engine = ENGINE_get_first();
		     engine;
		     engine = ENGINE_get_next(engine)) {
			len = strlen(ENGINE_get_id(engine) + 1);
			if (max < len) max = len;
		}
#endif

		for (ci = cf_item_next(features, NULL);
		     ci;
		     ci = cf_item_next(features, ci)) {
		     	char const *attr;

			cp = cf_item_to_pair(ci);
			attr = cf_pair_attr(cp);

			DEBUG2("  %s%.*s : %s", attr,
			       (int)(max - talloc_array_length(attr)), spaces, cf_pair_value(cp));
		}

		DEBUG2("Server core libs:");

		for (ci = cf_item_next(versions, NULL);
		     ci;
		     ci = cf_item_next(versions, ci)) {
		     	char const *attr;

			cp = cf_item_to_pair(ci);
			attr = cf_pair_attr(cp);

			DEBUG2("  %s%.*s : %s", attr,
			       (int)(max - talloc_array_length(attr)), spaces, cf_pair_value(cp));
		}

		talloc_free(features);
		talloc_free(versions);

#ifdef WITH_TLS
		DEBUG3("OpenSSL engines:");
		for (engine = ENGINE_get_first();
		     engine;
		     engine = ENGINE_get_next(engine)) {
			engine_id = ENGINE_get_id(engine);

			DEBUG3("  %s%.*s : %s", engine_id, (int)(max - (strlen(engine_id) + 1)), spaces,
			       ENGINE_get_name(engine));
		}
#endif

		DEBUG2("Endianness:");
#ifdef WORDS_BIGENDIAN
		DEBUG2("  big");
#else
		DEBUG2("  little");
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
	INFO("Copyright 1999-2020 The FreeRADIUS server project and contributors");
	INFO("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A");
	INFO("PARTICULAR PURPOSE");
	INFO("You may redistribute copies of FreeRADIUS under the terms of the");
	INFO("GNU General Public License");
	INFO("For more information about these matters, see the file named COPYRIGHT");

	fflush(NULL);
}

