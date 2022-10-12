/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#if !defined(__MINGW32__)
#  include <sys/wait.h>
#endif

#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>

#ifndef FALL_THROUGH
/** clang 10 doesn't recognised the FALL-THROUGH comment anymore
 */
#  if (defined(__clang__) && (__clang_major__ >= 10)) || (defined(__GNUC__) && __GNUC__ >= 7)
#    define FALL_THROUGH		__attribute__((fallthrough))
#  else
#    define FALL_THROUGH		((void)0)
#  endif
#endif

#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)

#define UNCONST(_type, _ptr)		((_type)((uintptr_t)(_ptr)))

/** The set of executables used
 *
 */
typedef struct {
	char const			*cc;		//!< C compiler.
	char const			*cxx;		//!< C++ compiler.
	char const			*link_c;	//!< C linker.
	char const			*link_cxx;	//!< C++ linker.
	char const			*ranlib;	//!< Archiver/indexer.
} toolset_t;

#ifndef BUILD_CC
#  define BUILD_CC 			"clang"
#endif

#ifndef HOST_CXX
#  define HOST_CXX 			"g++"
#endif

#ifndef HOST_LINK_C
#  define HOST_LINK_C 			"clang"
#endif

#ifndef HOST_LINK_CXX
#  define HOST_LINK_CXX			"g++"
#endif

#ifndef BUILD_RANLIB
#  if !defined(__EMX__) && !defined(_OSD_POSIX)
#    define BUILD_RANLIB			"ranlib"
#  endif
#endif

#ifndef TARGET_CC
#  define TARGET_CC			BUILD_CC
#endif

#ifndef TARGET_CXX
#  define TARGET_CXX			HOST_CXX
#endif

#ifndef TARGET_LINK_C
#  define TARGET_LINK_C			HOST_LINK_C
#endif

#ifndef TARGET_LINK_CXX
#  define TARGET_LINK_CXX		HOST_LINK_CXX
#endif

#ifndef TARGET_RANLIB
#  define TARGET_RANLIB		        "ranlib"
#endif

static const toolset_t toolset_host = {
	.cc				= BUILD_CC,
	.cxx				= HOST_CXX,
	.link_c				= HOST_LINK_C,
	.link_cxx			= HOST_LINK_CXX,
#ifdef BUILD_RANLIB
	.ranlib				= BUILD_RANLIB
#endif
};

static const toolset_t toolset_target = {
	.cc				= TARGET_CC,
	.cxx				= TARGET_CXX,
	.link_c				= TARGET_LINK_C,
	.link_cxx			= TARGET_LINK_CXX,
#ifdef TARGET_RANLIB
	.ranlib				= TARGET_RANLIB
#endif
};

/** The default active toolset
 *
 */
static const toolset_t *toolset = &toolset_host;

/** A jlibtool build system target
 *
 */
typedef struct {
	char const			*name;		//!< Canonical name for this target.
	char const			*shell_cmd;
	char const			*gen_exports;
	char const			*def2implib_cmd;
	char const			*share_sw;
	bool				use_omf;
	bool				truncate_dll_name;

	char const			*dynamic_lib_ext;
	char const			*static_lib_ext;
	char const			*module_lib_ext;
	char const			*object_ext;
	char const      		*exe_ext;

	char const			*librarian;
	char const			*librarian_opts;

	char const			*pic_flag;
	char const			*rpath;
	char const			*shared_opts;
	char const			*module_opts;
	char const			*linker_flag_prefix;
	bool				linker_flag_no_equals;

	char const			*dynamic_link_opts;
	char const			*dynamic_link_opts_undefined;
	char const			*(*dynamic_link_version_func)(char const *version_info);
	char const			*dynamic_install_name;
	char const			*dynamic_link_no_install;

	bool				has_realpath;
	bool				add_minus_l;

	char const			*ld_run_path;
	char const			*ld_library_path;
	char const			*ld_library_path_local;
} target_t;

static char const *darwin_dynamic_link_function(char const *version_info);

static const target_t target_macos = {
	.name				= "macos",
	.shell_cmd			= "/bin/sh",
	.dynamic_lib_ext		= "dylib",
	.module_lib_ext			= "bundle",
	.static_lib_ext			= "a",
	.object_ext			= "o",
	.librarian			= "ar",
	.librarian_opts			= "cr",
/* man libtool(1) documents ranlib option of -c.  */
	.pic_flag			= "-fPIC -fno-common",
	.shared_opts			= "-dynamiclib",
	.module_opts			= "-bundle -dynamic",
	.dynamic_link_opts		= "-bind_at_load",
	.dynamic_link_opts_undefined	= "-Wl,-w -undefined dynamic_lookup",
	.dynamic_link_version_func	= darwin_dynamic_link_function,
	.dynamic_install_name		= "-install_name",
	.dynamic_link_no_install	= "-dylib_file",
	.has_realpath			= true,
/*-install_name  /Users/jerenk/apache-2.0-cvs/lib/libapr.0.dylib -compatibility_version 1 -current_version 1.0 */
	.ld_library_path		= "DYLD_LIBRARY_PATH",
	.ld_library_path_local		= "DYLD_FALLBACK_LIBRARY_PATH",
};

static const target_t target_linux_and_bsd = {
	.name				= "linux_and_bsd",
	.shell_cmd			= "/bin/sh",
	.dynamic_lib_ext		= "so",
	.module_lib_ext			= "so",
	.static_lib_ext			= "a",
	.object_ext			= "o",
	.librarian			= "ar",
	.librarian_opts			= "cr",
	.pic_flag			= "-fPIC",
	.rpath				= "-rpath",
	.shared_opts			= "-shared",
	.module_opts			= "-shared",
	.linker_flag_prefix		= "-Wl,",
	.dynamic_link_opts		= "-Wl,-export-dynamic",
	.add_minus_l			= true,
	.ld_run_path			= "LD_RUN_PATH",
	.ld_library_path		= "LD_LIBRARY_PATH",
	.ld_library_path_local		= "LD_LIBRARY_PATH"
};

static const target_t target_solaris_gnu = {
	.name				= "solaris_gnu",
	.shell_cmd			= "/bin/sh",
	.dynamic_lib_ext		= "so",
	.module_lib_ext			= "so",
	.static_lib_ext			= "a",
	.object_ext			= "o",
	.librarian			= "ar",
	.librarian_opts			= "cr",
	.pic_flag			= "-fPIC",
	.rpath				= "-rpath",
	.shared_opts			= "-shared",
	.module_opts			= "-shared",
	.linker_flag_prefix		= "-Wl,",
	.dynamic_link_opts		= "-export-dynamic",
	.add_minus_l			= true,
	.ld_run_path			= "LD_RUN_PATH",
	.ld_library_path		= "LD_LIBRARY_PATH",
	.ld_library_path_local		= "LD_LIBRARY_PATH"
};

static const target_t target_solaris = {
	.name				= "solaris",
	.shell_cmd			= "/bin/sh",
	.dynamic_lib_ext		= "so",
	.module_lib_ext			= "so",
	.static_lib_ext			= "a",
	.object_ext			= "o",
	.librarian			= "ar",
	.librarian_opts			= "cr",
	.pic_flag			= "-KPIC",
	.rpath				= "-R",
	.shared_opts			= "-G",
	.module_opts			= "-G",
	.dynamic_link_opts		= "",
	.linker_flag_no_equals		= true,
	.add_minus_l			= true,
	.has_realpath			= true,
	.ld_run_path			= "LD_RUN_PATH",
	.ld_library_path		= "LD_LIBRARY_PATH",
	.ld_library_path_local		= "LD_LIBRARY_PATH"
};

static const target_t target_osd_posix = {
	.name				= "osd_posix",
	.shell_cmd			= "/usr/bin/sh",
	.dynamic_lib_ext		= "so",
	.module_lib_ext			= "so",
	.static_lib_ext			= "a",
	.object_ext			= "o",
	.librarian			= "ar",
	.librarian_opts			= "cr",
	.shared_opts			= "-G",
	.module_opts			= "-G",
	.linker_flag_prefix		= "-Wl,",
};

static const target_t target_sinix_mips = {
	.name				= "sinix_mips",
	.shell_cmd			= "/usr/bin/sh",
	.dynamic_lib_ext		= "so",
	.module_lib_ext			= "so",
	.static_lib_ext			= "a",
	.object_ext			= "o",
	.librarian			= "ar",
	.librarian_opts			= "cr",
	.rpath				= "-Brpath",
	.shared_opts			= "-G",
	.module_opts			= "-G",
	.linker_flag_prefix		= "-Wl,",
	.dynamic_link_opts		= "-Wl,-Blargedynsym",
	.ld_run_path			= "LD_RUN_PATH",
	.ld_library_path		= "LD_LIBRARY_PATH",
	.ld_library_path_local		= "LD_LIBRARY_PATH"
};

static const target_t target_emx_omf = {
	.name				= "emx_omf",
	.shell_cmd			= "sh",
	.gen_exports			= "emxexp",
	.def2implib_cmd			= "emximp",
	.share_sw			= "-Zdll -Zmtd",
	.use_omf			= true,

	.truncate_dll_name		= true,
	.dynamic_lib_ext		= "dll",
	.exe_ext			= ".exe",

	.static_lib_ext			= "lib",
	.object_ext			= "obj",
	.librarian			= "emxomfar",
	.librarian_opts			= "cr"
};

static const target_t target_emx = {
	.name				= "emx",
	.shell_cmd			= "sh",
	.gen_exports			= "emxexp",
	.def2implib_cmd			= "emximp",
	.share_sw			= "-Zdll -Zmtd",
	.truncate_dll_name		= true,
	.dynamic_lib_ext		= "dll",
	.exe_ext			= ".exe",
	.static_lib_ext			= "a",
	.object_ext			= "o",
	.librarian			= "ar",
	.librarian_opts			= "cr"
};

static const target_t target_ming32 = {
	.name				= "ming32",
	.shell_cmd			= "sh",
	.dynamic_lib_ext		= "dll",
	.module_lib_ext			= "dll",
	.static_lib_ext			= "a",
	.object_ext			= "o",
	.librarian			= "ar",
	.librarian_opts			= "cr",
	.linker_flag_prefix		= "-Wl,",
	.shared_opts			= "-shared",
	.module_opts			= "-shared",
	.exe_ext			= ".exe",
};

static const target_t target_emscripten = {
	.name				= "emscripten",
	.shell_cmd			= "/bin/sh",
	.dynamic_lib_ext		= "wasm",
	.module_lib_ext			= "wasm",
	.static_lib_ext			= "a",
	.exe_ext			= ".js",
	.object_ext			= "o",
	.librarian			= "emar",
	.librarian_opts			= "cr",
	.pic_flag			= "-fPIC",
	.shared_opts			= "-shared",
	.module_opts			= "-shared",
	.linker_flag_prefix		= "-Wl,",
	.dynamic_link_opts		= "",
	.add_minus_l			= true,
	.ld_run_path			= "LD_RUN_PATH",
	.ld_library_path		= "LD_LIBRARY_PATH",
	.ld_library_path_local		= "LD_LIBRARY_PATH"
};

/** jlibtool should be compiled in the host environment
 *
 * For the vast majority of cases the host environment and the target environment
 * are the same, but not always.
 *
 * Still, it makes more sense to default to the host target, so use various
 * preprocessor checks to figure out what system type we're building on
 * and set the default target appropriately.
 */

/*
 *	macOS/Darwin
 */
#if defined(__APPLE__)
static const target_t	*target = &target_macos;

/*
 *	Linux and the BSDs
 */
#elif defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
static const target_t	*target = &target_linux_and_bsd;

/*
 *	Solaris with GNUC
 */
#elif defined(__sun) && defined(__GNUC__)
static const target_t	*target = &target_solaris_gnu;

/*
 *	Solaris without GNUC
 */
#elif defined(__sun) && !defined(__GNUC__)
static const target_t	*target = &target_solaris;

/*
 *	OSD POSIX
 */
#elif defined(_OSD_POSIX)
#  define NEED_SNPRINTF
static const target_t	*target = &target_osd_posix;

/*
 *	SINIX (mips)
 */
#elif defined(sinix) && defined(mips) && defined(__SNI_TARG_UNIX)
#  define NEED_SNPRINTF
static const target_t	*target = &target_sinix_mips;

/*
 *	EMX with OMF format
 */
#elif defined(__EMX__) && defined(USE_OMF)
#include <process.h>
static const target_t	*target = &target_emx_omf;

/*
 *	EMX without OMF format
 */
#elif defined(__EMX__)
#include <process.h>
static const target_t	*target = &target_emx;

/*
 *	Ming32
 */
#elif defined(__MINGW32__)
#define MKDIR_NO_UMASK
static const target_t	*target = &target_ming32;

/*
 *	Emscripten (WASM)
 */
#elif defined(__EMSCRIPTEN__)
static const target_t	*target = &target_emscripten;
#else
#  error Unsupported platform: Please add a target for your platform.
#endif

typedef struct {
	char const	*name;
	target_t const	*target;
} target_map_t;

#define IS_TARGET(_name) (target == &target_ ##_name)
#define TARGET(_name, _struct)	{ .name = _name, .target = &target_ ## _struct }

/** Mapping values for --target
 *
 * These allow the users to specify a target system when cross-compiling
 */
static const target_map_t target_map[] = {
	TARGET("bsd",		linux_and_bsd),
	TARGET("emscripten",	emscripten),
	TARGET("emx",		emx),
	TARGET("emx-omf",	emx_omf),
	TARGET("freebsd",	linux_and_bsd),
	TARGET("linux",		linux_and_bsd),
	TARGET("macos",		macos),
	TARGET("darwin",	macos),
	TARGET("ming32",	ming32),
	TARGET("netbsd",	linux_and_bsd),
	TARGET("openbsd",	linux_and_bsd),
	TARGET("osd-posix",	osd_posix),
	TARGET("sinix",		sinix_mips),
	TARGET("solaris",	solaris),
	TARGET("solaris-gnuc",	solaris_gnu),
	TARGET("wasm",		emscripten),
};

#ifndef LIBDIR
#  define LIBDIR			"/usr/local/lib"
#endif

#ifndef OBJDIR
#  define OBJDIR			".libs"
#endif

#ifdef NEED_SNPRINTF
#include <stdarg.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX			1024
#endif

/* We want to say we are libtool 1.4 for shlibtool compatibility. */
#define VERSION "1.4"

#define DEBUG(fmt, ...) if (cmd->options.debug) printf(fmt, ## __VA_ARGS__)
#define NOTICE(fmt, ...) if (!cmd->options.silent) printf(fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)

enum tool_mode {
	MODE_UNKNOWN,
	MODE_COMPILE,
	MODE_LINK,
	MODE_EXECUTE,
	MODE_INSTALL,
};

enum output_type {
	OUT_GENERAL,
	OUT_OBJECT,
	OUT_PROGRAM,
	OUT_LIB,
	OUT_STATIC_LIB_ONLY,
	OUT_DYNAMIC_LIB_ONLY,
	OUT_MODULE,
};

enum pic_mode {
	PIC_UNKNOWN,
	PIC_PREFER,
	PIC_AVOID,
};

enum shared_mode {
	SHARE_UNSET,
	SHARE_STATIC,
	SHARE_SHARED,
};

enum lib_type {
	TYPE_UKNOWN,
	TYPE_STATIC_LIB,
	TYPE_DYNAMIC_LIB,
	TYPE_MODULE_LIB,
	TYPE_OBJECT,
};

typedef struct {
	char const **vals;
	int num;
} count_chars;

typedef struct {
	char const *normal;
	char const *install;
} library_name;

typedef struct {
	count_chars *normal;
	count_chars *install;
	count_chars *dependencies;
} library_opts;

typedef struct {
	int silent;
	int debug;
	enum shared_mode shared;
	int export_all;
	int dry_run;
	enum pic_mode pic_mode;
	int export_dynamic;
	int no_install;
} options_t;

typedef struct {
	enum tool_mode mode;
	enum output_type output;
	options_t options;

	char const *output_name;
	char const *fake_output_name;
	char const *basename;

	char const *install_path;
	char const *compiler;
	char const *program;
	count_chars *program_opts;

	count_chars *arglist;
	count_chars *tmp_dirs;
	count_chars *obj_files;
	count_chars *dep_rpaths;
	count_chars *rpaths;

	library_name static_name;
	library_name shared_name;
	library_name module_name;

	library_opts static_opts;
	library_opts shared_opts;

	char const *version_info;
	char const *undefined_flag;
} command_t;

static void add_rpath(count_chars *cc, char const *path);

static pid_t spawn_pid;
static char const *program = NULL;

static void __attribute__((noreturn)) usage(int code)
{
	printf("Usage: jlibtool [OPTIONS...] COMMANDS...\n");
	printf("jlibtool is a replacement for GNU libtool with similar functionality.\n\n");

	printf("  --config	            show all configuration variables\n");
	printf("  --debug	            enable verbose shell tracing\n");
	printf("  --dry-run	            display commands without modifying any files\n");
	printf("  --help	            display this help message and exit\n");
	printf("  --target=TARGET           specify a target for cross-compilation\n");
	printf("  --toolset=(host|target)   which set of utilities we use\n");
	printf("  --mode=MODE	            use operational mode MODE (you *must* set mode)\n");

	printf("  --silent	           don't print informational messages\n");
	printf("  --tag=TAG	           Ignored for libtool compatibility\n");
	printf("  --version	           print version information\n");

	printf("  --shared	           Build shared libraries when using --mode=link\n");
	printf("  --export-all	           Try to export 'def' file on some platforms\n");

	printf("\nMODE must be one of the following:\n\n");
	printf("  compile	           compile a source file into a jlibtool object\n");
	printf("  execute	           automatically set library path, then run a program\n");
	printf("  install	           install libraries or executables\n");
	printf("  link	                   create a library or an executable\n");

	printf("\nMODE-ARGS can be the following:\n\n");
	printf("  -export-dynamic          accepted and ignored\n");
	printf("  -module	           create a module when linking\n");
	printf("  -shared	           create a shared library when linking\n");
	printf("  -prefer-pic              prefer position-independent-code when compiling\n");
	printf("  -prefer-non-pic          prefer non position-independent-code when compiling\n");
	printf("  -static	           create a static library when linking\n");
	printf("  -no-install              link libraries locally\n");
	printf("  -rpath arg	           Set install path for shared libraries\n");
	printf("  -l arg	           pass '-l arg' to the link stage\n");
	printf("  -L arg	           pass '-L arg' to the link stage\n");
	printf("  -R dir	           add 'dir' to runtime library search path.\n");
	printf("  -Zexe	                   accepted and ignored\n");
	printf("  -avoid-version           accepted and ignored\n");

	exit(code);
}

#if defined(NEED_SNPRINTF)
/* Write at most n characters to the buffer in str, return the
 * number of chars written or -1 if the buffer would have been
 * overflowed.
 *
 * This is portable to any POSIX-compliant system has /dev/null
 */
static FILE *f = NULL;

static int vsnprintf(char *str, size_t n, char const *fmt, va_list ap)
{
	int res;

	if (!f) {
		f = fopen("/dev/null","w");
	}

	if (!f) {
		return -1;
	}

	setvbuf(f, str, _IOFBF, n);

	res = vfprintf(f, fmt, ap);

	if ((res > 0) && (res < n)) {
		res = vsprintf( str, fmt, ap );
	}
	return res;
}

static int snprintf(char *str, size_t n, char const *fmt, ...)
{
	va_list ap;
	int res;

	va_start(ap, fmt);
	res = vsnprintf(str, n, fmt, ap);
	va_end(ap);
	return res;
}
#endif

static void strip_double_chars(char *str, char c)
{
	size_t	len = strlen(str);
	char	*p = str;
	char	*out = str;
	char	*end = p + len;

	while (p < end) {
		while ((p[0] == c) && (p[1] == c)) p++;
		*out++ = *p++;
	}
	*out = '\0';
}

static void *lt_alloc_check(void *out)
{
	if (!out) {
		ERROR("Failed to allocate, OOM\n");
		exit(1);
	}

	return out;
}

static void *lt_malloc(size_t size)
{
	return lt_alloc_check(malloc(size));
}

static char *lt_strdup(char const *str)
{
	return lt_alloc_check(strdup(str));
}

static void lt_const_free(const void *ptr)
{
	void *tmp;

	memcpy(&tmp, &ptr, sizeof(tmp));
	free(tmp);
}

static void init_count_chars(count_chars *cc)
{
	cc->vals = (char const**) lt_malloc(PATH_MAX*sizeof(char*));
	cc->num = 0;
}

static count_chars *alloc_countchars(void)
{
	count_chars *out;
	out = lt_malloc(sizeof(count_chars));
	init_count_chars(out);

	return out;
}

static void clear_count_chars(count_chars *cc)
{
	int i;
	for (i = 0; i < cc->num; i++) {
		cc->vals[i] = NULL;
	}

	cc->num = 0;
}

static void push_count_chars(count_chars *cc, char const *newval)
{
	cc->vals[cc->num++] = newval;
}

static char const *pop_count_chars(count_chars *cc)
{
	if (!cc->num) {
		return NULL;
	}
	return cc->vals[--cc->num];
}

static void insert_count_chars(count_chars *cc, char const *newval, int position)
{
	int i;

	for (i = cc->num; i > position; i--) {
		cc->vals[i] = cc->vals[i-1];
	}

	cc->vals[position] = newval;
	cc->num++;
}

static void append_count_chars(count_chars *cc, count_chars *cctoadd)
{
	int i;
	for (i = 0; i < cctoadd->num; i++) {
		if (cctoadd->vals[i]) {
			push_count_chars(cc, cctoadd->vals[i]);
		}
	}
}

static char const *flatten_count_chars(count_chars *cc, char delim)
{
	int i, size;
	char *newval;

	size = 0;
	for (i = 0; i < cc->num; i++) {
		if (cc->vals[i]) {
			size += strlen(cc->vals[i]) + 1;
			if (delim) {
				size++;
			}
		}
	}

	newval = (char*)lt_malloc(size + 1);
	newval[0] = '\0';

	for (i = 0; i < cc->num; i++) {
		if (cc->vals[i]) {
			strcat(newval, cc->vals[i]);
			if (delim) {
				size_t len = strlen(newval);
				newval[len] = delim;
				newval[len + 1] = '\0';
			}
		}
	}

	return newval;
}

static char *shell_esc(char const *str)
{
	int in_quote = 0;
	char *cmd;
	uint8_t *d;
	uint8_t const *s;

	cmd = (char *)lt_malloc(2 * strlen(str) + 3);
	d = (unsigned char *)cmd;
	s = (const unsigned char *)str;

	if (IS_TARGET(ming32)) {
		*d++ = '\"';
	}

	for (; *s; ++s) {
		if (*s == '"') {
			*d++ = '\\';
			in_quote++;
		}
		else if (*s == '\\' || (*s == ' ' && (in_quote % 2))) {
			*d++ = '\\';
		}
		*d++ = *s;
	}

	if (IS_TARGET(ming32)) {
		*d++ = '\"';
	}

	*d = '\0';
	return cmd;
}

static void external_spawn_sig_handler(int signo)
{
	kill(spawn_pid, signo);	/* Forward the signal to the process we're executing */
}

static int external_spawn(command_t *cmd, __attribute__((unused)) char const *file, char const **argv)
{
	if (!cmd->options.silent) {
		char const **argument = argv;
		NOTICE("Executing: ");
		while (*argument) {
			NOTICE("%s ", *argument);
			argument++;
		}
		puts("");
	}

	if (cmd->options.dry_run) {
		return 0;
	}

#if defined(__EMX__) || defined(__MINGW32__)
	return spawnvp(P_WAIT, argv[0], argv);
#else
	{
		/*
		 *	Signals we forward to our executing process
		 */
		spawn_pid = fork();
		if (spawn_pid == 0) {
			return execvp(argv[0], UNCONST(char **, argv));
		}
		else if (spawn_pid < 0) {
			fprintf(stderr, "Failed fork: %s\n", strerror(errno));
			return -1;
		}
		else {
			int status;

#define SIGNAL_FORWARD(_sig) if (signal(_sig, external_spawn_sig_handler) == SIG_ERR) \
	do { \
		fprintf(stderr, "Failed setting signal handler for %i: %s\n", _sig, strerror(errno)); \
		exit(EXIT_FAILURE); \
	} while(0)

#define SIGNAL_RESET(_sig) signal(_sig, SIG_DFL)

			SIGNAL_FORWARD(SIGHUP);
			SIGNAL_FORWARD(SIGINT);
			SIGNAL_FORWARD(SIGQUIT);
			SIGNAL_FORWARD(SIGTRAP);
			SIGNAL_FORWARD(SIGPIPE);
			SIGNAL_FORWARD(SIGTERM);
			SIGNAL_FORWARD(SIGUSR1);
			SIGNAL_FORWARD(SIGUSR2);

			waitpid(spawn_pid, &status, 0);

			SIGNAL_RESET(SIGHUP);
			SIGNAL_RESET(SIGINT);
			SIGNAL_RESET(SIGQUIT);
			SIGNAL_RESET(SIGTRAP);
			SIGNAL_RESET(SIGPIPE);
			SIGNAL_RESET(SIGTERM);
			SIGNAL_RESET(SIGUSR1);
			SIGNAL_RESET(SIGUSR2);

			/*
			 *	Exited via exit(status)
			 */
			if (WIFEXITED(status)) {
				return WEXITSTATUS(status);
			}

#ifdef WTERMSIG
			if (WIFSIGNALED(status)) {
				return WTERMSIG(status);
			}
#endif

			/*
			 *	Some other failure.
			 */
			return 1;
		}
	}
#endif
}

static int run_command(command_t *cmd, count_chars *cc)
{
	int ret;
	char *command;
	char *tmp;
	char const *raw;
	char const *spawn_args[4];
	count_chars tmpcc;

	init_count_chars(&tmpcc);

	if (cmd->program) {
		push_count_chars(&tmpcc, cmd->program);
	}

	append_count_chars(&tmpcc, cmd->program_opts);

	append_count_chars(&tmpcc, cc);

	raw = flatten_count_chars(&tmpcc, ' ');
	command = shell_esc(raw);

	memcpy(&tmp, &raw, sizeof(tmp));
	free(tmp);

	spawn_args[0] = target->shell_cmd;
	spawn_args[1] = "-c";
	spawn_args[2] = command;
	spawn_args[3] = NULL;
	ret = external_spawn(cmd, spawn_args[0], spawn_args);

	free(command);

	return ret;
}

/*
 * print configuration
 * shlibpath_var is used in configure.
 */
#define printc(_var, _id) if (!*value || !strcmp(value, _id)) if (_var) printf(_id "=\"%s\"\n", _var)

#define printc_ext(_var, _id, _ext) if (!*value || !strcmp(value, _id)) if (_var) printf(_id "=\"%s%s\"\n", _ext, _var)

static void print_config(char const *value)
{
	assert(value != NULL);

	printc(target->ld_run_path, "runpath_var");
	printc(target->ld_library_path, "shlibpath_var");
	printc(target->ld_library_path_local, "shlocallibpath_var");
	printc(target->shell_cmd, "SHELL");
	printc(target->object_ext, "objext");

#ifdef OBJDIR
	if (!value || !strcmp(value, "objdir")) printf("objdir=\"%s\"\n", OBJDIR);
#endif

	/* add a '.' prefix because libtool does that. */
	printc_ext(target->dynamic_lib_ext, "shrext_cmds", "echo .");
	/* add a '.' prefix because libtool does that. */
	printc_ext(target->dynamic_lib_ext, "shrext", ".");
	printc(target->static_lib_ext, "libext");
	printc(target->librarian, "AR");
	printc(target->librarian_opts, "AR_FLAGS");
	printc(target->linker_flag_prefix, "wl");
	printc(toolset->cc, "cc");
	printc(toolset->link_c, "link_c");
	printc(toolset->ranlib, "ranlib");
}
/*
 * Add a directory to the runtime library search path.
 */
static void add_runtime_dir_lib(char const *arg, command_t *cmd)
{
	if (target->rpath) {
		add_rpath(cmd->shared_opts.dependencies, arg);
	} else {
		(void) arg;			/* -Wunused */
		(void) cmd;
	}
}

static int parse_long_opt(char const *arg, command_t *cmd)
{
	char *equal_pos = strchr(arg, '=');
	char var[50];
	char value[500];
	static bool toolset_set = false;

	if (equal_pos) {
		strncpy(var, arg, equal_pos - arg);
		var[equal_pos - arg] = 0;
		if (strlen(equal_pos + 1) >= sizeof(var)) {
			return 0;
		}
		strcpy(value, equal_pos + 1);
	} else {
		strncpy(var, arg, sizeof(var) - 1);
		var[sizeof(var) - 1] = '\0';

		value[0] = '\0';
	}

	if (strcmp(var, "silent") == 0) {
		cmd->options.silent = 1;
	} else if (strcmp(var, "quiet") == 0) {
		cmd->options.silent = 1;
	} else if (strcmp(var, "debug") == 0) {
		cmd->options.debug = 1;
	} else if (strcmp(var, "target") == 0) {
		target_map_t const *p;
		target_map_t const *end;
		size_t i, len;

		/*
		 *	Zero length len is fine, it just means we use the default.
		 */
		len = strlen(value);
		if (!len) return 1;

		/*
		 *	Smash the target to lower case
		 */
		for (i = 0; i < len; i++) value[i] = tolower(value[i]);

		for (p = target_map, end = target_map + (sizeof(target_map) / sizeof(*target_map));
		     p < end;
		     p++) {
			if (strcmp(value, p->name) == 0) {
			found_target:
				/*
				 *	This is cross-compilation target
				 *	switch out the toolset too unless
				 *	explicitly specified.
				 */
				if (p->target != target) {
					if (!toolset_set) toolset = &toolset_target;
					target = p->target;
				}
				DEBUG("Switching target to %s, and toolset to toolset_target\n", p->name);
				break;
			}
		}
		/*
		 *	Invalid target
		 */
		if (p == end) {
			/*
			 *	Can we find a partial match, if so
			 *	use that in preference to failing...
			 */
			for (p = target_map, end = target_map + (sizeof(target_map) / sizeof(*target_map));
			     p < end;
			     p++) {
				if (strstr(value, p->name)) goto found_target;
			}

			ERROR("Unrecognised --target, valid targets are:\n");

			for (p = target_map, end = target_map + (sizeof(target_map) / sizeof(*target_map));
			     p < end;
			     p++) {
				ERROR("  %s (%s)\n", p->name, p->target->name);
			}
			exit(1);
		}
	/*
	 *	Manual override for the set of compilers/linkers etc. we use
	 */
	} else if (strcmp(var, "toolset") == 0) {
		size_t len;

		len = strlen(value);
		if (!len) return 1;

		if (strcasecmp(value, "host") == 0) {
			toolset = &toolset_host;
			toolset_set = true;
		} else if (strcasecmp(value, "target") == 0) {
			toolset = &toolset_target;
			toolset_set = true;
		} else {
			ERROR("Invalid --toolset value \"%s\"", value);
			exit(1);
		}

	} else if (strcmp(var, "mode") == 0) {
		if (cmd->mode != MODE_UNKNOWN) {
			ERROR("Cannot set --mode twice\n");
			exit(1);
		}

		if (strcmp(value, "compile") == 0) {
			cmd->mode = MODE_COMPILE;
			cmd->output = OUT_OBJECT;

		} else if (strcmp(value, "link") == 0) {
			cmd->mode = MODE_LINK;
			cmd->output = OUT_LIB;

		} else if (strcmp(value, "install") == 0) {
			cmd->mode = MODE_INSTALL;

		} else if (strcmp(value, "execute") == 0) {
			cmd->mode = MODE_EXECUTE;

		} else {
			ERROR("Unknown mode \"%s\"\n", value);
			exit(1);
		}

	} else if (strcmp(var, "shared") == 0) {
		if ((cmd->mode == MODE_LINK) && (cmd->output == OUT_GENERAL)) {
			cmd->output = OUT_DYNAMIC_LIB_ONLY;
		}
		cmd->options.shared = SHARE_SHARED;

	} else if (strcmp(var, "export-all") == 0) {
		cmd->options.export_all = 1;

	} else if (strcmp(var, "dry-run") == 0) {
		NOTICE("Dry-run mode on!\n");
		cmd->options.dry_run = 1;

	} else if (strcmp(var, "version") == 0) {
		NOTICE("Version " VERSION "\n");

	} else if (strcmp(var, "help") == 0) {
		usage(0);

	} else if (strcmp(var, "config") == 0) {
		print_config(value);

		exit(0);
	} else if (strcmp(var, "tag") == 0) {
		DEBUG("discard --tag=%s\n", value);
	} else {
		return 0;
	}

	return 1;
}

/* Return 1 if we eat it. */
static int parse_short_opt(char const *arg, command_t *cmd)
{
	if (strcmp(arg, "export-dynamic") == 0) {
		cmd->options.export_dynamic = 1;
		return 1;
	}

	if (strcmp(arg, "module") == 0) {
		cmd->output = OUT_MODULE;
		return 1;
	}

	if (strcmp(arg, "shared") == 0) {
		if (cmd->mode == MODE_LINK) {
			cmd->output = OUT_DYNAMIC_LIB_ONLY;
		}
		cmd->options.shared = SHARE_SHARED;
		return 1;
	}

	if (strcmp(arg, "Zexe") == 0) {
		return 1;
	}

	if (strcmp(arg, "avoid-version") == 0) {
		return 1;
	}

	if (strcmp(arg, "prefer-pic") == 0) {
		cmd->options.pic_mode = PIC_PREFER;
		return 1;
	}

	if (strcmp(arg, "prefer-non-pic") == 0) {
		cmd->options.pic_mode = PIC_AVOID;
		return 1;
	}

	if (strcmp(arg, "static") == 0) {
		if ((cmd->mode == MODE_LINK) && (cmd->output == OUT_LIB)) {
			cmd->output = OUT_STATIC_LIB_ONLY;
		}
		cmd->options.shared = SHARE_STATIC;
		return 1;
	}

	if (cmd->mode == MODE_LINK) {
		if (strcmp(arg, "no-install") == 0) {
			cmd->options.no_install = 1;
			return 1;
		}
		if (arg[0] == 'L' || arg[0] == 'l') {
			/* Hack... */
			arg--;
			push_count_chars(cmd->shared_opts.dependencies, arg);
			return 1;
		} else if (arg[0] == 'R' && arg[1]) {
			/* -Rdir Add dir to runtime library search path. */
			add_runtime_dir_lib(&arg[1], cmd);
			return 1;
		}
	}
	return 0;
}

static char *truncate_dll_name(char const *path)
{
	/* Cut DLL name down to 8 characters after removing any mod_ prefix */
	char *tmppath = lt_strdup(path);
	char *newname = strrchr(tmppath, '/') + 1;
	char *ext = strrchr(newname, '.');
	int len, ext_len;

	if (ext == NULL) return tmppath;

	/*
	 *	About the removals: they can't be done with strcpy() because
	 *	there is necessarily overlap, which for strcpy() is undefined
	 *	behavior. Only memmove() is guaranteed to work in the presence
	 *	of overlap.
	 */

	len = ext - newname;
	ext_len = strlen(ext);

	if (strncmp(newname, "mod_", 4) == 0) {
		memmove(newname, newname + 4, len + ext_len - 4 + 1);
		ext -= 4;
		len -= 4;
	}

	if (len > 8) memmove(newname + 8, ext, ext_len + 1);

	return tmppath;
}

static void safe_mkdir(command_t *cmd, char const *path)
{
	int status;
	mode_t old_umask;

	old_umask = umask(0);
	umask(old_umask);

#ifdef MKDIR_NO_UMASK
	status = mkdir(path);
#else
	status = mkdir(path, ~old_umask);
#endif
	if ((status < 0) && (errno != EEXIST)) {
		NOTICE("Warning: mkdir of %s failed: %s\n", path, strerror(errno));
	}
}

/** Returns a file's name without the path
 *
 * @param path to break apart.
 * @return pointer in path.
 */
static char const *file_name(char const *path)
{
	char const *name;

	name = strrchr(path, '/');
	if (!name) {
		name = strrchr(path, '\\'); 	/* eww windows? */
	}
	if (!name) {
		name = path;
	} else {
		name++;
	}

	return name;
}

/** Returns a file's name without path or extension
 *
 * @param path to check
 * @return pointer in path.
 */
static char const *file_name_stripped(char const *path, bool *allocated)
{
	char const *name;
	char const *ext;

	name = file_name(path);
	ext = strrchr(name, '.');

	if (ext) {
		char *trimmed;

		trimmed = lt_malloc(ext - name + 1);
		strncpy(trimmed, name, ext - name);
		trimmed[ext-name] = 0;

		*allocated = true;
		return trimmed;
	}

	*allocated = false;
	return name;
}

/* version_info is in the form of MAJOR:MINOR:PATCH */
static char const *darwin_dynamic_link_function(char const *version_info)
{
	static const char seps[] = ":.,-_";
	const char *major, *minor;
	int major_len, minor_len;
	char *newarg;

	if (version_info) {
		major = version_info;
		major_len = strcspn(major, seps);
		minor = major + major_len;
		minor += strspn(minor, seps);
		minor_len = strcspn(major, seps);
	} else {
		major = "1";
		major_len = 1;
		minor = "0";
		minor_len = 1;
	}
	newarg = (char*)lt_malloc(100);
	snprintf(newarg, 99,
		 "-compatibility_version %.*s -current_version %.*s.%.*s",
		 major_len, major, major_len, major, minor_len, minor);
	return newarg;
}


/*
 *	Add a '.libs/' to the buffer.  The caller ensures that
 *	The buffer is large enough to handle 6 extra characters.
 */
static void add_dotlibs(char *buffer)
{
	char *name = strrchr(buffer, '/');

	if (!name) {
		if (!buffer[0]) {
			strcpy(buffer, ".libs/");
			return;
		}
		name = buffer;
	} else {
		name++;
	}
	memmove(name + 6, name, strlen(name) + 1);
	memcpy(name, ".libs/", 6);
}

static char *gen_library_name(char const *name, enum lib_type genlib)
{
	char *newarg, *newext;

	newarg = (char *)calloc(strlen(name) + 11, 1);

	if (genlib == TYPE_MODULE_LIB && strncmp(name, "lib", 3) == 0) {
		name += 3;
	}

	if (genlib == TYPE_MODULE_LIB) {
		strcpy(newarg, file_name(name));
	}
	else {
		strcpy(newarg, name);
	}

	newext = strrchr(newarg, '.');
	if (!newext) {
		ERROR("Library path does not have an extension\n");
	free(newarg);

	return NULL;
	}
	newext++;

	switch (genlib) {
	case TYPE_STATIC_LIB:
		strcpy(newext, target->static_lib_ext);
		break;

	case TYPE_DYNAMIC_LIB:
		strcpy(newext, target->dynamic_lib_ext);
		break;

	case TYPE_MODULE_LIB:
		strcpy(newext, target->module_lib_ext);
		break;

	default:
		break;
	}

	add_dotlibs(newarg);

	return newarg;
}

static char *gen_install_name(char const *name, enum lib_type genlib)
{
	char *newname;
	int rv;
	struct stat sb;

	newname = gen_library_name(name, genlib);
	if (!newname) return NULL;

	/* Check if it exists. If not, return NULL.  */
	rv = stat(newname, &sb);

	if (rv) {
		free(newname);
		return NULL;
	}

	return newname;
}

static char const *check_object_exists(command_t *cmd, char const *arg, int arglen)
{
	char *newarg, *ext;
	struct stat sb;

	newarg = (char *)lt_malloc(arglen + 10);
	memcpy(newarg, arg, arglen);
	newarg[arglen] = 0;
	ext = newarg + arglen;

	strcpy(ext, target->object_ext);

	DEBUG("Checking (obj): %s\n", newarg);
	if (stat(newarg, &sb) == 0) {
		return newarg;
	}

	free(newarg);

	return NULL;
}

/* libdircheck values:
 * 0 - no .libs suffix
 * 1 - .libs suffix
 */
static char *check_library_exists(command_t *cmd, char const *arg, int pathlen,
				  int libdircheck, enum lib_type *libtype)
{
	char *newarg, *ext;
	int pass, rv, newpathlen;

	newarg = (char *)lt_malloc(strlen(arg) + 10);
	strcpy(newarg, arg);
	newarg[pathlen] = '\0';

	newpathlen = pathlen;
	if (libdircheck) {
		add_dotlibs(newarg);
		newpathlen += sizeof(".libs/") - 1;
	}

	strcpy(newarg + newpathlen, arg + pathlen);
	ext = strrchr(newarg, '.');
	if (!ext || ext == newarg) {
		ERROR("Error: Library path does not have an extension\n");
		free(newarg);

		return NULL;
	}
	ext++;

	pass = 0;

	do {
		struct stat sb;

		switch (pass) {
		case 0:
			if (cmd->options.pic_mode != PIC_AVOID &&
				cmd->options.shared != SHARE_STATIC) {
				strcpy(ext, target->dynamic_lib_ext);
				*libtype = TYPE_DYNAMIC_LIB;
				break;
			}
			pass = 1;
			FALL_THROUGH;

		case 1:
			strcpy(ext, target->static_lib_ext);
			*libtype = TYPE_STATIC_LIB;
			break;
		case 2:
			strcpy(ext, target->module_lib_ext);
			*libtype = TYPE_MODULE_LIB;
			break;
		case 3:
			strcpy(ext, target->object_ext);
			*libtype = TYPE_OBJECT;
			break;
		default:
			*libtype = TYPE_UKNOWN;
			break;
		}

		DEBUG("Checking (lib): %s\n", newarg);
		rv = stat(newarg, &sb);
	}
	while (rv != 0 && ++pass < 4);

	if (rv == 0) {
		return newarg;
	}

	free(newarg);

	return NULL;
}

static char * load_install_path(char const *arg)
{
	FILE *f;
	char *path = NULL;
	char line[PATH_MAX + 10]; /* libdir='<path>'\n */
	char token[] = "libdir='";
	char *p;

	f = fopen(arg,"r");
	if (f == NULL) {
		return NULL;
	}

	while (fgets(line, sizeof(line), f)) {
		/* Skip comments and blank lines */
		if ((line[0] == '#') || (line[0] < ' ')) continue;

		if ((p = strstr(line, token))) {
			p += strlen(token);
			path = lt_malloc(PATH_MAX);
			strncpy(path, p, PATH_MAX);

			/* fgets reads newline */
			if (path[strlen(path)-1] == '\n') {
				path[strlen(path)-1] = '\0';
			}

			/* Remove endquote for libdir */
			if (path[strlen(path)-1] == '\'') {
				path[strlen(path)-1] = '\0';
			}

			break;
		}
	}

	fclose(f);

	if (!path) return NULL;

	/* Check that we have an absolute path.
	 * Otherwise the file could be a GNU libtool file.
	 */
	if (path[0] != '/') {
		free(path);

		return NULL;
	}

	return path;
}

static char *load_noinstall_path(char const *arg, int pathlen)
{
	char *newarg, *expanded_path;
	int newpathlen;

	newarg = (char *)lt_malloc(strlen(arg) + 10);
	strcpy(newarg, arg);
	newarg[pathlen] = 0;

	newpathlen = pathlen;
	strcat(newarg, ".libs");
	newpathlen += sizeof(".libs") - 1;
	newarg[newpathlen] = 0;

	if (target->has_realpath) {
		expanded_path = lt_malloc(PATH_MAX);
		/* Uh, oh.  There was an error.  Fall back on our first guess. */
		if (!realpath(newarg, expanded_path)) {
			lt_const_free(expanded_path);
			expanded_path = newarg;
		} else {
			lt_const_free(newarg);
		}
	} else {
		/* We might get ../ or something goofy.  Oh, well. */
		expanded_path = newarg;
	}

	return expanded_path;
}

static void add_dynamic_link_opts(command_t *cmd, count_chars *args)
{
	if (target->dynamic_link_opts && (cmd->options.pic_mode != PIC_AVOID)) {
		DEBUG("Adding linker opt: %s\n", target->dynamic_link_opts);

		push_count_chars(args, target->dynamic_link_opts);
		if (cmd->undefined_flag) {
			push_count_chars(args, "-undefined");

			if (IS_TARGET(macos)) {
				/* -undefined dynamic_lookup is used by the bundled Python in
				 * 10.4, but if we don't set MACOSX_DEPLOYMENT_TARGET to 10.3+,
				 * we'll get a linker error if we pass this flag.
				 */
				if (strcasecmp(cmd->undefined_flag, "dynamic_lookup") == 0) {
					insert_count_chars(cmd->program_opts, "MACOSX_DEPLOYMENT_TARGET=10.3", 0);
				}
			}
			push_count_chars(args, cmd->undefined_flag);
		}
		else if (target->dynamic_link_opts_undefined){
			DEBUG("Adding linker opt: %s\n", target->dynamic_link_opts_undefined);

			push_count_chars(args, target->dynamic_link_opts_undefined);
		}
	}
}

/* Read the final install location and add it to runtime library search path. */
static void add_rpath(count_chars *cc, char const *path)
{
	int size = 0;
	char *tmp;

	if (target->linker_flag_prefix) size = strlen(target->linker_flag_prefix);
	size = size + strlen(path) + strlen(target->rpath) + 2;
	tmp = lt_malloc(size);

	if (target->linker_flag_prefix) {
		strcpy(tmp, target->linker_flag_prefix);
		strcat(tmp, target->rpath);
	} else {
		strcpy(tmp, target->rpath);
	}

	if (!target->linker_flag_no_equals) strcat(tmp, "=");
	strcat(tmp, path);

	push_count_chars(cc, tmp);
}

static void add_rpath_file(count_chars *cc, char const *arg)
{
	char const *path;

	path = load_install_path(arg);
	if (path) {
		add_rpath(cc, path);
		lt_const_free(path);
	}
}

static void add_rpath_noinstall(count_chars *cc, char const *arg, int pathlen)
{
	char const *path;

	path = load_noinstall_path(arg, pathlen);
	add_rpath(cc, path);
	lt_const_free(path);
}

#if 0
static void add_dylink_noinstall(count_chars *cc, char const *arg, int pathlen,
						  int extlen)
{
	char const *install_path, *current_path, *name;
	char *exp_argument;
	int i_p_len, c_p_len, name_len, dyext_len, cur_len;

	install_path = load_install_path(arg);
	if (!install_path) return;

	current_path = load_noinstall_path(arg, pathlen);

	push_count_chars(cc, target->dynamic_link_no_install);

	i_p_len = strlen(install_path);
	c_p_len = strlen(current_path);

	name = arg+pathlen;
	name_len = extlen-pathlen;
	dyext_len = sizeof(target->dynamic_lib_ext) - 1;

	/* No, we need to replace the extension. */
	exp_argument = (char *)lt_malloc(i_p_len + c_p_len + (name_len*2) +
								  (dyext_len*2) + 2);

	cur_len = 0;
	strcpy(exp_argument, install_path);
	cur_len += i_p_len;
	exp_argument[cur_len++] = '/';
	strncpy(exp_argument+cur_len, name, extlen-pathlen);
	cur_len += name_len;
	strcpy(exp_argument+cur_len, target->dynamic_lib_ext);
	cur_len += dyext_len;
	exp_argument[cur_len++] = ':';
	strcpy(exp_argument+cur_len, current_path);
	cur_len += c_p_len;
	exp_argument[cur_len++] = '/';
	strncpy(exp_argument+cur_len, name, extlen-pathlen);
	cur_len += name_len;
	strcpy(exp_argument+cur_len, target->dynamic_lib_ext);
	cur_len += dyext_len;

	push_count_chars(cc, exp_argument);
	lt_const_free(install_path);
	lt_const_free(current_path);
}
#endif

/* use -L -llibname to allow to use installed libraries */
static void add_minus_l(count_chars *cc, char const *arg)
{
	char *newarg;
	char *name = strrchr(arg, '/');
	char *file = strrchr(arg, '.');

	if ((name != NULL) && (file != NULL) &&
		(strstr(name, "lib") == (name + 1))) {
		*name = '\0';
		*file = '\0';
		file = name;
		file = file+4;
		push_count_chars(cc, "-L");
		push_count_chars(cc, arg);
		/* we need one argument like -lapr-1 */
		newarg = lt_malloc(strlen(file) + 3);
		strcpy(newarg, "-l");
		strcat(newarg, file);
		push_count_chars(cc, newarg);
	}
	/* special case for FreeRADIUS loadable modules */
	else if ((name != NULL) && (file != NULL) &&
		(strstr(name, "rlm_") == (name + 1))) {
		*name = '\0';
		file = name+1;
		push_count_chars(cc, "-L");
		push_count_chars(cc, arg);
		/* we need one argument like -lapr-1 */
		newarg = lt_malloc(strlen(file) + 4);
		strcpy(newarg, "-l:");
		strcat(newarg, file);
		push_count_chars(cc, newarg);
	} else {
		push_count_chars(cc, arg);
	}
}

#if 0
static void add_linker_flag_prefix(count_chars *cc, char const *arg)
{
	if (!target->linker_flag_prefix) {
		push_count_chars(cc, arg);
	} else {
		char *newarg;
		newarg = (char*)lt_malloc(strlen(arg) + sizeof(target->linker_flag_prefix) + 1);
		strcpy(newarg, target->linker_flag_prefix);
		strcat(newarg, arg);
		push_count_chars(cc, newarg);
	}
}
#endif

static int explode_static_lib(command_t *cmd, char const *lib)
{
	count_chars tmpdir_cc, libname_cc;
	char const *tmpdir, *libname;
	char savewd[PATH_MAX];
	char const *name;
	DIR *dir;
	struct dirent *entry;
	char const *lib_args[4];

	/* Bah! */
	if (cmd->options.dry_run) {
		return 0;
	}

	name = file_name(lib);

	init_count_chars(&tmpdir_cc);
	push_count_chars(&tmpdir_cc, ".libs/");
	push_count_chars(&tmpdir_cc, name);
	push_count_chars(&tmpdir_cc, ".exploded/");
	tmpdir = flatten_count_chars(&tmpdir_cc, 0);

	NOTICE("Making: %s\n", tmpdir);

	safe_mkdir(cmd, tmpdir);

	push_count_chars(cmd->tmp_dirs, tmpdir);

	getcwd(savewd, sizeof(savewd));

	if (chdir(tmpdir) != 0) {
		NOTICE("Warning: could not explode %s\n", lib);

		return 1;
	}

	if (lib[0] == '/') {
		libname = lib;
	}
	else {
		init_count_chars(&libname_cc);
		push_count_chars(&libname_cc, "../../");
		push_count_chars(&libname_cc, lib);
		libname = flatten_count_chars(&libname_cc, 0);
	}

	lib_args[0] = target->librarian;
	lib_args[1] = "x";
	lib_args[2] = libname;
	lib_args[3] = NULL;

	external_spawn(cmd, target->librarian, lib_args);

	chdir(savewd);
	dir = opendir(tmpdir);

	while ((entry = readdir(dir)) != NULL) {
		if (IS_TARGET(macos) && toolset->ranlib) {
			/* Apple inserts __.SYMDEF which isn't needed.
			 * Leopard (10.5+) can also add '__.SYMDEF SORTED' which isn't
			 * much fun either.  Just skip them.
			 */
			if (strstr(entry->d_name, "__.SYMDEF") != NULL) {
				continue;
			}
		}
		if (entry->d_name[0] != '.') {
			push_count_chars(&tmpdir_cc, entry->d_name);
			name = flatten_count_chars(&tmpdir_cc, 0);

			DEBUG("Adding object: %s\n", name);
			push_count_chars(cmd->obj_files, name);
			pop_count_chars(&tmpdir_cc);
		}
	}

	closedir(dir);
	return 0;
}

static int parse_input_file_name(char const *arg, command_t *cmd)
{
	char const *ext = strrchr(arg, '.');
	char const *name;
	int pathlen;
	enum lib_type libtype;
	char const *newarg;

	/* Can't guess the extension */
	if (!ext) {
		return 0;
	}

	ext++;
	name = file_name(arg);
	pathlen = name - arg;

	/*
	 *	Were linking and have an archived object or object file
	 *	push it onto the list of object files which'll get used
	 *	to create the input files list for the linker.
	 *
	 *	We assume that these are outside of the project were building,
	 *	as there's no reason to create .a files as part of the build
	 *	process.
	 */
	if (!strcmp(ext, target->static_lib_ext) && (cmd->mode == MODE_LINK)) {
		struct stat sb;

		if (!stat(arg, &sb)) {
			DEBUG("Adding object: %s\n", arg);

			push_count_chars(cmd->obj_files, arg);

			return 1;
		}
	}

	/*
	 *	More object files, if were linking they get set as input
	 *	files.
	 */
	if (!strcmp(ext, "lo") || !strcmp(ext, target->object_ext)) {
		newarg = check_object_exists(cmd, arg, ext - arg);
		if (!newarg) {
			ERROR("Can not find suitable object file for %s\n", arg);
			exit(1);
		}

		if (cmd->mode == MODE_LINK) {
			DEBUG("Adding object: %s\n", newarg);

			push_count_chars(cmd->obj_files, newarg);
		} else {
			push_count_chars(cmd->arglist, newarg);
		}

		return 1;
	}

	if (!strcmp(ext, "la")) {
		switch (cmd->mode) {
		case MODE_LINK:
			/* Try the .libs dir first! */
			newarg = check_library_exists(cmd, arg, pathlen, 1, &libtype);
			if (!newarg) {
				/* Try the normal dir next. */
				newarg = check_library_exists(cmd, arg, pathlen, 0, &libtype);
				if (!newarg) {
					ERROR("Can not find suitable library for %s\n", arg);
					exit(1);
				}
			}

			/* It is not ok to just add the file: a library may added with:
			   1 - -L path library_name. (For *.so in Linux).
			   2 - library_name.
			 */
			if (target->add_minus_l) {
				if (libtype == TYPE_DYNAMIC_LIB) {
					/* coverity[string_null] */
					add_minus_l(cmd->shared_opts.dependencies, newarg);
				} else if ((cmd->output == OUT_LIB) && (libtype == TYPE_STATIC_LIB)) {
					explode_static_lib(cmd, newarg);
				} else {
					push_count_chars(cmd->shared_opts.dependencies, newarg);
				}
			} else {
				if (cmd->output == OUT_LIB && libtype == TYPE_STATIC_LIB) {
					explode_static_lib(cmd, newarg);
				}
				else {
					push_count_chars(cmd->shared_opts.dependencies, newarg);
				}
			}

			if ((libtype == TYPE_DYNAMIC_LIB) && target->rpath) {
				if (cmd->options.no_install) {
					add_rpath_noinstall(cmd->shared_opts.dependencies, arg, pathlen);
				}
				else {
					add_rpath_file(cmd->shared_opts.dependencies, arg);
				}
			}
			break;
		case MODE_INSTALL:
			/*
			 *	If we've already recorded a library to
			 *	install, we're most likely getting the .la
			 *	file that we want to install as.
			 *
			 *	The problem is that we need to add it as the
			 *	directory, not the .la file itself.
			 *	Otherwise, we'll do odd things.
			 */
			if (cmd->output == OUT_LIB && pathlen > 0) {
				char *tmp = lt_strdup(arg);
				tmp[pathlen] = '\0';
				DEBUG("Adding: %s\n", tmp);
				push_count_chars(cmd->arglist, tmp);
			} else {
				cmd->output = OUT_LIB;
				cmd->output_name = arg;
				cmd->static_name.install = gen_install_name(arg, 0);
				cmd->shared_name.install = gen_install_name(arg, 1);
				cmd->module_name.install = gen_install_name(arg, 2);

				if (!cmd->static_name.install &&
					!cmd->shared_name.install &&
					!cmd->module_name.install) {
					ERROR("Files to install do not exist\n");
					exit(1);
				}

			}
			break;
		default:
			break;
		}

		return 1;
	}

	if (!strcmp(ext, "c")) {
		/* If we don't already have an idea what our output name will be. */
		if (!cmd->basename) {
			char *tmp = lt_malloc(strlen(arg) + 4);
			strcpy(tmp, arg);
			strcpy(strrchr(tmp, '.') + 1, "lo");

			cmd->basename = tmp;

			cmd->fake_output_name = strrchr(cmd->basename, '/');
			if (cmd->fake_output_name) {
				cmd->fake_output_name++;
			} else {
				cmd->fake_output_name = cmd->basename;
			}
		}
	}

	return 0;
}

static int parse_output_file_name(char const *arg, command_t *cmd)
{
	char const *name;
	char const *ext;
	char *newarg = NULL;

	cmd->fake_output_name = arg;

	name = file_name(arg);
	ext = strrchr(name, '.');

	if (!ext || (target->exe_ext && (strcmp(ext, target->exe_ext) == 0))) {
		cmd->basename = arg;
		cmd->output = OUT_PROGRAM;

		if (IS_TARGET(osd_posix)) {
			cmd->options.pic_mode = PIC_AVOID;
		}
		newarg = (char *)lt_malloc(strlen(arg) + 5);
		strcpy(newarg, arg);

		if (target->exe_ext && !ext) {
			strcat(newarg, target->exe_ext);
		}
		cmd->output_name = newarg;
		return 1;
	}

	ext++;

	if (strcmp(ext, "la") == 0) {
		assert(cmd->mode == MODE_LINK);

		cmd->basename = arg;
		cmd->static_name.normal = gen_library_name(arg, TYPE_STATIC_LIB);
		cmd->shared_name.normal = gen_library_name(arg, TYPE_DYNAMIC_LIB);
		cmd->module_name.normal = gen_library_name(arg, TYPE_MODULE_LIB);
		cmd->static_name.install = gen_install_name(arg, TYPE_STATIC_LIB);
		cmd->shared_name.install = gen_install_name(arg, TYPE_DYNAMIC_LIB);
		cmd->module_name.install = gen_install_name(arg, TYPE_MODULE_LIB);

		if (!cmd->options.dry_run) {
			char *newname;
			char *newext;
			newname = lt_malloc(strlen(cmd->static_name.normal) + 1);

			strcpy(newname, cmd->static_name.normal);
			newext = strrchr(newname, '/');
			if (!newext) {
				/* Check first to see if the dir already exists! */
				safe_mkdir(cmd, ".libs");
			} else {
				*newext = '\0';
				safe_mkdir(cmd, newname);
			}
			free(newname);
		}

		if (target->truncate_dll_name) {
			arg = truncate_dll_name(arg);
		}

		cmd->output_name = arg;
		return 1;
	}

	if (strcmp(ext, target->static_lib_ext) == 0) {
		assert(cmd->mode == MODE_LINK);

		cmd->basename = arg;
		cmd->options.shared = SHARE_STATIC;
		cmd->output = OUT_STATIC_LIB_ONLY;
		cmd->static_name.normal = gen_library_name(arg, TYPE_STATIC_LIB);
		cmd->static_name.install = gen_install_name(arg, TYPE_STATIC_LIB);

		if (!cmd->options.dry_run) {
			char *newname;
			char *newext;
			newname = lt_malloc(strlen(cmd->static_name.normal) + 1);

			strcpy(newname, cmd->static_name.normal);
			newext = strrchr(newname, '/');
			if (!newext) {
				/* Check first to see if the dir already exists! */
				safe_mkdir(cmd, ".libs");
			} else {
				*newext = '\0';
				safe_mkdir(cmd, newname);
			}
			free(newname);
		}

		cmd->output_name = arg;
		return 1;
	}

	if (strcmp(ext, target->dynamic_lib_ext) == 0) {
		assert(cmd->mode == MODE_LINK);

		cmd->basename = arg;
		cmd->options.shared = SHARE_SHARED;
		cmd->output = OUT_DYNAMIC_LIB_ONLY;
		cmd->shared_name.normal = gen_library_name(arg, TYPE_DYNAMIC_LIB);
		cmd->module_name.normal = gen_library_name(arg, TYPE_MODULE_LIB);
		cmd->shared_name.install = gen_install_name(arg, TYPE_DYNAMIC_LIB);
		cmd->module_name.install = gen_install_name(arg, TYPE_MODULE_LIB);

		if (!cmd->options.dry_run) {
			char *newname;
			char *newext;
			newname = lt_malloc(strlen(cmd->shared_name.normal) + 1);

			strcpy(newname, cmd->shared_name.normal);
			newext = strrchr(newname, '/');
			if (!newext) {
				/* Check first to see if the dir already exists! */
				safe_mkdir(cmd, ".libs");
			} else {
				*newext = '\0';
				safe_mkdir(cmd, newname);
			}
			free(newname);
		}

		cmd->output_name = arg;
		return 1;
	}

	if (strcmp(ext, "lo") == 0) {
		char *newext;
		cmd->basename = arg;
		cmd->output = OUT_OBJECT;
		newarg = (char *)lt_malloc(strlen(arg) + 2);
		strcpy(newarg, arg);
		newext = strrchr(newarg, '.') + 1;
		strcpy(newext, target->object_ext);
		cmd->output_name = newarg;
		return 1;
	}

	if (strcmp(ext, target->dynamic_lib_ext) == 0) {
		ERROR("Please build libraries with .la target, not .%s\n", target->dynamic_lib_ext);

		exit(1);
	}

	if (strcmp(ext, target->static_lib_ext) == 0) {
		ERROR("Please build libraries with .la target, not .%s\n", target->static_lib_ext);

		exit(1);
	}

	return 0;
}

static char const *automode(char const *arg, command_t *cmd)
{
	if (cmd->mode != MODE_UNKNOWN) return arg;

	if (!strcmp(arg, "CC") ||
	    !strcmp(arg, "CXX")) {
		DEBUG("Now in compile mode, guessed from: %s\n", arg);
		arg = toolset->cc;
		cmd->mode = MODE_COMPILE;

	} else if (!strcmp(arg, "LINK") ||
		   !strcmp(arg, "LINK.c") ||
		   !strcmp(arg, "LINK.cxx")) {
		DEBUG("Now in linker mode, guessed from: %s\n", arg);
		arg = toolset->link_c;
		cmd->mode = MODE_LINK;
	}

	return arg;
}

static void generate_def_file(command_t *cmd)
{
	char def_file[1024];
	char implib_file[1024];
	char *ext;
	FILE *hDef;
	char const *export_args[1024];
	int num_export_args = 0;
	char *cmd_str;
	int cmd_size = 0;
	int imp_len;


	if (cmd->output_name) {
		if (strlen(cmd->output_name) + 4 > sizeof(def_file)) {
			ERROR("Def file name too long, out of buffer space\n");
			return;
		}
		strcpy(def_file, cmd->output_name);
		strcat(def_file, ".def");
		hDef = fopen(def_file, "w");

		if (hDef != NULL) {
			bool stripped_allocated;
			char const *stripped;

			stripped = file_name_stripped(cmd->output_name, &stripped_allocated);
			fprintf(hDef, "LIBRARY '%s' INITINSTANCE\n", stripped);
			fprintf(hDef, "DATA NONSHARED\n");
			fprintf(hDef, "EXPORTS\n");
			fclose(hDef);
			if (stripped_allocated) lt_const_free(stripped);

#if 0	/* No num_obj_files ? */
			for (a = 0; a < cmd->num_obj_files; a++) {
				cmd_size += strlen(cmd->obj_files[a]) + 1;
			}
#endif
			cmd_size += strlen(target->gen_exports) + strlen(def_file) + 3;
			cmd_str = (char *)lt_malloc(cmd_size);
			strcpy(cmd_str, target->gen_exports);

#if 0	/* No num_obj_files ? */
			for (a=0; a < cmd->num_obj_files; a++) {
				strcat(cmd_str, " ");
				strcat(cmd_str, cmd->obj_files[a] );
			}
#endif

			strcat(cmd_str, ">>");
			strcat(cmd_str, def_file);
			puts(cmd_str);
			export_args[num_export_args++] = target->shell_cmd;
			export_args[num_export_args++] = "-c";
			export_args[num_export_args++] = cmd_str;
			export_args[num_export_args++] = NULL;
			external_spawn(cmd, export_args[0], (char const**)export_args);
#if 0	/* No num args ? */
			cmd->arglist[cmd->num_args++] = lt_strdup(def_file);
#endif
			/* Now make an import library for the dll */
			num_export_args = 0;
			export_args[num_export_args++] = target->def2implib_cmd;
			export_args[num_export_args++] = "-o";

			imp_len = strlen(cmd->basename) + 7;
			if (imp_len > sizeof(implib_file)) {
			imp_too_long:
				ERROR("imp file name too long, out of buffer space\n");
				return;
			}

			strcpy(implib_file, ".libs/");
			strcat(implib_file, cmd->basename);

			ext = strrchr(implib_file, '.');
			if (ext) {
				*ext = '\0';
				imp_len = ext - implib_file + 1;
			}

			imp_len += strlen(target->static_lib_ext) + 1;
			if (imp_len > sizeof(implib_file)) goto imp_too_long;

			strcat(implib_file, ".");
			strcat(implib_file, target->static_lib_ext);

			export_args[num_export_args++] = implib_file;
			export_args[num_export_args++] = def_file;
			export_args[num_export_args++] = NULL;
			external_spawn(cmd, export_args[0], (char const**)export_args);

		}
	}
}

#if 0
static char const* expand_path(char const *relpath)
{
	char foo[PATH_MAX], *newpath;

	getcwd(foo, PATH_MAX-1);
	newpath = (char*)lt_malloc(strlen(foo)+strlen(relpath)+2);
	strcpy(newpath, foo);
	strcat(newpath, "/");
	strcat(newpath, relpath);
	return newpath;
}
#endif

static void link_fixup(command_t *cmd)
{
	/* If we were passed an -rpath directive, we need to build
	 * shared objects too.  Otherwise, we should only create static
	 * libraries.
	 */
	if (!cmd->install_path && (cmd->output == OUT_DYNAMIC_LIB_ONLY ||
		cmd->output == OUT_MODULE || cmd->output == OUT_LIB)) {
		if (cmd->options.shared == SHARE_SHARED) {
			cmd->install_path = LIBDIR;
		}
		if (cmd->output == OUT_LIB) {
			cmd->output = OUT_STATIC_LIB_ONLY;
		}
	}

	if (cmd->output == OUT_DYNAMIC_LIB_ONLY ||
		cmd->output == OUT_MODULE ||
		cmd->output == OUT_LIB) {

		push_count_chars(cmd->shared_opts.normal, "-o");
		if (cmd->output == OUT_MODULE) {
			push_count_chars(cmd->shared_opts.normal, cmd->module_name.normal);
		} else {
			push_count_chars(cmd->shared_opts.normal, cmd->shared_name.normal);
			if (target->dynamic_install_name) {
				push_count_chars(cmd->shared_opts.normal, target->dynamic_install_name);

				if (IS_TARGET(macos)) {
					/*
					 *	Install paths on OSX are absolute.
					 */
					if (!cmd->install_path) {
						ERROR("Installation mode requires -rpath\n");
						exit(1);
					}
				}

				{
					char *tmp = lt_malloc(PATH_MAX + 30);
					char *suffix;

					if (cmd->install_path) {
						strcpy(tmp, cmd->install_path);
					} else {
						strcpy(tmp, "");
					}

					suffix = strrchr((cmd->shared_name.install ?
							 cmd->shared_name.install : cmd->shared_name.normal),
							 '/');
					if (!suffix) {
						ERROR("Installation mode requires directory\n");
						exit(1);
					}
					strcat(tmp, suffix);

					/*
					 *	Add the version as "libfoo.so.PROGRAM_VERSION"
					 */
#if 0
					if (target->program_version && !IS_TARGET(macos)) {
						strcat(tmp, ".");
						strcat(tmp, target->program_version);
					}
#endif
					strip_double_chars(tmp, '/');	/* macos now complains bitterly about double slashes */

					push_count_chars(cmd->shared_opts.normal, tmp);
				}

#ifdef PROGRAM_VERSION
				if (IS_TARGET(macos)) {
					/*
					 *	These are separate options on OSX.
					 */
					push_count_chars(cmd->shared_opts.normal, "-current_version ");
					push_count_chars(cmd->shared_opts.normal, STRINGIFY(PROGRAM_VERSION));
					push_count_chars(cmd->shared_opts.normal, "-compatibility_version ");
					push_count_chars(cmd->shared_opts.normal, STRINGIFY(PROGRAM_VERSION));
				}
#endif
			}
		}

		append_count_chars(cmd->shared_opts.normal, cmd->obj_files);
		append_count_chars(cmd->shared_opts.normal, cmd->shared_opts.dependencies);

		if (cmd->options.export_all && target->gen_exports) {
			generate_def_file(cmd);
		}
	}

	if (cmd->output == OUT_LIB || cmd->output == OUT_STATIC_LIB_ONLY) {
		push_count_chars(cmd->static_opts.normal, "-o");
		push_count_chars(cmd->static_opts.normal, cmd->output_name);
	}

	if (cmd->output == OUT_PROGRAM) {
		if (cmd->output_name) {
			push_count_chars(cmd->arglist, "-o");
			push_count_chars(cmd->arglist, cmd->output_name);
			append_count_chars(cmd->arglist, cmd->obj_files);
			append_count_chars(cmd->arglist, cmd->shared_opts.dependencies);
			add_dynamic_link_opts(cmd, cmd->arglist);
		}
	}
}

static void post_parse_fixup(command_t *cmd)
{
	switch (cmd->mode) {
	case MODE_COMPILE:
		if ((cmd->options.pic_mode != PIC_AVOID) && target->pic_flag) {
			push_count_chars(cmd->arglist, target->pic_flag);
		}
		if (cmd->output_name) {
			push_count_chars(cmd->arglist, "-o");
			push_count_chars(cmd->arglist, cmd->output_name);
		}
		break;

	case MODE_LINK:
		link_fixup(cmd);
		break;

	case MODE_INSTALL:
		if (cmd->output == OUT_LIB) {
			link_fixup(cmd);
		}
		break;

	default:
		break;
	}

	if (target->use_omf &&
	    ((cmd->output == OUT_OBJECT) ||
	     (cmd->output == OUT_PROGRAM) ||
	     (cmd->output == OUT_LIB) ||
	     (cmd->output == OUT_DYNAMIC_LIB_ONLY))) {
		push_count_chars(cmd->arglist, "-Zomf");
	}

	if (cmd->options.shared && target->share_sw &&
			(cmd->output == OUT_OBJECT ||
			 cmd->output == OUT_LIB ||
			 cmd->output == OUT_DYNAMIC_LIB_ONLY)) {
		push_count_chars(cmd->arglist, target->share_sw);
	}
}

static int run_mode(command_t *cmd)
{
	int rv = 0;
	count_chars *cctemp;

	cctemp = (count_chars*)lt_malloc(sizeof(count_chars));
	init_count_chars(cctemp);

	switch (cmd->mode) {
	case MODE_COMPILE:
		rv = run_command(cmd, cmd->arglist);
		if (rv) goto finish;
		break;
	case MODE_INSTALL:
		/* Well, we'll assume it's a file going to a directory... */
		/* For brain-dead install-sh based scripts, we have to repeat
		 * the command N-times.  install-sh should die.
		 */
		if (!cmd->output_name) {
			rv = run_command(cmd, cmd->arglist);
			if (rv) goto finish;
		}
		if (cmd->output_name) {
			append_count_chars(cctemp, cmd->arglist);
			insert_count_chars(cctemp,
							   cmd->output_name,
							   cctemp->num - 1);
			rv = run_command(cmd, cctemp);
			if (rv) goto finish;
			clear_count_chars(cctemp);
		}
		if (cmd->static_name.install) {
			append_count_chars(cctemp, cmd->arglist);
			insert_count_chars(cctemp,
							   cmd->static_name.install,
							   cctemp->num - 1);
			rv = run_command(cmd, cctemp);
			if (rv) goto finish;

			/* From the Apple libtool(1) manpage on Tiger/10.4:
			 * ----
			 * With  the way libraries used to be created, errors were possible
			 * if the library was modified with ar(1) and  the  table  of
			 * contents  was  not updated  by  rerunning ranlib(1).  Thus the
			 * link editor, ld, warns when the modification date of a library
			 * is more  recent  than  the  creation date  of its table of
			 * contents.  Unfortunately, this means that you get the warning
			 * even if you only copy the library.
			 * ----
			 *
			 * This means that when we install the static archive, we need to
			 * rerun ranlib afterwards.
			 */
			if (IS_TARGET(macos) && toolset->ranlib) {
				char const *lib_args[3], *static_lib_name;

				{
					char *tmp;
					size_t len1, len2;

					len1 = strlen(cmd->arglist->vals[cmd->arglist->num - 1]);

					static_lib_name = file_name(cmd->static_name.install);
					len2 = strlen(static_lib_name);

					tmp = lt_malloc(len1 + len2 + 2);

					snprintf(tmp, len1 + len2 + 2, "%s/%s",
							cmd->arglist->vals[cmd->arglist->num - 1],
							static_lib_name);

					lib_args[0] = toolset->ranlib;
					lib_args[1] = tmp;
					lib_args[2] = NULL;

					external_spawn(cmd, toolset->ranlib, lib_args);

					free(tmp);
				}
			}
			clear_count_chars(cctemp);
		}
		if (cmd->shared_name.install) {
			append_count_chars(cctemp, cmd->arglist);
			insert_count_chars(cctemp, cmd->shared_name.install,
					   cctemp->num - 1);
			rv = run_command(cmd, cctemp);
			if (rv) goto finish;
			clear_count_chars(cctemp);
		}
		if (cmd->module_name.install) {
			append_count_chars(cctemp, cmd->arglist);
			insert_count_chars(cctemp, cmd->module_name.install,
					   cctemp->num - 1);
			rv = run_command(cmd, cctemp);
			if (rv) goto finish;
			clear_count_chars(cctemp);
		}
		break;
	case MODE_LINK:
		if ((cmd->output == OUT_STATIC_LIB_ONLY) || (cmd->output == OUT_LIB)) {
			char const *lib_args[3];
			/* Removes compiler! */
			cmd->program = target->librarian;
			push_count_chars(cmd->program_opts, target->librarian_opts);
			push_count_chars(cmd->program_opts, cmd->static_name.normal);

			rv = run_command(cmd, cmd->obj_files);
			if (rv) goto finish;

			if (toolset->ranlib) {
				lib_args[0] = toolset->ranlib;
				lib_args[1] = cmd->static_name.normal;
				lib_args[2] = NULL;
				external_spawn(cmd, toolset->ranlib, lib_args);
			}
		}

		if ((cmd->output == OUT_DYNAMIC_LIB_ONLY) ||
		    (cmd->output == OUT_MODULE) ||
		    (cmd->output == OUT_LIB)) {
			cmd->program = NULL;
			clear_count_chars(cmd->program_opts);

			append_count_chars(cmd->program_opts, cmd->arglist);
			if (cmd->output == OUT_MODULE) {
				if (target->module_opts) {
					push_count_chars(cmd->program_opts, target->module_opts);
				}
			} else if (target->shared_opts){
				push_count_chars(cmd->program_opts, target->shared_opts);

				if (target->dynamic_link_version_func) {
					push_count_chars(cmd->program_opts,
						 	 target->dynamic_link_version_func(cmd->version_info));
				}
			}
			add_dynamic_link_opts(cmd, cmd->program_opts);

			rv = run_command(cmd, cmd->shared_opts.normal);
			if (rv) goto finish;
		}
		if (cmd->output == OUT_PROGRAM) {
			rv = run_command(cmd, cmd->arglist);
			if (rv) goto finish;
		}
		break;
	case MODE_EXECUTE:
	{
		char *l, libpath[PATH_MAX];

		if (!cmd->arglist->num) {
			ERROR("No command to execute.\n");
			rv = 1;

			goto finish;
		}

		/*
		 *	jlibtool is in $(BUILD_DIR)/make/jlibtool
		 */
		/* coverity[fixed_size_dest] */
		strcpy(libpath, program);

		/*
		 *	Libraries are relative to jlibtool, in
		 *	$(BUILD_DIR)/lib/local/.libs/
		 */
		l = strstr(libpath, "/make");
		if (l) strcpy(l, "/lib/local/.libs");

		setenv(target->ld_library_path, libpath, 1);
		setenv(target->ld_library_path_local, libpath, 1);
		setenv("FR_LIBRARY_PATH", libpath, 1);

		rv = run_command(cmd, cmd->arglist);
		if (rv) goto finish;
	}
		break;

	default:
		break;
	}

	finish:

	free(cctemp);
	return rv;
}

static void cleanup_tmp_dir(char const *dirname)
{
	DIR *dir;
	struct dirent *entry;
	char fullname[1024];

	dir = opendir(dirname);
	if (!dir) {
		return;
	}

	if ((strlen(dirname) + 1 + sizeof(entry->d_name)) >= sizeof(fullname)) {
		ERROR("Dirname too long, out of buffer space\n");

		(void) closedir(dir);
		return;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] != '.') {
			strcpy(fullname, dirname);
			strcat(fullname, "/");
			strcat(fullname, entry->d_name);
			(void) remove(fullname);
		}
	}

	rmdir(dirname);

	(void) closedir(dir);
}

static void cleanup_tmp_dirs(command_t *cmd)
{
	int d;

	for (d = 0; d < cmd->tmp_dirs->num; d++) {
		cleanup_tmp_dir(cmd->tmp_dirs->vals[d]);
	}
}

static int ensure_fake_uptodate(command_t *cmd)
{
	/* FIXME: could do the stat/touch here, but nah... */
	char const *touch_args[3];

	if (cmd->mode == MODE_INSTALL) {
		return 0;
	}
	if (!cmd->fake_output_name) {
		return 0;
	}

	touch_args[0] = "touch";
	touch_args[1] = cmd->fake_output_name;
	touch_args[2] = NULL;
	return external_spawn(cmd, "touch", touch_args);
}

/* Store the install path in the *.la file */
static int add_for_runtime(command_t *cmd)
{
	if (cmd->mode == MODE_INSTALL) {
		return 0;
	}
	if (cmd->output == OUT_DYNAMIC_LIB_ONLY ||
		cmd->output == OUT_LIB) {
		int i;
		FILE *f=fopen(cmd->fake_output_name,"w");
		char *lib_so = basename(UNCONST(char *, cmd->module_name.normal));
		count_chars *dep = cmd->shared_opts.dependencies;

		if (f == NULL) {
			return -1;
		}
		fprintf(f,"# Generated by jlibtool %s\n", VERSION);
		fprintf(f,"#\n");
		fprintf(f,"# Please DO NOT delete this file!\n");
		fprintf(f,"# It is necessary for linking the library.\n");
		fprintf(f,"\n");
		fprintf(f,"# The name that we can dlopen(3).\n");
		fprintf(f,"dlname='%s'\n", lib_so);
		fprintf(f,"\n");

		fprintf(f,"# Libraries that this one depends upon.\n");
		fprintf(f,"dependency_libs='");
		for (i = 0; i < dep->num; i++) {
			fprintf(f,"%s ", dep->vals[i]);
		}
		fprintf(f,"'\n\n");

		fprintf(f,"# Names of this library.\n");
		fprintf(f,"library_names='%s'\n", lib_so);
		fprintf(f,"\n");
		fprintf(f,"# Is this an already installed library?\n");
		fprintf(f,"installed=yes\n");
		fprintf(f,"\n");
		fprintf(f,"# Files to dlopen/dlpreopen\n");
		fprintf(f,"dlopen=''\n");
		fprintf(f,"dlpreopen=''\n");
		fprintf(f,"\n");
		fprintf(f,"# Directory that this library needs to be installed in:\n");
		fprintf(f,"libdir='%s'\n", cmd->install_path);
		fclose(f);

		return(0);
	} else {
		return(ensure_fake_uptodate(cmd));
	}
}

static void parse_args(int argc, char *argv[], command_t *cmd)
{
	int a;
	char const *arg, *base;
	int arg_used;

	/*
	 *	We now take a major step past libtool.
	 *
	 *	IF there's no "--mode=...", AND we recognise
	 *	the binary as a "special" name, THEN replace it
	 * 	with the correct one, and set the correct mode.
	 *
	 *	For example if were called 'CC' then we know we should
	 *	probably be compiling stuff.
	 */
	base = file_name(argv[0]);
	arg = automode(base, cmd);
	if (arg != base) {
		push_count_chars(cmd->arglist, arg);

		assert(cmd->mode != MODE_UNKNOWN);
	}

	/*
	 *	We first pass over the command-line arguments looking for
	 *	"--mode", etc.  If so, then use the libtool compatibility
	 *	method for building the software.  Otherwise, auto-detect it
	 * 	via "-o" and the extensions.
	 */
	base = NULL;
	if (cmd->mode == MODE_UNKNOWN) for (a = 1; a < argc; a++) {
		arg = argv[a];

		if (strncmp(arg, "--mode=", 7) == 0) {
			base = NULL;
			break;
		}

		/*
		 *	Stop if we get another magic method
		 */
		if ((a == 1) &&
		    ((strncmp(arg, "LINK", 4) == 0) ||
		     (strcmp(arg, "CC") == 0) ||
		     (strcmp(arg, "CXX") == 0))) {
			base = NULL;
			break;
		}

		if (strncmp(arg, "-o", 2) == 0) {
			base = argv[++a];
		}
	}

	/*
	 *	There were no magic args or an explicit --mode= but we did
	 *	find an output file, so guess what mode were meant to be in
	 *	from its extension.
	 */
	if (base) {
		arg = strrchr(base, '.');
		if (!arg) {
			cmd->mode = MODE_LINK;
			push_count_chars(cmd->arglist, toolset->link_c);
		}
		else if (target->exe_ext && (strcmp(arg, target->exe_ext) == 0)) {
			cmd->mode = MODE_LINK;
			push_count_chars(cmd->arglist, toolset->link_c);
		}
		else if (strcmp(arg + 1, target->dynamic_lib_ext) == 0) {
			cmd->mode = MODE_LINK;
			push_count_chars(cmd->arglist, toolset->link_c);
		}
		else if (strcmp(arg + 1, target->static_lib_ext) == 0) {
			cmd->mode = MODE_LINK;
			push_count_chars(cmd->arglist, toolset->link_c);
		}
		else if (strcmp(arg + 1, "la") == 0) {
			cmd->mode = MODE_LINK;
			push_count_chars(cmd->arglist, toolset->link_c);
		}
		else if ((strcmp(arg + 1, "lo") == 0) ||
			 (strcmp(arg + 1, "o") == 0)) {
			cmd->mode = MODE_COMPILE;
			push_count_chars(cmd->arglist, toolset->cc);
		}
	}

	for (a = 1; a < argc; a++) {
		arg = argv[a];
		arg_used = 1;

		if (cmd->mode == MODE_EXECUTE) {
			if (strchr(arg, ' ') == NULL) {
				push_count_chars(cmd->arglist, arg);

			} else {
				size_t len;
				char *sp;

				len = strlen(arg);

				sp = lt_malloc(len + 3);
				sp[0] = '\'';
				memcpy(sp + 1, arg, len);
				sp[len + 1] = '\'';
				sp[len + 2] = '\0';

				push_count_chars(cmd->arglist, sp);
			}

			continue;
		}

		if (arg[0] == '-') {
			/*
			 *	Double dashed (long) single dash (short)
			 */
			arg_used = (arg[1] == '-') ?
				parse_long_opt(arg + 2, cmd) :
				parse_short_opt(arg + 1, cmd);

			if (arg_used) continue;

			/*
			 *	Ignore all options after the '--execute'
			 */
			if (cmd->mode == MODE_EXECUTE) continue;

			/*
			 *	We haven't done anything with it yet, but
			 *	there are still some arg/value pairs.
			 *
			 *	Try some of the more complicated short opts...
			 */
			if (a + 1 < argc) {
				/*
				 *	We found an output file!
				 */
				if ((arg[1] == 'o') && (arg[2] == '\0')) {
					arg = argv[++a];
					arg_used = parse_output_file_name(arg,
									  cmd);
				/*
				 *	-MT literal dependency
				 */
				} else if (!strcmp(arg + 1, "MT")) {
					DEBUG("Adding: %s\n", arg);

					push_count_chars(cmd->arglist, arg);
					arg = argv[++a];

					DEBUG("Adding: %s\n", arg);

					push_count_chars(cmd->arglist, arg);
					arg_used = 1;
				/*
				 *	Runtime library search path
				 */
				} else if (!strcmp(arg + 1, "rpath")) {
					/* Aha, we should try to link both! */
					cmd->install_path = argv[++a];
					arg_used = 1;

				} else if (!strcmp(arg + 1, "release")) {
					/* Store for later deciphering */
					cmd->version_info = argv[++a];
					arg_used = 1;

				} else if (!strcmp(arg + 1, "version-info")) {
					/* Store for later deciphering */
					cmd->version_info = argv[++a];
					arg_used = 1;

				} else if (!strcmp(arg + 1,
						   "export-symbols-regex")) {
					/* Skip the argument. */
					++a;
					arg_used = 1;

				} else if (!strcmp(arg + 1, "undefined")) {
					cmd->undefined_flag = argv[++a];
					arg_used = 1;
				/*
				 *	Add dir to runtime library search path.
				 */
				} else if ((arg[1] == 'R') && !arg[2]) {

					add_runtime_dir_lib(argv[++a], cmd);
					arg_used = 1;
				}
			}
		/*
		 *	Ok.. the argument doesn't begin with a dash
		 *	maybe it's an input file.
		 *
		 *	Check its extension to see if it's a known input
		 *	file and verify it exists.
		 */
		} else {
			arg_used = parse_input_file_name(arg, cmd);
		}

		/*
		 *	If we still don't have a run mode, look for a magic
		 *	program name CC, LINK, or whatever.  Then replace that
		 *	with the name of the real program we want to run.
		 */
		if (!arg_used) {
			if ((cmd->arglist->num == 0) &&
				(cmd->mode == MODE_UNKNOWN)) {
				arg = automode(arg, cmd);
			}

			DEBUG("Adding: %s\n", arg);

			push_count_chars(cmd->arglist, arg);
		}
	}

}

int main(int argc, char *argv[])
{
	int rc;
	command_t cmd;

	program = argv[0];
	memset(&cmd, 0, sizeof(cmd));

	cmd.options.pic_mode = PIC_UNKNOWN;
	cmd.mode = MODE_UNKNOWN;
	cmd.output = OUT_GENERAL;

	/*
	 *	Initialise the various argument lists
	 */
	cmd.program_opts		= alloc_countchars();
	cmd.arglist			= alloc_countchars();
	cmd.tmp_dirs 			= alloc_countchars();
	cmd.obj_files			= alloc_countchars();
	cmd.dep_rpaths 			= alloc_countchars();
	cmd.rpaths			= alloc_countchars();
	cmd.static_opts.normal		= alloc_countchars();
	cmd.shared_opts.normal		= alloc_countchars();
	cmd.shared_opts.dependencies	= alloc_countchars();

	/*
	 *	Fill up the various argument lists
	 */
	parse_args(argc, argv, &cmd);
	post_parse_fixup(&cmd);

	/*
	 *	We couldn't figure out which mode to operate in
	 */
	if (cmd.mode == MODE_UNKNOWN) {
		usage(1);
	}

	rc = run_mode(&cmd);
	if (!rc) {
		add_for_runtime(&cmd);
	}

	cleanup_tmp_dirs(&cmd);

	return rc;
}
