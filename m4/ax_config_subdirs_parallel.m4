dnl #
dnl #  Configure the AC_CONFIG_SUBDIRS subdirectories concurrently.
dnl #
dnl #  Autoconf runs the sub-configure scripts one after another. No
dnl #  sub-configure script depends on another, and there are enough
dnl #  sub-configure scripts that most of a configure run is spent waiting on
dnl #  the serial loop. Passing the same work to xargs -P cuts the wait to
dnl #  roughly the time of the slowest single sub-configure script.
dnl #
dnl #  AX_CONFIG_SUBDIRS_PARALLEL redefines autoconf's own
dnl #  _AC_OUTPUT_SUBDIRS. _AC_OUTPUT_SUBDIRS is m4_define'd rather than
dnl #  AC_DEFUN'd, so a redefinition here replaces _AC_OUTPUT_SUBDIRS for one
dnl #  configure only, and autoconf's installed copy is left alone. AC_OUTPUT
dnl #  calls whatever definition is current at expansion time, so
dnl #  AX_CONFIG_SUBDIRS_PARALLEL must be called before AC_OUTPUT.
dnl #
dnl #  The code below handles arguments, derives paths and rewrites the cache
dnl #  file name the same way autoconf does, and calls the same macros
dnl #  (_AC_SRCDIRS, AS_MKDIR_P) rather than copying each macro's expansion, so
dnl #  a newer autoconf that changes how srcdir paths are derived changes the
dnl #  behaviour here too.
dnl #
dnl #  Diffing the loop below against status.m4 is how a new autoconf gets
dnl #  checked for changes, so three of the comments in the loop are
dnl #  autoconf's own, copied word for word: the "CONFIG_SUBDIRS section"
dnl #  banner, "Do not complain" above the directory test, and "Check for
dnl #  configure.gnu first" above the AS_IF. Leave those three as autoconf
dnl #  wrote them. Every other comment here is ours.
dnl #
dnl #  _AC_OUTPUT_SUBDIRS runs every sub-configure script in the one shell that
dnl #  is running the parent configure, cd'ing into each directory and back out
dnl #  again in turn. Concurrent jobs cannot share one shell's working
dnl #  directory, so here xargs starts a shell per subdirectory instead. Two
dnl #  things follow from the separate shells:
dnl #
dnl #    - each subdirectory's command goes into a job script of its own, so
dnl #      the shell xargs starts has everything needed to cd and run the
dnl #      sub-configure script without reading anything from the parent shell.
dnl #
dnl #    - we report a failure after every job script has finished rather than
dnl #      at the first failure. With job scripts running at the same time
dnl #      there is no "first" failure to stop at, and stopping partway through
dnl #      leaves a half-configured tree, which is worse to debug than a fully
dnl #      configured one.
dnl #
dnl #  Set AX_SUBCONF_JOBS to change how many sub-configure scripts run
dnl #  at once. The default is the core count, and 1 restores serial behaviour,
dnl #  which is the first thing to try when a sub-configure script fails and
dnl #  running several at once is a suspect.
dnl #
dnl #  A sub-configure script can be passed extra arguments by setting
dnl #  ax_subconf_args_<dir with / and - replaced by _>, for example:
dnl #
dnl #    ax_subconf_args_src_lib_backtrace="--enable-host-shared"
dnl #
dnl #  which is how we tell libbacktrace the objects are going into a shared
dnl #  library. Autoconf has no way to vary arguments per subdirectory, because
dnl #  AC_CONFIG_SUBDIRS passes one argument list to every sub-configure
dnl #  script.
dnl #
dnl #  Usage, anywhere in configure.ac ahead of AC_OUTPUT:
dnl #
dnl #    AX_CONFIG_SUBDIRS_PARALLEL
dnl #
dnl #  aclocal pulls in m4/*.m4 by matching AC_DEFUN'd names against the macros
dnl #  configure.ac calls, and skips any file defining a name with m4_define
dnl #  alone. The AC_DEFUN wrapper is what gets this file collected.
dnl #
dnl #  Keep autoconf's definition under a second name before replacing
dnl #  _AC_OUTPUT_SUBDIRS, so the replacement can still call autoconf's
dnl #  definition for the argument handling.
dnl #
m4_copy([_AC_OUTPUT_SUBDIRS], [_AX_ORIG_OUTPUT_SUBDIRS])

AC_DEFUN([AX_CONFIG_SUBDIRS_PARALLEL],
[m4_define([_AC_OUTPUT_SUBDIRS],
[
#
# CONFIG_SUBDIRS section.
#
if test "$no_recursion" != yes; then

  dnl #
  dnl #  The replacement calls autoconf's own argument handling rather than
  dnl #  keeping a copy of the same code. _AC_OUTPUT_SUBDIRS strips
  dnl #  --cache-file, --srcdir and --prefix out of $ac_configure_args, re-adds
  dnl #  --prefix and --disable-option-checking, and leaves the result in
  dnl #  $ac_sub_configure_args.
  dnl #
  dnl #  Those option patterns list every abbreviation a user might type, down
  dnl #  to --c for --cache-file, and autoconf maintains the patterns by hand in
  dnl #  two places already. A third copy here would go stale the first time
  dnl #  upstream adds an option, and nothing would report the staleness.
  dnl #
  dnl #  We empty $subdirs before calling _AC_OUTPUT_SUBDIRS so only the
  dnl #  argument computation happens. The loop inside reads
  dnl #  "for ac_dir in : $subdirs" and skips the : sentinel, so an empty
  dnl #  $subdirs configures nothing. Do not remove the "subdirs=" line: every
  dnl #  subdirectory would then be configured twice, serially the first time.
  dnl #
  ax_subconfs_deferred=$subdirs
  subdirs=
  _AX_ORIG_OUTPUT_SUBDIRS
  subdirs=$ax_subconfs_deferred

  #
  #  Only the parent shell has $srcdir and $ac_pwd, so we derive every
  #  subdirectory's paths here rather than inside the job script that runs the
  #  sub-configure script. The result is one job script per subdirectory, each
  #  holding a complete command that xargs can run.
  #
  #  Each job script gets a number, counting up in the order $subdirs lists
  #  the subdirectories, so the captured output can print in that order rather
  #  than in whatever order the job scripts happen to finish.
  #
  ax_subconf_logs=`pwd`/config-subconfs.logs
  rm -rf "$ax_subconf_logs"
  AS_MKDIR_P(["$ax_subconf_logs"])

  ax_subconf_jobs=$ax_subconf_logs/jobs
  ax_subconf_manifest=$ax_subconf_logs/manifest
  : > "$ax_subconf_jobs"
  : > "$ax_subconf_manifest"
  ax_subconf_n=0
  ax_subconf_seen=

  ac_popdir=`pwd`
  for ac_dir in : $subdirs; do test "x$ac_dir" = x: && continue

    # Do not complain, so a configure script can configure whichever
    # parts of a large source tree are present.
    test -d "$srcdir/$ac_dir" || continue

    #
    #  Two sub-configure scripts running in the same directory at the same
    #  time delete each other's conftest files, and AC_PROG_CC reports the
    #  wreckage as "C compiler cannot create executables", so a directory
    #  named twice in $subdirs is configured once. Autoconf tolerates the
    #  repeat because autoconf runs the sub-configure scripts one after
    #  another, and $MODULES does repeat a module when the same
    #  --with-modules name is given twice.
    #
    #  ./src/lib/curl and src/lib/curl are the same directory, so the leading
    #  ./ comes off before the comparison. The stripped name is also what the
    #  ax_subconf_args_ lookup below is keyed on.
    #
    ax_subconf_dir=`AS_ECHO(["$ac_dir"]) | sed -e 's|^\./||' -e 's|^/||'`
    AS_CASE([" $ax_subconf_seen "],
	    [*" $ax_subconf_dir "*], [continue])
    ax_subconf_seen="$ax_subconf_seen $ax_subconf_dir"

    AS_VAR_ARITH([ax_subconf_n], [$ax_subconf_n + 1])
    ax_subconf_id=$ax_subconf_n

    AS_MKDIR_P(["$ac_dir"])
    _AC_SRCDIRS(["$ac_dir"])

    # Check for configure.gnu first; this name is used for a wrapper for
    # Metaconfig's "Configure" on case-insensitive file systems.
    AS_IF([test -f "$srcdir/$ac_dir/configure.gnu"],
	  [ax_sub_configure=configure.gnu],
	  [test -f "$srcdir/$ac_dir/configure"],
	  [ax_sub_configure=configure],
	  [AC_MSG_WARN([no configuration information is in $ac_dir])
	   continue])

    #
    #  Concurrent sub-configure scripts sharing one cache file read and write
    #  the file at the same time and corrupt each other's entries, so each
    #  sub-configure script gets a copy of the top-level cache to itself.
    #  Autoconf points every subdirectory at the one top-level cache file,
    #  which is safe only because autoconf runs the sub-configure scripts one
    #  after another. GCC's top-level Makefile carries the same warning: "Host
    #  configures don't work well in parallel to each other, due to contention
    #  over config.cache".
    #
    #  The copies sit with the logs and go when the logs go, so no cache file
    #  outlives the configure run that wrote the cache file. A copy left in a
    #  subdirectory would be picked up by the next run, and a run with
    #  different CFLAGS then stops with "`CFLAGS' has changed since the
    #  previous run". Nothing else in the tree knows to delete a cache file in
    #  a subdirectory, so leaving one there breaks the next build.
    #
    #  Reading is where the saving is anyway: the top-level cache already
    #  holds the compiler and header answers every sub-configure script would
    #  otherwise work out again. The answers a sub-configure script adds are
    #  dropped, so the top-level cache stays exactly as the top-level
    #  configure left the top-level cache.
    #
    #  /dev/null is the default and means no cache at all.
    #
    AS_CASE([$cache_file],
	    [/dev/null], [ac_sub_cache_file=/dev/null],
	    [ac_sub_cache_file=$ax_subconf_logs/$ax_subconf_id.cache
	     AS_IF([test -f "$cache_file"],
		   [cp "$cache_file" "$ac_sub_cache_file"])])

    #
    #  The extra arguments for a sub-configure script come from a shell
    #  variable named after the directory, with the characters a shell variable
    #  name cannot contain replaced by underscores.
    #
    #  The key is built from the stripped name, because mysubdirs is built by
    #  find(1) over $srcdir and an in-tree build yields ./src/lib/backtrace. A
    #  leading ./ left in place looks for ax_subconf_args_._src_lib_backtrace,
    #  which nobody would think to set.
    #
    ax_subconf_key=`AS_ECHO(["$ax_subconf_dir"]) | sed 's|[[/.-]]|_|g'`
    eval "ax_subconf_extra=\${ax_subconf_args_$ax_subconf_key:-}"

    ax_subconf_cmd="\$SHELL '$ac_srcdir/$ax_sub_configure' $ac_sub_configure_args $ax_subconf_extra --cache-file='$ac_sub_cache_file' --srcdir='$ac_srcdir'"

    #
    #  The manifest holds one line per subdirectory, in the order $subdirs
    #  lists the subdirectories, carrying what _AC_OUTPUT_SUBDIRS printed
    #  before running each sub-configure script.
    #
    AS_ECHO(["$ax_subconf_id	$ac_dir	$ax_subconf_cmd"]) >> "$ax_subconf_manifest"

    #
    #  Each subdirectory gets a job script of its own holding the whole
    #  command, redirect and failure marker included, so xargs only has to run
    #  $SHELL on the job script. Splitting a command back apart inside the job
    #  script is one quoting mistake away from writing the log somewhere nobody
    #  looks.
    #
    #  Passing the command through xargs -I instead is not portable: the BSD
    #  xargs on macOS caps a replacement at 255 bytes and refuses a configure
    #  line with "command line cannot be assembled, too long".
    #
    AS_ECHO(["cd '$ac_popdir/$ac_dir' && $ax_subconf_cmd > '$ax_subconf_logs/$ax_subconf_id.log' 2>&1 || { : > '$ax_subconf_logs/$ax_subconf_id.failed'; exit 1; }"]) > "$ax_subconf_logs/$ax_subconf_id.sh"
    AS_ECHO(["$ax_subconf_logs/$ax_subconf_id.sh"]) >> "$ax_subconf_jobs"
  done

  AS_IF([test "$ax_subconf_n" -gt 0], [
    #
    #  No POSIX utility reports the core count. The order below comes from
    #  AX_COUNT_CPUS in the autoconf archive, minus the branches that read
    #  $host_os: rlm_sql and rlm_cache ship no config.guess, so
    #  AC_CANONICAL_HOST is not available in every configure that calls this
    #  macro.
    #
    #  POSIX spells the getconf name NPROCESSORS_ONLN while Linux and macOS
    #  want _NPROCESSORS_ONLN, so try both. nproc is GNU coreutils. sysctl
    #  hw.ncpu answers on the BSDs. One at a time is the safe last resort:
    #  slower, never wrong.
    #
    AS_IF([test -z "$AX_SUBCONF_JOBS"],
	  [AX_SUBCONF_JOBS=`getconf _NPROCESSORS_ONLN 2>/dev/null \
	     || getconf NPROCESSORS_ONLN 2>/dev/null \
	     || nproc 2>/dev/null \
	     || sysctl -n hw.ncpu 2>/dev/null`
	   AS_IF([test "$AX_SUBCONF_JOBS" -gt 0 2>/dev/null],
		 [], [AX_SUBCONF_JOBS=1])])

    AC_MSG_NOTICE([calling $ax_subconf_n sub-configure scripts, $AX_SUBCONF_JOBS at a time])

    #
    #  xargs runs the job scripts. Each job script writes one sub-configure
    #  script's output to a numbered log; nothing reaches the terminal while
    #  the job scripts are running, because interleaved output is unreadable.
    #
    ax_subconf_rc=0
    dnl #
    dnl #  The BSD xargs on macOS has no -a option, so we pass the job script
    dnl #  list on stdin. -n1 passes one job script path to each shell
    dnl #  invocation, which every xargs understands.
    dnl #
    xargs -n1 -P "$AX_SUBCONF_JOBS" \
      $SHELL < "$ax_subconf_jobs" || ax_subconf_rc=$?

    #
    #  The loop below walks the manifest, so the logs print in the order
    #  $subdirs lists the subdirectories rather than the order the job scripts
    #  finished. The transcript then matches what _AC_OUTPUT_SUBDIRS would have
    #  written running one sub-configure script after another: the same header,
    #  the same "running" notice, then the sub-configure script's output. The
    #  loop prints to stdout for the person watching and to config.log for
    #  afterwards.
    #
    while IFS="	" read ax_id ax_dir ax_cmd; do
      ax_msg="=== configuring in $ax_dir (`pwd`/$ax_dir)"
      _AS_ECHO_LOG([$ax_msg])
      _AS_ECHO([$ax_msg])
      AC_MSG_NOTICE([running $ax_cmd])
      AS_IF([test -f "$ax_subconf_logs/$ax_id.log"],
	    [cat "$ax_subconf_logs/$ax_id.log"
	     cat "$ax_subconf_logs/$ax_id.log" >&AS_MESSAGE_LOG_FD])
      AS_IF([test -f "$ax_subconf_logs/$ax_id.failed"],
	    [AC_MSG_NOTICE([sub-configure script failed for $ax_dir])])
    done < "$ax_subconf_manifest"

    AS_IF([test "$ax_subconf_rc" -ne 0],
	  [AC_MSG_ERROR([one or more sub-configure scripts failed, see above])])

    rm -rf "$ax_subconf_logs"
  ])
fi
])])dnl # AX_CONFIG_SUBDIRS_PARALLEL
