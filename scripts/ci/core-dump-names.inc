#
#  Core dump name patterns. Sourced, not run: no shebang, not executable.
#
#  Shared by collect-core-dumps.sh, which keeps cores, and
#  publish-profiling-results.sh, which drops them, so the two can never
#  disagree about what a core file looks like.
#
#  The patterns expect a "/" before the basename, which every "find" result
#  under a root has. Basenames covered: "core", "core.<pid>", "<name>.core",
#  "<name>.core.<pid>", and valgrind's "vgcore.<pid>".
#
#  One pattern per line rather than the equivalent single expression
#  "/([^/]*\.)?(vg)?core(\.[^/]+)?$". That compact form is valid ERE and works
#  under GNU and BSD grep, but ugrep matches nothing against it and says
#  nothing about why. A silent miss here either leaks gigabyte cores into a
#  publish or throws away the only evidence of a crash.
#
core_dump_re='/core$
/core\.[^/]+$
/[^/]*\.core$
/[^/]*\.core\.[^/]+$
/vgcore\.[^/]+$'
