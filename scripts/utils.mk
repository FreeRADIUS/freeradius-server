#
#  scripts/utils.mk - shared make helpers that are useful outside boilermake.
#
#  The package test (scripts/ci/package-test.mk) drives the test makefiles
#  against an installed server with no build tree, so it never includes
#  scripts/boiler.mk.  Helpers it needs live here, where both boiler.mk and the
#  test makefiles can reach the one definition.
#

# QUALIFY_PATH - Given a "root" directory and one or more paths, qualifies the
#   paths using the "root" directory (i.e. appends the root directory name to
#   the paths) except for paths that are absolute.
define QUALIFY_PATH
$(addprefix ${1}/,$(filter-out /%,${2})) $(filter /%,${2})
endef

# SHELL_QUOTE - Parameterized "function" that quotes a value so that it
#   reaches the shell as a single word.
define SHELL_QUOTE
'$(subst ','\'',${1})'
endef
