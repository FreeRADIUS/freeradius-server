AC_DEFUN([FR_STATUS_FILE], [config.info])

dnl
dnl Store status about module configure state.
dnl
dnl Usage:
dnl   FR_MODULE_STATUS([status])
dnl   FR_MODULE_STATUS([status], [reason])
dnl
dnl First argument is the status to report, likely "OK",
dnl "skipping" or "disabled".
dnl
dnl Second optional argument is the reason for skipping this
dnl module (likely dependencies not met).
dnl
AC_DEFUN([FR_MODULE_STATUS],[
ifelse([$2], [], [
fr_status="$1"
], [
fr_status="$1 ($2)"
])])


dnl
dnl FR_MODULE_START_TESTS
dnl
dnl Usage:
dnl   FR_MODULE_START_TESTS
dnl
dnl Set up ready to do module-specific tests. Clears variables and
dnl adds code to output a header before the tests to make the
dnl configure output easier to read.
dnl
AC_DEFUN([FR_MODULE_START_TESTS],
[
fail=
fr_status=

m4_divert_text([SHELL_FN], [
echo
echo Running tests for modname
echo
])

if test x"$with_[]modname" != xno; then
])


dnl
dnl FR_MODULE_END_TESTS
dnl
dnl Usage:
dnl   FR_MODULE_END_TESTS
dnl   FR_MODULE_END_TESTS([nostrict])
dnl
dnl If passed "nostrict", checks will be made for the
dnl enable_strict_dependencies flag.
dnl
dnl Called at the end of module-specific tests. This outputs
dnl information on whether the module is disabled or not, or why
dnl configuration failed. It also stores the status for a summary
dnl to be printed at the end of the main configure script.
dnl
AC_DEFUN([FR_MODULE_END_TESTS], [
	targetname=modname
else
	targetname=
	echo \*\*\* module modname is disabled.
	FR_MODULE_STATUS([disabled])
fi

if test x"$fail" != x""; then
	targetname=""

ifelse([$1], [nostrict], [], [
	if test x"${enable_strict_dependencies}" = x"yes"; then
		AC_MSG_ERROR([set --without-]modname[ to disable it explicitly.])
	else
])
		AC_MSG_WARN([silently not building ]modname[.])
		AC_MSG_WARN([FAILURE: ]modname[ requires: $fail.]);
		fail="$(echo $fail)"
		FR_MODULE_STATUS([skipping], [requires $fail])
ifelse([$1], [nostrict], [], [
	fi
])
else
	FR_MODULE_STATUS([OK])
fi

echo "$fr_status" > FR_STATUS_FILE

AC_SUBST(targetname)
])


dnl
dnl FR_MODULE_TEST_FAIL_DO
dnl
dnl Usage:
dnl   FR_MODULE_TEST_FAIL_DO([commands])
dnl
dnl Run commands when the module tests fail and the module is not
dnl going to be built.
dnl
AC_DEFUN([FR_MODULE_TEST_FAIL_DO], [
if test x"$fail" != x""; then :
	$1
fi
])

dnl
dnl FR_MODULE_TEST_PASS_DO
dnl
dnl Usage:
dnl   FR_MODULE_TEST_PASS_DO([commands])
dnl
dnl Run commands when the module tests succeed and the module is
dnl going to be built.
dnl
AC_DEFUN([FR_MODULE_TEST_PASS_DO], [
if test x"$fail" = x""; then :
	$1
fi
])


dnl
dnl FR_MODULE_REPORT
dnl
dnl Usage:
dnl   FR_MODULE_REPORT
dnl
dnl Outputs a summary list of all modules and any configure errors.
dnl
AC_DEFUN([FR_MODULE_REPORT], [
module_list=$(find src/modules/ -type d -name 'rlm_*' -print | sort)

echo
echo Module configure status report
echo ------------------------------

for module in $module_list; do
  module_name="$(basename $module)"
  module_print="$(echo "$module_name ........................" | cut -c 1-25)"
  module_status="OK"

  if test -r $module/configure.ac; then
    if test -r $module/FR_STATUS_FILE; then
      module_status=$(head -1 $module/FR_STATUS_FILE)
    fi
  fi

  echo "$module_print $module_status"
done
])
