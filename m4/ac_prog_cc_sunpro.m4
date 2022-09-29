dnl Checks to see if this is SUNPro we're building with
dnl Usage:
dnl
dnl   AC_PROG_CC_SUNPRO
dnl
AC_DEFUN([AC_PROG_CC_SUNPRO],
[AC_CACHE_CHECK(whether we are using SUNPro C, ac_cv_prog_suncc,
[dnl The semicolon is to pacify NeXT's syntax-checking cpp.
cat > conftest.c <<EOF
#ifdef __SUNPRO_C
yes;
#endif
EOF
if AC_TRY_COMMAND(${CC-cc} -E conftest.c) | egrep yes >/dev/null 2>&1; then
ac_cv_prog_suncc=yes
else
ac_cv_prog_suncc=no
fi])])
