dnl #
dnl #  Look for a header file in a number of places.
dnl #
dnl #  FR_SMART_CHECK_INCLUDE(foo.h, [ #include <other.h> ])
dnl #
AC_DEFUN([FR_SMART_CHECK_INCLUDE], [

ac_safe=`echo "$1" | sed 'y%./+-%__pm%'`
old_CPPFLAGS="$CPPFLAGS"
smart_include=
dnl #  The default directories we search in (in addition to the compilers search path)
smart_include_dir="/usr/local/include /opt/include"

dnl #  Our local versions
_smart_try_dir=
_smart_include_dir=

dnl #  Add variants with the different prefixes and one with no prefix
for _prefix in $smart_prefix ""; do
  for _dir in $smart_try_dir; do
    _smart_try_dir="${_smart_try_dir} ${_dir}/${_prefix}"
  done

  for _dir in $smart_include_dir; do
    _smart_include_dir="${_smart_include_dir} ${_dir}/${_prefix}"
  done
done

dnl #
dnl #  Try any user-specified directory first otherwise we may pick up
dnl #  the wrong version.
dnl #
if test "x$_smart_try_dir" != "x"; then
  for try in $_smart_try_dir; do
    AC_MSG_CHECKING([for $1 in $try])
    CPPFLAGS="-isystem $try $old_CPPFLAGS"
    AC_TRY_COMPILE([$2
		    #include <$1>],
		   [int a = 1;],
		   [
		     smart_include="-isystem $try"
		     AC_MSG_RESULT(yes)
		     break
		   ],
		   [
		     smart_include=
		     AC_MSG_RESULT(no)
		   ])
  done
  CPPFLAGS="$old_CPPFLAGS"
fi

dnl #
dnl #  Try using the default includes (with prefixes).
dnl #
if test "x$smart_include" = "x"; then
  for _prefix in $smart_prefix; do
    AC_MSG_CHECKING([for ${_prefix}/$1])

    AC_TRY_COMPILE([$2
		    #include <$1>],
		   [int a = 1;],
		   [
		     smart_include="-isystem ${_prefix}/"
		     AC_MSG_RESULT(yes)
		     break
		   ],
		   [
		     smart_include=
		     AC_MSG_RESULT(no)
		   ])
  done
fi

dnl #
dnl #  Try using the default includes (without prefixes).
dnl #
if test "x$smart_include" = "x"; then
    AC_MSG_CHECKING([for $1])

    AC_TRY_COMPILE([$2
		    #include <$1>],
		   [int a = 1;],
		   [
		     smart_include=" "
		     AC_MSG_RESULT(yes)
		     break
		   ],
		   [
		     smart_include=
		     AC_MSG_RESULT(no)
		   ])
fi

dnl #
dnl #  Try to guess possible locations.
dnl #
if test "x$smart_include" = "x"; then

  for try in $_smart_include_dir; do
    AC_MSG_CHECKING([for $1 in $try])
    CPPFLAGS="-isystem $try $old_CPPFLAGS"
    AC_TRY_COMPILE([$2
		    #include <$1>],
		   [int a = 1;],
		   [
		     smart_include="-isystem $try"
		     AC_MSG_RESULT(yes)
		     break
		   ],
		   [
		     smart_include=
		     AC_MSG_RESULT(no)
		   ])
  done
  CPPFLAGS="$old_CPPFLAGS"
fi

dnl #
dnl #  Found it, set the appropriate variable.
dnl #
if test "x$smart_include" != "x"; then
  eval "ac_cv_header_$ac_safe=yes"
  CPPFLAGS="$smart_include $old_CPPFLAGS"
  SMART_CPPFLAGS="$smart_include $SMART_CPPFLAGS"
fi

dnl #
dnl #  Consume prefix, it's not likely to be used
dnl #  between multiple calls.
dnl #
smart_prefix=
])
