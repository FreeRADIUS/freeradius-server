dnl #
dnl #  Look for a header file in a number of places.
dnl #
dnl #  Usage:  FR_CHECK_STRUCT_HAS_MEMBER([#include <foo.h>], [struct foo], member)
dnl #  If the member is defined, then the variable
dnl #     ac_cv_type_struct_foo_has_member is set to 'yes'
dnl #
AC_DEFUN([FR_CHECK_STRUCT_HAS_MEMBER], [
  AC_MSG_CHECKING([for $3 in $2])

dnl BASED on 'offsetof':
dnl #define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
dnl

  AC_TRY_COMPILE([
$1
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((int) &((TYPE *)0)->MEMBER)
#endif
],
                 [ int foo = offsetof($2, $3) ],
                 has_element=" ",
                 has_element=)

  ac_safe_type=`echo "$2" | sed 'y% %_%'`
  if test "x$has_element" != "x"; then
    AC_MSG_RESULT(yes)
    eval "ac_cv_type_${ac_safe_type}_has_$3=yes"
  else
    AC_MSG_RESULT(no)
    eval "ac_cv_type_${ac_safe_type}_has_$3="
 fi
])
