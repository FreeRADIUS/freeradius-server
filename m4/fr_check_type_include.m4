dnl #
dnl # FR_CHECK_TYPE_INCLUDE([#includes ...], type, default-C-types)
dnl #
dnl # This function is like AC_CHECK_TYPE, but you can give this one
dnl # a list of include files to check.
dnl #
AC_DEFUN([FR_CHECK_TYPE_INCLUDE],
[
  AC_CACHE_CHECK(for $2, ac_cv_type_$2,
    [ ac_cv_type_$2=no
      AC_TRY_COMPILE($1,
        [$2 foo],
        ac_cv_type_$2=yes,
      )
    ]
  )

  if test "$ac_cv_type_$2" != "yes"; then
         AC_DEFINE($2, $3, $4)
  fi
])
