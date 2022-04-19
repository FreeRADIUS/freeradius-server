dnl #
dnl #  Figure out which storage class specifier for Thread Local Storage is supported by the compiler
dnl #
AC_DEFUN([AX_THREAD_LOCAL_SUPPORT],
[
dnl #
dnl #  _Thread_local does exactly the same thing as __thread, but it's standards compliant with C11.
dnl #
  AC_MSG_CHECKING(for _Thread_local support in compiler)
  AC_COMPILE_IFELSE(
    [AC_LANG_SOURCE(
      [[
        static _Thread_local int val;
        int main(int argc, char **argv) {
          val = 0;
          return val;
        }
      ]])
    ],[have_tls=yes],[have_tls=no])
  AC_MSG_RESULT($have_tls)
  if test "x$have_tls" = "xyes"; then
    AC_DEFINE([TLS_STORAGE_CLASS],[_Thread_local],[Define if the compiler supports a thread local storage class])
  fi

dnl #
dnl #  __declspec(thread) does exactly the same thing as __thread, but is supported by MSVS
dnl #
if test "x$have_tls" = "xno"; then
  AC_MSG_CHECKING(for __declspec(thread) support in compiler)
  AC_COMPILE_IFELSE(
    [AC_LANG_SOURCE(
      [[
        static _Thread_local int val;
        int main(int argc, char **argv) {
          val = 0;
          return val;
        }
      ]])
    ],[have_tls=yes],[have_tls=no])
  AC_MSG_RESULT($have_tls)
  if test "x$have_tls" = "xyes"; then
    AC_DEFINE([TLS_STORAGE_CLASS],[__declspec(thread)],[Define if the compiler supports a thread local storage class])
  fi
fi
dnl #
dnl #  See if the compilation works with __thread, for thread-local storage
dnl #  This is used by earlier versions of GCC and clang.
dnl #
if test "x$have_tls" = "xno"; then
  AC_MSG_CHECKING(for __thread support in compiler)
  AC_COMPILE_IFELSE(
    [AC_LANG_SOURCE(
      [[
        static __thread int val;
        int main(int argc, char **argv) {
          val = 0;
          return val;
        }
      ]])
    ],[have_tls=yes],[have_tls=no])
  AC_MSG_RESULT($have_tls)
  if test "x$have_tls" = "xyes"; then
    AC_DEFINE([TLS_STORAGE_CLASS],[__thread],[Define if the compiler supports a thread local storage class])
  fi
fi
])
