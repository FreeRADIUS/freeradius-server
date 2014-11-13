AC_PREREQ([2.53])
AC_INIT(rlm_cache.c)
AC_REVISION($Revision$)
AC_DEFUN(modname,[rlm_cache])

fail=
SMART_LIBS=
SMART_CLFAGS=
if test x$with_[]modname != xno; then

	AC_PROG_CC

	mysubdirs=
	if test "x$EXPERIMENTAL" = "xyes"; then
	  for foo in `find ./drivers -name configure -print`; do
	    bar=`echo $foo | sed 's%/configure$%%g'`
	    mysubdirs="$mysubdirs $bar"
	  done
	else
	  for foo in `cat stable`; do
	    mysubdirs="$mysubdirs ./drivers/$foo"
	  done
	fi

	dnl # don't ask... this is done to avoid autoconf stupidities.
	ln -s ../../../install-sh install-sh

	dnl #
	dnl #  Don't change the variable name here.  Autoconf goes bonkers
	dnl #  if you do.
	dnl #
	AC_CONFIG_SUBDIRS($mysubdirs)
	rm install-sh

	dnl #
	dnl # Don't bother looking for errors in the child directories
	dnl #

	targetname=modname
else
	targetname=
	echo \*\*\* module modname is disabled.
fi

AC_SUBST(targetname)
AC_OUTPUT(all.mk)
