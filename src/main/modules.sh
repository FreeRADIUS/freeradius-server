#!/bin/sh
OUTPUT=static_modules.h
INPUT=../raddb/modules

rm -f $OUTPUT

#######################################################################
#
#  Make static_modules.h from ../raddb/modules
#
#  This process is a little complicated.
#
#  We're trying to build a C header file, which defines a static
# structure, from the ../raddb/modules configuration file.  We want
# to include ONLY the modules which are being built, and ignore the others.
#  
#######################################################################


#######################################################################
#
#  Root through ../raddb/modules:
#
#  Remove comments
#
#  Remove blank lines (by looking for NON-blank lines)
#
#  Remove '.so' trailers from the module config file
# also, replace the FIRST '../' with '/', the FIRST './' with '/',
# and the delete from the FIRST '/' to the LAST '/', which is followed
# by an 'rlm'.
#
#  The last sed rule is a bit iffy... It requires ALL modules to begin
# with rlm, and there to be NO module configuration parameters containing
# the string '/rlm'.  It's rare, so I guess we're safe.
#
#  Look for pre-build rlm_foo.o files.  ONLY include the ones we're told
# too use, and ignore the rlm_bar.so's in ../raddb/modules which are
# there, but aren't in the MODULES list.
#
#######################################################################
MODULES=`echo $* | sed 's/ rlm/|rlm/g;s/\.o//g;'`
cat $INPUT | egrep -v '^#' \
           | grep -i '^[a-z]' \
	   | egrep "$MODULES" \
           | sed 's/\.so//;s/\.\.\//\//;s/\.\//\//;s/\/.*\/rlm/rlm/;' \
           > .tmp.$$

#######################################################################
#
#  Create the output file a piece at a time.
#
#######################################################################
echo '#ifndef __STATIC_MODULES_H' >> $OUTPUT
echo '#define __STATIC_MODULES_H' >> $OUTPUT
echo >> $OUTPUT

echo '/* Automatically created header file: do not edit! */' >> $OUTPUT
echo >> $OUTPUT

# define the external functions by grabbing the module name
awk '{print "extern module_t " $2 ";"}' .tmp.$$ >> $OUTPUT

echo >> $OUTPUT

# initialize the array
echo 'static static_modules_t modules[] = {' >>  $OUTPUT

# grab the two fields from the input, and add structure wrappers
awk '{print "  {\"" $1 "\", \t&" $2 " },"}' .tmp.$$ >> $OUTPUT

# output a trailing empty structure for the array
echo '  { NULL, NULL }' >> $OUTPUT

# and close off the array
echo '};' >> $OUTPUT

echo >> $OUTPUT
echo '#endif __STATIC_MODULES_H' >> $OUTPUT

#######################################################################
#
#  Warn about modules in ../raddb/modules which will NOT be included
# in the static server.
#
#  The 'sort' and 'uniq' are the to be sure we complain only once.
#
#######################################################################
cat $INPUT | egrep -v '^#' \
           | grep -i '^[a-z]' \
           | awk '{print $2}' \
	   | egrep -v "$MODULES" \
           | sed 's/\.so//;s/\.\.\//\//;s/\.\//\//;s/\/.*\/rlm/rlm/;' \
           | sort \
           | uniq \
           > .tmp.$$
for x in `cat .tmp.$$`;do
  echo Warning: Module $x will NOT be included in the server. >/dev/stderr
  echo "         Delete it from ../raddb/modules, or ensure that $x can be built." >/dev/stderr
done

#######################################################################
#
#  Don't warn about modules in the MODULES list which are built, but are
# NOT in ../raddb/modules, and so will NOT be included in the server.
#
#######################################################################

# remove the intermediate config file
rm -f .tmp.$$

