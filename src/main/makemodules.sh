#! /bin/sh
#
# makemodules.sh	Helper script to generate a list of modules
#			to compile into the server.
#
# Version:	$Id$
#

if [ "$1" = static ]
then
	shift
	mods=`echo $* | sed -e 's/\.[coa]//g' -e 's/\.so//g'`
	for i in $mods
	do
		echo "extern module_t $i;"
	done
	echo
	echo "static_modules_t static_modules[] = {"
	for i in $mods
	do
		echo "  {  \"$i.c\", &$i  },"
	done
	echo "  {  NULL, NULL  }"
	echo "};"
	exit 0
fi

if [ "$2" != "" ]
then
	# $(LIBDL) is set, so no static modules.
	exit 0
fi

for i in ../modules/rlm_*
do
	module=`basename $i`
	if [ ! -f $i/$module.a ]
	then
		continue
	fi
	MODULE_PATHS="$MODULE_PATHS$i/$module.a "
	MODULES="$MODULES$module "
done

if [ "$1" = paths ]
then
	echo $MODULE_PATHS
elif [ "$1" = modules ]
then
	echo $MODULES
else
	echo "Usage: $0 paths|modules [libdl]"
	exit 1
fi

exit 0

