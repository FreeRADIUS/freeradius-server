#! /bin/sh
#
# makemodules.sh	Helper script to generate a list of modules
#			to compile into the server.
#
# Version:	$Id$
#

if [ "$2" != "" ]
then
	# $(LIBDL) is set, so no static modules.
	exit 0
fi

for i in ../modules/rlm_*/rlm_*.a
do
	module=`basename $i`
	module=`echo $module | sed 's/\.a$//'`
	MODULE_PATHS="$MODULE_PATHS$i "
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

