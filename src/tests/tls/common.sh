#
#  Common definitions.
#
DIR=$(dirname $0)/../../..
PROGRAM=$(basename $0)

export RADDB=$DIR/raddb
export FR_LOCAL_PREFIX=`cat prefix 2>/dev/null`
export TEST_PATH=$(dirname $0)/
export LIB_PATH=$DIR/build/lib/local/
export FR_LIBRARY_PATH=$DIR/build/lib/local/.libs/

