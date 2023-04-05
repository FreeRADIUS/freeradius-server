#!/bin/sh

#
#  Run the home server.
#

DIR=$(dirname $0)/../../..
PROGRAM=$(basename $0)

export RADDB=$DIR/raddb
export TEST_PATH=$(dirname $0)/
export LIB_PATH=$DIR/build/lib/local/

exec $DIR/build/make/jlibtool --mode=execute $FR_DEBUGGER $DIR/build/bin/local/radiusd -d $(dirname $0)/proxy -D $DIR/share/ -fxx -l stdout $@
