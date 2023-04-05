#!/bin/sh

#
#  Run the home server.
#

DIR=$(dirname $0)/../../..
PROGRAM=$(basename $0)

export RADDB=$DIR/raddb
export TEST_PATH=$(dirname $0)/
export LIB_PATH=$DIR/build/lib/local/

exec $DIR/build/make/jlibtool --mode=execute $FR_DEBUGGER $DIR/build/bin/local/radclient -d $(dirname $0)/home -D $DIR/share/ -f user_password $@ localhost auth testing123
