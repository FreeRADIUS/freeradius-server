#!/bin/sh
. $(dirname $0)/common.sh

#
#  Run radclient auth
#
exec $DIR/build/make/jlibtool --mode=execute $FR_DEBUGGER $DIR/build/bin/local/radclient -d $(dirname $0)/home -D $DIR/share/ -f user_password $@ localhost:${FR_LOCAL_PREFIX}1812 auth testing123
