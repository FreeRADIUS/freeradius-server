#!/bin/sh
. $(dirname $0)/common.sh

#
#  Run radclient acct
#
exec $DIR/build/make/jlibtool --mode=execute $FR_DEBUGGER $DIR/build/bin/local/radclient -d $(dirname $0)/home -D $DIR/share/ -f acct $@ localhost acct testing123
