#!/bin/sh
. $(dirname $0)/common.sh

#
#  Run the proxy server.
#
exec $DIR/build/make/jlibtool --mode=execute $FR_DEBUGGER $DIR/build/bin/local/radiusd -d $(dirname $0)/proxy -D $DIR/share/ -fxx -l stdout $@
