#! /bin/sh
#
# c		Short script fragment that configures the paths
#		exactly as they were in the 1.5.x series of the
#		Cistron Radius Server.
#
# Usage:	./c
#
# Version:	@(#)./c  1.00  25-Jul-1999  miquels@cistron.nl
#

./configure	--localstatedir=/var \
		--sysconfdir=/etc "$@" \
		--without-dynamic-modules

