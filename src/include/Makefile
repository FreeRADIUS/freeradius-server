#
# Makefile
#
# Version:	$Id$
#

include ../../Make.inc
.PHONY: all clean distclean install

all: radpaths.h

radpaths.h: build-radpaths-h
	@/bin/sh ./build-radpaths-h

distclean:
	rm -f radpaths.h

clean:

install:
