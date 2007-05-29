#
# Makefile
#
# Version:	$Id$
#

HEADERS	= hash.h libradius.h md4.h md5.h missing.h packet.h radius.h \
		radpaths.h sha1.h token.h udpfromto.h vqp.h ident.h 

include ../../Make.inc
.PHONY: all clean distclean install

all: radpaths.h

radpaths.h: build-radpaths-h
	@/bin/sh ./build-radpaths-h

distclean:
	rm -f radpaths.h

clean:

install:
	$(INSTALL) -d -m 755 $(R)$(includedir)/freeradius
	for i in $(HEADERS); do \
		sed 's/^#include <freeradius-devel/#include <freeradius/' $$i > $(R)$(includedir)/freeradius/$$i; \
		chmod 644 $(R)$(includedir)/freeradius/$$i; \
	done
