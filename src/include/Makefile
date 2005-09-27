#
# Makefile
#
# Version:	$Id$
#

include ../../Make.inc
.PHONY: all clean install

all: radpaths.h


radpaths.h:
	@/bin/sh ./build-radpaths-h


distclean:
	rm -f radpaths.h

clean:

install:
	$(INSTALL) -d -m 755 $(R)$(includedir)/freeradius
	$(INSTALL) -m 644 libradius.h $(R)$(includedir)/freeradius
	$(INSTALL) -m 644 md4.h $(R)$(includedir)/freeradius
	$(INSTALL) -m 644 md5.h $(R)$(includedir)/freeradius
	$(INSTALL) -m 644 missing.h $(R)$(includedir)/freeradius
	$(INSTALL) -m 644 radius.h $(R)$(includedir)/freeradius
	$(INSTALL) -m 644 radpaths.h $(R)$(includedir)/freeradius
	$(INSTALL) -m 644 sha1.h $(R)$(includedir)/freeradius
	$(INSTALL) -m 644 token.h $(R)$(includedir)/freeradius
	$(INSTALL) -m 644 udpfromto.h $(R)$(includedir)/freeradius
