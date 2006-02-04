#
# Makefile
#
# Version:	$Id$
#

include ../../Make.inc

all:

clean:
	@rm -f *~

install:
	$(INSTALL) -d -m 755 $(R)$(datadir)/doc/freeradius/examples
	for file in *[!~]; do \
		if [ -f $$file -a $$file != Makefile ]; then \
			$(INSTALL) -m 644 $$file $(R)$(datadir)/doc/freeradius/examples; \
		fi; \
	done

.PHONY: all clean install
