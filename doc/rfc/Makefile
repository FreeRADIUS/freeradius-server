#
# Makefile
#
# Version:	$Id$
#

include ../../Make.inc

RFC	= rfc2548.txt rfc2865.txt rfc2866.txt rfc2867.txt rfc2868.txt \
	  rfc2869.txt rfc3162.txt

all:

html: refs
	./rewrite.pl $(RFC)
	@touch .rewrite

refs: $(RFC)
	./genref.pl $(RFC) > refs

clean:
	rm -f refs rfc*.html *~ .rewrite index.html

install:
	$(INSTALL) -d -m 755 $(R)$(datadir)/doc/freeradius/rfc
	for file in `ls -1 *.txt *.html`; do \
		$(INSTALL) -m 644 $$file $(R)$(datadir)/doc/freeradius/rfc; \
	done

.PHONY: all clean install html
