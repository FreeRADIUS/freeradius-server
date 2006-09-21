#
# Makefile
#
# Version:	$Id$
#

include ../../Make.inc

RFC	= rfc2548.txt rfc2865.txt rfc2866.txt rfc2867.txt rfc2868.txt \
	  rfc2869.txt rfc3162.txt rfc3576.txt rfc3579.txt rfc3580.txt \
	  rfc4590.txt

all:

html: refs
	./rewrite.pl $(RFC)
	./per-rfc.pl $(RFC)
	@touch .rewrite

index.html: html
	./update.sh

refs: $(RFC)
	./genref.pl $(RFC) > refs
	@echo 'rfc2865 Class' >> refs
	@echo 'rfc2865 State' >> refs

clean:
	rm -f refs *rfc*.html *~ .rewrite index.html

install:
	$(INSTALL) -d -m 755 $(R)$(docdir)/rfc
	for file in `ls -1 *.txt *.html`; do \
		$(INSTALL) -m 644 $$file $(R)$(docdir)/rfc; \
	done

.PHONY: all clean install html
