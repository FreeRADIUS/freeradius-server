include ../../Make.inc

RFC	= rfc2548.txt rfc2865.txt rfc2866.txt rfc2867.txt rfc2868.txt \
	  rfc2869.txt rfc3162.txt 

all: refs
	./rewrite.pl $(RFC)

refs: $(RFC)
	./genref.pl $(RFC) > refs

clean:
	rm -f refs *.html *~

install:
	$(INSTALL) -d -m 755	$(R)$(datadir)/doc/freeradius-$(RADIUSD_VERSION)/rfc
	for i in *.txt *.html; do \
		$(INSTALL) -m 644 $$i $(R)$(datadir)/doc/freeradius-$(RADIUSD_VERSION)/rfc; \
	done
