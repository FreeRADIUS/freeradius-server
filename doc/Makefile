#
# Makefile
#
# Version:	$Id$
#

include ../Make.inc

SUBDIRS		= rfc
WHAT_TO_MAKE	= all

all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f *~

install:
	$(INSTALL) -d -m 755 $(R)$(datadir)/doc
	$(INSTALL) -d -m 755 $(R)$(datadir)/doc/freeradius-$(RADIUSD_VERSION)
	for file in *[!~]; do \
		if [ -f $$file -a $$file != Makefile ]; then \
			$(INSTALL) -m 644 $$file $(R)$(datadir)/doc/freeradius-$(RADIUSD_VERSION); \
		fi; \
	done
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

common:
	@for dir in $(SUBDIRS); do \
		echo "Making $(WHAT_TO_MAKE) in $$dir..."; \
		(cd $$dir && $(MAKE) $(MFLAGS) $(WHAT_TO_MAKE)) || exit $?;\
	done
