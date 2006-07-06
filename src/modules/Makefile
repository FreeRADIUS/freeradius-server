#
# Makefile
#
# Version:	$Id$
#

include ../../Make.inc

WHAT_TO_MAKE	= all

all:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

install:
	$(INSTALL) -d -m 755 $(R)$(libdir)
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common
	@rm -f *~ lib/rlm_* lib/*.o lib/smbencrypt

distclean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

reconfig:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

common:
	@[ -d lib/ ] || mkdir lib
	@for mod in $(MODULES); do \
		if [ -d $$mod ] && [ -f $$mod/Makefile ]; then \
			echo "Making $(WHAT_TO_MAKE) in $$mod..."; \
			$(MAKE) $(MFLAGS) -C $$mod $(WHAT_TO_MAKE) || exit $$?; \
		fi; \
	done
