#
# Makefile
#
# Version:	$Id$
#

all:
	$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

clean:
	$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

install:
	$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

reconfig:
	$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

common:
	@for mod in rlm_eap*; do \
		if [ -d $$mod ] && [ -f $$mod/Makefile ]; then \
			echo "Making $(WHAT_TO_MAKE) in $$mod..."; \
			$(MAKE) $(MFLAGS) -C $$mod $(WHAT_TO_MAKE) || exit $$?; \
		fi; \
	done
