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

SUBDIRS := $(patsubst %/,%,$(dir $(wildcard rlm_eap*/Makefile)))

.PHONY: common $(SUBDIRS)

common: $(SUBDIRS)

# The PEAP and TTLS sub-modules require eap_tls.
#
# If they're not being built, this rule is ignored because they're
# phony targets.
# 
rlm_eap_peap rlm_eap_ttls: rlm_eap_tls

$(SUBDIRS): 
	@echo "Making $(WHAT_TO_MAKE) in $@..."
	@$(MAKE) $(MFLAGS) -C $@ $(WHAT_TO_MAKE)
