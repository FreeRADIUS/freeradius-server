TARGET      = rlm_eap
SRCS        = rlm_eap.c eap.c mem.c state.c
HEADERS     = eap.h
RLM_CFLAGS  = $(INCLTDL)
RLM_LIBS    = 
RLM_INSTALL = install-types

RLM_SUBDIRS = types

#
#  If Not using shared libraries, add in ALL known static eap_types
# at build time.
#
#ifneq ($(USE_SHARED_LIBS),yes)
#RLM_EAP_LIBS += $(shell for x in types/rlm_eap*/rlm_eap*.la;do echo -dlpreopen $$x;done)
#endif

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

all: 
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=$@ common

allclean:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=clean common

install-types:
	@$(MAKE) $(MFLAGS) WHAT_TO_MAKE=install common

common:
	@for dir in $(RLM_SUBDIRS); do \
		echo "Making $(WHAT_TO_MAKE) in $$dir..."; \
		(cd $$dir && $(MAKE) $(MFLAGS) $(WHAT_TO_MAKE)) || exit 1;\
	done

## this uses the RLM_CFLAGS and RLM_LIBS and SRCS defs to make TARGET.
include ../rules.mak

## the rule that RLM_INSTALL tells the parent rules.mak to use.
install-eap:
	touch .
