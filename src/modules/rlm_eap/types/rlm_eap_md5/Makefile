include ../../../../../Make.inc

TARGET      = rlm_eap_md5
SRCS        = rlm_eap_md5.c eap_md5.c
HEADERS     = eap_md5.h
RLM_EAP_FLAGS  = @eap_cflags@
RLM_EAP_LIBS    = @eap_ldflags@
RLM_INSTALL = install-eap

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

## this uses the RLM_CFLAGS and RLM_LIBS and SRCS defs to make TARGET.
include ../rules.mak

## the rule that RLM_INSTALL tells the parent rules.mak to use.
install-eap:
	touch .
