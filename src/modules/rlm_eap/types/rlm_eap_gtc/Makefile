#
# Makefile
#
# Version:	$Id$
#

TARGET      = rlm_eap_gtc
SRCS        = rlm_eap_gtc.c
RLM_CFLAGS  = -I../.. -I../../libeap
HEADERS     =  ../../rlm_eap.h ../../eap.h
RLM_INSTALL =

RLM_DIR=../../
include ${RLM_DIR}../rules.mak

$(LT_OBJS): $(HEADERS)
