#
# Makefile
#
# Version:	$Id$
#

TARGET      = rlm_eap_sim
SRCS        = rlm_eap_sim.c
HEADERS     =
RLM_CFLAGS  = $(INCLTDL) -I../.. -I../../libeap
RLM_LIBS    =  ../../libeap/libeap.la
RLM_INSTALL =

RLM_DIR=../../
include ${RLM_DIR}../rules.mak

$(LT_OBJS): $(HEADERS)
