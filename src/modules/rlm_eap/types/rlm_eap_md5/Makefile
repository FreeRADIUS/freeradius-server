#
# Makefile
#
# Version:	$Id$
#

TARGET      = rlm_eap_md5
SRCS        = rlm_eap_md5.c eap_md5.c
HEADERS     = eap_md5.h
RLM_CFLAGS  = $(INCLTDL) -I../.. -I../../libeap
RLM_INSTALL =

RLM_DIR=../../
include ${RLM_DIR}../rules.mak

$(LT_OBJS): $(HEADERS)
