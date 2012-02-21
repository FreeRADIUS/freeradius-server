#
# Makefile
#
# Version:	$Id$
#

TARGET      = rlm_eap_pwd
SRCS        = rlm_eap_pwd.c eap_pwdc
HEADERS     = rlm_eap_pwd.h eap_pwd.h
RLM_CFLAGS  = -I../.. -I../../libeap
RLM_INSTALL =

RLM_DIR=../../
include ${RLM_DIR}../rules.mak

$(LT_OBJS): $(HEADERS)
