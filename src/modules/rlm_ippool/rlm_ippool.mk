#
# $Id$
#

SOURCES		:= rlm_ippool.c
TARGET		:= rlm_ippool.a

SRC_CFLAGS	:= $(rlm_ippool_CFLAGS) 
TGT_LDLIBS	:= $(OPENSSL_LIBS) $(rlm_ippool_LDLIBS)
