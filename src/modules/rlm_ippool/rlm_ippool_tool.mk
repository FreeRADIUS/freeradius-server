#
# $Id$
#

SOURCES		:= rlm_ippool_tool.c
TARGET		:= rlm_ippool_tool
TGT_PREREQS	:= libfreeradius-radius.a

SRC_CFLAGS	:= $(rlm_ippool_CFLAGS)
TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS) $(rlm_ippool_LDLIBS)

MAN		:= rlm_ippool_tool.8
