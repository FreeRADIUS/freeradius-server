#
# $Id$
#

SOURCES		:= rlm_dbm.c
TARGET		:= rlm_dbm.a

SRC_CFLAGS	:= $(rlm_dbm_CFLAGS) 
TGT_LDLIBS	:= $(rlm_dbm_LDLIBS)
