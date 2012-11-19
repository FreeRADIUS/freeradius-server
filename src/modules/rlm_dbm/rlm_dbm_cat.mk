#
# $Id$
#

TARGET		:= rlm_dbm_cat
SOURCES		:= rlm_dbm_cat.c
TGT_PREREQS	:= libfreeradius-radius.a

SRC_CFLAGS 	:= $(rlm_dbm_CFLAGS)
TGT_LDLIBS	:= $(rlm_dbm_LDLIBS)

MAN		:= rlm_dbm_cat.8