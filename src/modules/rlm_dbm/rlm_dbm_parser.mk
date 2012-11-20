#
# $Id$
#

TARGET		:= rlm_dbm_parser
SOURCES		:= rlm_dbm_parser.c
TGT_PREREQS	:= libfreeradius-radius.a
TGT_PRLIBS	:= ${LIBS}

SRC_CFLAGS 	:= $(rlm_dbm_CFLAGS)
TGT_LDLIBS	:= $(rlm_dbm_LDLIBS)

MAN		:= rlm_dbm_parser.8
