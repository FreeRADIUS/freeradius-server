#
# $Id$
#

SOURCES		:= rlm_dbm_parser.c
TARGET		:= rlm_dbm_parser
TGT_PREREQS	:= libfreeradius-radius.a

SRC_CFLAGS 	:= $(rlm_dbm_CFLAGS)
TGT_LDLIBS	:= $(rlm_dbm_LDLIBS)

MAN		:= rlm_dbm_parser.8