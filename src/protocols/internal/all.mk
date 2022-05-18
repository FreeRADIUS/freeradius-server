#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-internal$(L)

SOURCES		:= decode.c \
		   encode.c

TGT_PREREQS	:= libfreeradius-util$(L)
