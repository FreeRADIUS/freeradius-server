#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-internal.a

SOURCES		:= decode.c \
		   encode.c

TGT_PREREQS	:= libfreeradius-util.a
