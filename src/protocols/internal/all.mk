#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-internal.a

SOURCES		:= decode.c \
		   encode.c

SRC_CFLAGS	:= -DNO_ASSERT
TGT_PREREQS	:= libfreeradius-util.a
