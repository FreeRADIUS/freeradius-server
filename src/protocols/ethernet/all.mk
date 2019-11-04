#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-ethernet.a

SOURCES		:= ethernet.c

SRC_CFLAGS	:= -DNO_ASSERT
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a libfreeradius-util.a
