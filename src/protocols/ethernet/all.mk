#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-ethernet.a

SOURCES		:= ethernet.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io.a libfreeradius-util.a
