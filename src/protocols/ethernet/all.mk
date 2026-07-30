#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-ethernet$(L)
TGT_CATEGORY	:= lib-protocol

SOURCES		:= ethernet.c

SRC_CFLAGS	:= -DNO_ASSERT
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L)
