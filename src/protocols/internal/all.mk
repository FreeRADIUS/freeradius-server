#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-internal$(L)
TGT_CATEGORY	:= lib-protocol

SOURCES		:= decode.c \
		   encode.c

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL)
