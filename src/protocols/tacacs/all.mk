#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-tacacs$(L)
TGT_CATEGORY	:= lib-protocol
SOURCES		:= base.c decode.c encode.c
TGT_PREREQS	:= $(LIBFREERADIUS_UTIL)
