#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-arp$(L)
TGT_CATEGORY	:= lib-protocol

SOURCES		:= base.c

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL)
