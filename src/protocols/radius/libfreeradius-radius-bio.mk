#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-radius-bio$(L)
TGT_CATEGORY	:= lib-protocol

SOURCES		:= client.c \
		   client_udp.c \
		   client_tcp.c \
		   id.c \
		   bio.c \
		   server.c \
		   server_udp.c

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL) libfreeradius-radius$(L) libfreeradius-bio$(L)
