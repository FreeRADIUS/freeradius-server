#
# Makefile
#
# Version:      $Id$
#

SOURCES		:= dict.c filters.c hash.c hmac.c hmacsha1.c isaac.c log.c \
		  misc.c missing.c md4.c md5.c print.c radius.c rbtree.c \
		  sha1.c snprintf.c strlcat.c strlcpy.c token.c udpfromto.c \
		  valuepair.c fifo.c packet.c event.c getaddrinfo.c vqp.c \
		  heap.c dhcp.c tcp.c

INCLUDES	= ../include/radius.h ../include/libradius.h \
		  ../include/missing.h ../include/autoconf.h \
		  ../include/ident.h

SRC_CFLAGS	:= -D_LIBRADIUS -I$(top_builddir)/src

TARGET		:= libfreeradius-radius.a
