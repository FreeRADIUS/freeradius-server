#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-util.a

SOURCES		:= base64.c \
		   cbuff.c \
		   cursor.c \
		   debug.c \
		   dict.c \
		   event.c \
		   fifo.c \
		   filters.c \
		   getaddrinfo.c \
		   hash.c \
		   heap.c \
		   hmacmd5.c \
		   hmacsha1.c \
		   inet.c \
		   isaac.c \
		   log.c \
		   mem.c \
		   misc.c \
		   missing.c \
		   md4.c \
		   md5.c \
		   net.c \
		   pair.c \
		   pair_cursor.c \
		   pcap.c \
		   print.c \
		   proto.c \
		   rand.c \
		   rbtree.c \
		   regex.c \
		   sha1.c \
		   snprintf.c \
		   strerror.c \
		   strlcat.c \
		   strlcpy.c \
		   syserror.c \
		   socket.c \
		   talloc.c \
		   token.c \
		   udpfromto.c \
		   udp.c \
		   value.c \
		   version.c

SRC_CFLAGS	:= -D_LIBRADIUS -I$(top_builddir)/src

# System libraries discovered by our top level configure script, links things
# like pthread and the regexp libraries.
TGT_LDLIBS	:= $(LIBS) $(PCAP_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(PCAP_LDFLAGS)
