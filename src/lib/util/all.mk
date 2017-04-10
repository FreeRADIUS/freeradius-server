#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-util.a

SOURCES		:= cbuff.c \
		   cursor.c \
		   debug.c \
		   dict.c \
		   filters.c \
		   hash.c \
		   hmacmd5.c \
		   hmacsha1.c \
		   inet.c \
		   isaac.c \
		   log.c \
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
		   radius.c \
		   radius_encode.c \
		   radius_decode.c \
		   rbtree.c \
		   regex.c \
		   sha1.c \
		   snprintf.c \
		   strerror.c \
		   strlcat.c \
		   strlcpy.c \
		   syserror.c \
		   socket.c \
		   token.c \
		   udpfromto.c \
		   value.c \
		   fifo.c \
		   packet.c \
		   event.c \
		   getaddrinfo.c \
		   heap.c \
		   tcp.c \
		   udp.c \
		   base64.c \
		   version.c

SRC_CFLAGS	:= -D_LIBRADIUS -I$(top_builddir)/src

# System libraries discovered by our top level configure script, links things
# like pthread and the regexp libraries.
TGT_LDLIBS	:= $(LIBS) $(PCAP_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(PCAP_LDFLAGS)
