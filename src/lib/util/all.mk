#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-util.a

SOURCES		:= \
		   ascend.c \
		   base64.c \
		   cursor.c \
		   debug.c \
		   dict_print.c \
		   dict_tokenize.c \
		   dict_unknown.c \
		   dict_util.c \
		   dict_validate.c \
		   dl.c \
		   dns.c \
		   event.c \
		   fopencookie.c \
		   fifo.c \
		   file.c \
		   fring.c \
		   getaddrinfo.c \
		   hash.c \
		   heap.c \
		   hmac_md5.c \
		   hmac_sha1.c \
		   inet.c \
		   isaac.c \
		   log.c \
		   md4.c \
		   md5.c \
		   misc.c \
		   missing.c \
		   net.c \
		   packet.c \
		   pair_cursor.c \
		   pair.c \
		   pcap.c \
		   print.c \
		   proto.c \
		   rand.c \
		   rbtree.c \
		   retry.c \
		   regex.c \
		   sha1.c \
		   snprintf.c \
		   socket.c \
		   strerror.c \
		   strlcat.c \
		   strlcpy.c \
		   struct.c \
		   syserror.c \
		   table.c \
		   talloc.c \
		   thread_local.c \
		   token.c \
		   time.c \
		   timeval.c \
		   trie.c \
		   udp.c \
		   udpfromto.c \
		   value.c \
		   version.c

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/util/*.h))

SRC_CFLAGS	:= -D_LIBRADIUS -DNO_ASSERT -I$(top_builddir)/src

# System libraries discovered by our top level configure script, links things
# like pthread and the regexp libraries.
TGT_LDLIBS	:= $(LIBS) $(PCAP_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(PCAP_LDFLAGS)
