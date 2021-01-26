#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-util.a

SOURCES		:= \
		   base64.c \
		   cap.c \
		   cursor.c \
		   dbuff.c \
		   dcursor.c \
		   debug.c \
		   dict_ext.c \
		   dict_fixup.c \
		   dict_print.c \
		   dict_tokenize.c \
		   dict_unknown.c \
		   dict_util.c \
		   dict_validate.c \
		   dl.c \
		   dns.c \
		   event.c \
		   ext.c \
		   fifo.c \
		   file.c \
		   fopencookie.c \
		   fring.c \
		   getaddrinfo.c \
		   hash.c \
		   heap.c \
		   hex.c \
		   hmac_md5.c \
		   hmac_sha1.c \
		   hw.c \
		   inet.c \
		   isaac.c \
		   log.c \
		   md4.c \
		   md5.c \
		   misc.c \
		   missing.c \
		   net.c \
		   packet.c \
		   pair.c \
		   pair_legacy.c \
		   pair_print.c \
		   pair_tokenize.c \
		   paths.c \
		   pcap.c \
		   print.c \
		   proto.c \
		   rand.c \
		   rbtree.c \
		   regex.c \
		   retry.c \
		   sbuff.c \
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
		   time.c \
		   timeval.c \
		   token.c \
		   trie.c \
		   types.c \
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
