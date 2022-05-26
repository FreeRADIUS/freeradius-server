#
# Makefile
#
# Version:      $Id$
#
TARGET		:= libfreeradius-util$(L)

SOURCES		:= \
		   atexit.c \
		   base16.c \
		   base32.c \
		   base64.c \
		   calc.c \
		   cap.c \
		   dbuff.c \
		   debug.c \
		   decode.c \
		   dict_ext.c \
		   dict_fixup.c \
		   dict_print.c \
		   dict_test.c \
		   dict_tokenize.c \
		   dict_unknown.c \
		   dict_util.c \
		   dict_validate.c \
		   dl.c \
		   dns.c \
		   edit.c \
		   encode.c \
		   event.c \
		   ext.c \
		   fifo.c \
		   file.c \
		   fopencookie.c \
		   fring.c \
		   getaddrinfo.c \
		   hash.c \
		   heap.c \
		   hmac_md5.c \
		   hmac_sha1.c \
		   htrie.c \
		   hw.c \
		   inet.c \
		   isaac.c \
		   log.c \
		   lst.c \
		   machine.c \
		   md4.c \
		   md5.c \
		   minmax_heap.c \
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
		   perm.c \
		   print.c \
		   proto.c \
		   rand.c \
		   rb.c \
		   regex.c \
		   retry.c \
		   sbuff.c \
		   sem.c \
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
		   time.c \
		   timeval.c \
		   token.c \
		   trie.c \
		   types.c \
		   udp.c \
		   udpfromto.c \
		   udp_queue.c \
		   uri.c \
		   value.c \
		   version.c

#
#  Add the fuzzer only if everything was built with the fuzzing flags.
#
ifneq "$(findstring fuzzer,${CFLAGS})" ""
SOURCES		+= fuzzer.c
endif

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/util/*.h))

SRC_CFLAGS	:= -D_LIBRADIUS -DNO_ASSERT -I$(top_builddir)/src

# System libraries discovered by our top level configure script, links things
# like pthread and the regexp libraries.
TGT_LDLIBS	:= $(LIBS) $(PCAP_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(PCAP_LDFLAGS)

ifeq "$(TARGET_IS_WASM)" "yes"
SRC_CFLAGS      += -sMAIN_MODULE=1 -sUSE_PTHREADS=1
TGT_LDLIBS      += --no-entry
endif

