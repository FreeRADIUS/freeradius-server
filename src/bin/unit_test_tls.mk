#
#  Without OpenSSL there is nothing for this program to test.
#
ifneq ($(OPENSSL_LIBS),)
TARGET		:= unit_test_tls$(E)
endif
SOURCES 	:= unit_test_tls.c

TGT_INSTALLDIR  :=
TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS) $(LCRYPT) $(GPERFTOOLS_LIBS)
TGT_LDFLAGS	:= $(OPENSSL_FLAGS) $(GPERFTOOLS_LDFLAGS)
TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-io$(L) libfreeradius-tls$(L)

# Flags needed when linking main executables that link against LuaJIT
TGT_LDLIBS	+= $(LUAJIT_LDLIBS)

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
