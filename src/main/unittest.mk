TARGET	:= unittest
SOURCES := acct.c auth.c client.c crypt.c files.c \
		  mainconfig.c modules.c modcall.c \
		  unittest.c soh.c state.c connection.c \
		  session.c threads.c version.c  \
		  realms.c

ifneq ($(OPENSSL_LIBS),)
SOURCES		+= cb.c tls.c
endif

SRC_CFLAGS	:= -DHOSTINFO=\"${HOSTINFO}\"
TGT_INSTALLDIR  :=
TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS) $(LCRYPT)
TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a

# Libraries can't depend on libraries (oops), so make the binary
# depend on the EAP code...
ifneq "$(filter rlm_eap_%,${ALL_TGTS})" ""
TGT_PREREQS	+= libfreeradius-eap.a
endif

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
