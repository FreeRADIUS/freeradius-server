TARGET	:= unit_test_module
SOURCES := \
	acct.c \
	auth.c \
	client.c \
	crypt.c \
	files.c \
	mainconfig.c \
	modules.c \
	unit_test_module.c \
	soh.c \
	state.c \
	session.c \
	version.c  \
	virtual_servers.c \
	unlang_compile.c \
	unlang_interpret.c \
	realms.c

ifneq ($(OPENSSL_LIBS),)
include ${top_srcdir}/src/main/tls.mk
endif

TGT_INSTALLDIR  :=
TGT_LDLIBS	:= $(LIBS) $(LCRYPT)
TGT_PREREQS	:= libfreeradius-server.a libfreeradius-util.a libfreeradius-radius.a libfreeradius-io.a

# Libraries can't depend on libraries (oops), so make the binary
# depend on the EAP code...
ifneq "$(filter rlm_eap_%,${ALL_TGTS})" ""
TGT_PREREQS	+= libfreeradius-eap.a
endif

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif
