#
#  We only build radeapclient if we also build libfreeradius-eap.
#
ifneq "$(filter libfreeradius-eap%,${ALL_TGTS})" ""

TARGET   := radeapclient
SOURCES := radeapclient.c

SOURCES += ${top_srcdir}/src/main/files.c \
	   ${top_srcdir}/src/main/threads.c \
	   ${top_srcdir}/src/main/version.c

TGT_PREREQS := libfreeradius-eap.a libfreeradius-server.a libfreeradius-radius.a 
TGT_LDLIBS  := $(LIBS)

ifneq ($(OPENSSL_LIBS),)
SOURCES += ${top_srcdir}/src/main/cb.c ${top_srcdir}/src/main/tls.c
TGT_LDLIBS  += $(OPENSSL_LIBS)
endif

SRC_CFLAGS += -DWITH_EAPCLIENT
SRC_INCDIRS  := ${top_srcdir}/src/modules/rlm_eap/libeap

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif

endif
