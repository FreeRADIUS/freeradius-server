TARGET   := radeapclient
SOURCES := radeapclient.c

SOURCES += ${top_srcdir}/src/main/files.c \
	   ${top_srcdir}/src/main/threads.c \
	   ${top_srcdir}/src/main/version.c

TGT_PREREQS := libfreeradius-radius.a libfreeradius-server.a
TGT_LDLIBS  := $(LIBS)

#
#  For future work, if we want radeapclient to become radclient
#
ifneq "$(filter libfreeradius-eap%,${ALL_TGTS})" ""
TGT_PREREQS += libfreeradius-eap.a

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
