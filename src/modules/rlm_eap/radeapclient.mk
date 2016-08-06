TARGETNAME := radeapclient

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)
endif

SOURCES += ${top_srcdir}/src/main/files.c \
	   ${top_srcdir}/src/main/version.c

TGT_PREREQS := libfreeradius-radius.a libfreeradius-server.a
TGT_LDLIBS  := $(LIBS)

#
#  For future work, if we want radeapclient to become radclient
#
ifneq "$(filter libfreeradius-eap%,${ALL_TGTS})" ""
TGT_PREREQS += libfreeradius-eap.a libfreeradius-eap-sim.a

ifneq ($(OPENSSL_LIBS),)
include ${top_srcdir}/src/main/tls.mk
TGT_LDLIBS  += $(OPENSSL_LIBS)
endif

SRC_CFLAGS += -DWITH_EAPCLIENT
SRC_INCDIRS  := ${top_srcdir}/src/modules/rlm_eap/lib/base/ ${top_srcdir}/src/modules/rlm_eap/lib/sim/

ifneq ($(MAKECMDGOALS),scan)
SRC_CFLAGS	+= -DBUILT_WITH_CPPFLAGS=\"$(CPPFLAGS)\" -DBUILT_WITH_CFLAGS=\"$(CFLAGS)\" -DBUILT_WITH_LDFLAGS=\"$(LDFLAGS)\" -DBUILT_WITH_LIBS=\"$(LIBS)\"
endif

endif
