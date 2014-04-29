TARGET   := radeapclient
SOURCES := radeapclient.c

SOURCES += ${top_srcdir}/src/main/files.c \
	   ${top_srcdir}/src/main/threads.c \
	   ${top_srcdir}/src/main/version.c

TGT_PREREQS := libfreeradius-radius.a libfreeradius-eap.a libfreeradius-server.a
TGT_LDLIBS  := $(LIBS)

ifneq ($(OPENSSL_LIBS),)
SOURCES += ${top_srcdir}/src/main/cb.c ${top_srcdir}/src/main/tls.c
TGT_LDLIBS	+= -lssl
endif

SRC_INCDIRS  := libeap
