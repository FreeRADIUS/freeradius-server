TARGET   := radeapclient
SOURCES := radeapclient.c

ifneq ($(OPENSSL_LIBS),)
SOURCES += ${top_srcdir}/src/main/cb.c ${top_srcdir}/src/main/tls.c
endif

SOURCES += ${top_srcdir}/src/main/files.c \
${top_srcdir}/src/main/threads.c \
${top_srcdir}/src/main/version.c

TGT_PREREQS := libfreeradius-radius.a libfreeradius-eap.a libfreeradius-server.a
TGT_LDLIBS  := $(LIBS)
TGT_LDLIBS	+= -lssl

SRC_INCDIRS  := libeap
