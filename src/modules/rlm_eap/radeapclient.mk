TARGET   := radeapclient
SOURCES := radeapclient.c

TGT_PREREQS := libfreeradius-radius.a libfreeradius-eap.a
TGT_PRLIBS  := ${OPENSSL_LIBS}

SRC_INCDIRS  := libeap
