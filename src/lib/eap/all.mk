TARGET := libfreeradius-eap.a

SOURCES	:= \
	base.c\
	chbind.c

ifneq (${OPENSSL_LIBS},)
SOURCES		+= tls.c crypto.c
endif

TGT_PREREQS	:= libfreeradius-radius.a libfreeradius-util.a
SRC_CFLAGS	:= -DEAPLIB
