TARGET := libfreeradius-eap.a

SOURCES	:= \
	base.c\
	chbind.c

ifneq (${OPENSSL_LIBS},)
SOURCES		+= tls.c mppe_keys.c
endif

TGT_PREREQS	:= libfreeradius-radius.a libfreeradius-util.a
SRC_CFLAGS	:= -DEAPLIB
