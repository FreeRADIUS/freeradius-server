TARGET := libfreeradius-eap.a

SOURCES	:=		\
	base.c		\
	chbind.c	\
	compose.c	\
	types.c		\
	session.c

ifneq (${OPENSSL_LIBS},)
SOURCES		+= tls.c crypto.c
endif

TGT_PREREQS	:= libfreeradius-util.la libfreeradius-radius.a
SRC_CFLAGS	:= -DEAPLIB
