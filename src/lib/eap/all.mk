TARGET := libfreeradius-eap$(L)

SOURCES	:=		\
	base.c		\
	chbind.c	\
	compose.c	\
	types.c		\
	session.c

ifneq (${OPENSSL_LIBS},)
SOURCES		+= tls.c crypto.c
endif

TGT_PREREQS	:= libfreeradius-util$(L) libfreeradius-radius$(L)
SRC_CFLAGS	:= -DEAPLIB
