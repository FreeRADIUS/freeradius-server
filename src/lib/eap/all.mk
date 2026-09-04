TARGET := libfreeradius-eap$(L)
TGT_CATEGORY	:= lib-util

SOURCES	:=		\
	base.c		\
	chbind.c	\
	compose.c	\
	types.c		\
	session.c

ifneq (${OPENSSL_LIBS},)
SOURCES		+= tls.c crypto.c
endif

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL) libfreeradius-radius$(L)
SRC_CFLAGS	:= -DEAPLIB
