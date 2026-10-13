TARGETNAME	:= libfreeradius-bio-tls

#
#  The TLS bio needs the TLS library, which is only built when OpenSSL is available.
#
ifneq ($(OPENSSL_LIBS),)
TARGET		:= $(TARGETNAME)$(L)
endif

TGT_CATEGORY	:= lib-util

SOURCES	:=		\
	tls.c

TGT_PREREQS	:= libfreeradius-bio$(L) libfreeradius-tls$(L)
TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS)
