TARGETNAME	:= rlm_radius
TARGET		:= $(TARGETNAME)$(L)

SOURCES		:= rlm_radius.c

TGT_PREREQS	:= libfreeradius-radius$(L)
LOG_ID_LIB	= 39

#
#  RADIUS/TLS needs the TLS bio and the TLS library, which are only built when OpenSSL is available.
#
ifneq "$(OPENSSL_LIBS)" ""
TGT_PREREQS	+= libfreeradius-bio-tls$(L) libfreeradius-tls$(L)
TGT_LDLIBS	+= $(OPENSSL_LIBS)
endif
