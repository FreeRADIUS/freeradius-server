TARGETNAME	:= rlm_eap_fast

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c eap_fast_crypto.c

SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/

TGT_PREREQS	:= libfreeradius-tls$(L) libfreeradius-eap$(L)
