ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= eap_psk_tests$(E)
endif

SOURCES		:= eap_psk_tests.c

TGT_LDLIBS	:= $(LIBS) $(OPENSSL_LIBS)
TGT_LDFLAGS	:= $(LDFLAGS) $(OPENSSL_LDFLAGS)

TGT_PREREQS	:= libfreeradius-util$(L)

SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/

TGT_INSTALLDIR	:=
