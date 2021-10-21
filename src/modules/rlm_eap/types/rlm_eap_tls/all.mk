TARGETNAME	:= rlm_eap_tls

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME).a
endif

SOURCES		:= $(TARGETNAME).c

SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/ ${top_srcdir}/src/modules/rlm_eap/lib/base/

TGT_PREREQS	:= libfreeradius-eap.a
