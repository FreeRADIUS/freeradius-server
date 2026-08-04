TARGETNAME	:= rlm_eap_psk

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/ ${top_srcdir}/src/process/eap_psk/

TGT_PREREQS	:= libfreeradius-eap$(L)
