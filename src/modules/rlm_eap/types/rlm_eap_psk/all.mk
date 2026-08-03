SUBMAKEFILES	:= eap_psk_tests.mk

TARGETNAME	:= rlm_eap_psk

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c eap_psk.c

SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/

TGT_PREREQS	:= libfreeradius-eap$(L)
