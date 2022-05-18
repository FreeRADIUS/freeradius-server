TARGETNAME	:= rlm_eap_peap

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c peap.c

SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/ ${top_srcdir}/src/modules/rlm_eap/lib/base/

TGT_PREREQS	:= libfreeradius-eap$(L) libfreeradius-soh$(L)
