TARGETNAME	:= rlm_eap_ttls

ifneq "$(OPENSSL_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/

TGT_PREREQS	:= libfreeradius-eap$(L)
