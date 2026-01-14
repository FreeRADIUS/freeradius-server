TARGETNAME	:= rlm_eap_mschapv2

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/
TGT_PREREQS	:= libfreeradius-eap$(L)
