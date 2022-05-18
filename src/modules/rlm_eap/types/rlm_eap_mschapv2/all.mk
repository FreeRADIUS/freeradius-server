TARGETNAME	:= rlm_eap_mschapv2

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c

SRC_CFLAGS	:=
TGT_LDLIBS	:=
SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/ ${top_srcdir}/src/modules/rlm_eap/lib/base/

TGT_PREREQS	:= libfreeradius-eap$(L)
