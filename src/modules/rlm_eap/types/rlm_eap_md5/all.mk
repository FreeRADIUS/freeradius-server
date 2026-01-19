TARGETNAME	:= rlm_eap_md5

ifneq "$(TARGETNAME)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= $(TARGETNAME).c eap_md5.c

SRC_INCDIRS	:= ${top_srcdir}/src/modules/rlm_eap/

TGT_PREREQS	:= libfreeradius-eap$(L)
