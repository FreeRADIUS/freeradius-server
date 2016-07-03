TARGET		:= rlm_eap.a
SOURCES		:= rlm_eap.c eap.c mem.c

SRC_INCDIRS	:= . lib/base

TGT_PREREQS	:= libfreeradius-eap.a
