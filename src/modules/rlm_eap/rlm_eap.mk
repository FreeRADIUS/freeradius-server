TARGET		:= rlm_eap.a
SOURCES		:= rlm_eap.c eap.c mem.c

SRC_INCDIRS	:= . libeap

TGT_PREREQS	:= libfreeradius-eap.a

ifneq "$(WITH_CACHE_EAP)" ""
SOURCES		+= cache.c
TGT_LDLIBS	:= -ljson-c
endif
