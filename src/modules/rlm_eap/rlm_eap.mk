TARGET		:= rlm_eap.a
SOURCES		:= rlm_eap.c eap.c mem.c cache.c

SRC_INCDIRS	:= . libeap

TGT_PREREQS	:= libfreeradius-eap.a

TGT_LDLIBS	:= -ljson-c 
