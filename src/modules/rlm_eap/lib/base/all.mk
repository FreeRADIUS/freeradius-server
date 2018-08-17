TARGET := libfreeradius-eap.a

SOURCES	:= \
	eap_base.c\
	eap_chbind.c

ifneq (${OPENSSL_LIBS},)
SOURCES		+= eap_tls.c mppe_keys.c
endif

TGT_PREREQS	:= libfreeradius-radius.a libfreeradius-util.a
SRC_CFLAGS	:= -DEAPLIB
SRC_INCDIRS	:= . ${top_srcdir}/src/modules/rlm_eap/
