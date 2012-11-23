TARGET		:= rlm_eap_tls.a
SOURCES		:= rlm_eap_tls.c
SRC_INCDIRS	:= ../../ ../../libeap/
TGT_LDLIBS	:= $(OPENSSL_LIBS)
TGT_PREREQS	:= libfreeradius-eap.a
