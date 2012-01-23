TARGET      = rlm_eap_tls.a
SOURCES     = rlm_eap_tls.c
SRC_INCDIRS  = ../.. ../../libeap 
SRC_CFLAGS = $(OPENSSL_INCLUDE) 
TGT_LDLIBS    =  $(OPENSSL_LIBS)
#TGT_PREREQS  = libfreeradius-eap.a
