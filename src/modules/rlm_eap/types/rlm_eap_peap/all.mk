TARGET      = rlm_eap_peap.a
SOURCES        = rlm_eap_peap.c peap.c
SRC_INCDIRS  = ../.. ../../libeap
TGT_LDLIBS = $(OPENSSL_INCLUDE) 
TGT_LDLIBS    =  $(OPENSSL_LIBS)
#TGT_PREREQS = libfreeradius-eap.a
