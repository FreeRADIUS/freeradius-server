TARGET      = rlm_eap_ttls.a
SOURCES        = rlm_eap_ttls.c ttls.c
SRC_INCDIRS  = ../.. ../../libeap
TGT_LDLIBS = $(OPENSSL_INCLUDE) 
TGT_LDLIBS    =  $(OPENSSL_LIBS)
#TGT_PREREQS = libfreeradius-eap.a
