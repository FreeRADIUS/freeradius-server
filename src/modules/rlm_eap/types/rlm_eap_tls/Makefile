TARGET      = 
#TARGET      = rlm_eap_tls
SRCS        = rlm_eap_tls.c eap_tls.c cb.c tls.c
RLM_CFLAGS  = $(INCLTDL) -I../.. -I/path/to/openssl/include
HEADERS     = eap_tls.h
RLM_INSTALL = 

RLM_LDFLAGS += -L/path/to/openssl/lib
RLM_LIBS    += -lssl 

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

RLM_DIR=../../
include ${RLM_DIR}../rules.mak
