TARGET		= $(LIBPREFIX)eap
SRCS		= fips186prf.c eapcrypto.c eapcommon.c eapsimlib.c
INCLUDES	= 
RLM_CFLAGS	= -DEAPLIB -I../../../include 
LINK_MODE	= $(RLM_EAP_LINK_MODE)

RLM_DIR		= ../
include ../../rules.mak
