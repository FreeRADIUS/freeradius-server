TARGET      = rlm_jradius
SRCS        = rlm_jradius.c 
HEADERS     = 
RLM_CFLAGS  = -DEXTENDED_FMT
RLM_LIBS    = 

## this uses the RLM_CFLAGS and RLM_LIBS and SRCS defs to make TARGET.
include ../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)

