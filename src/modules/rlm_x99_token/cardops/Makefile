TARGET      = notused
SRCS        = $(wildcard *.c)
HEADERS     = $(wildcard *.h)
#RLM_CFLAGS  = @x99_token_cflags@ $(OPENSSL_INCLUDE)

RLM_DIR=../
include $(RLM_DIR)../rules.mak

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS)
