# must be first
include config.mak

TARGET		= rlm_sql_oracle
SRCS		= sql_oracle.c
HEADERS		= sql_oracle.h
RLM_SQL_CFLAGS	=
RLM_SQL_LIBS	=

$(DYNAMIC_OBJS): $(HEADERS) 

###
# over-ride the previous assignment if we're not building anything
ifeq ($(LIBORACLE),)
TARGET        =
endif

include ../rules.mak

# must be last
config.mak:
	@../checkconfig -l LIBORACLE oracle_init -loracle -L/usr/local/oracle/lib

