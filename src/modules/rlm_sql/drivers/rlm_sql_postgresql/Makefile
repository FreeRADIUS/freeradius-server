include ../../../../../Make.inc

TARGET		= rlm_sql_postgresql
SRCS		= sql_postgresql.c
HEADERS		= sql_postgresql.h
RLM_SQL_CFLAGS	= -I$(PG_INCLUDE_DIR)
RLM_SQL_LIBS	= $(PQ_LIBS)

$(DYNAMIC_OBJS): $(HEADERS) 

###
# over-ride the previous assignment if we're not building anything
ifeq ($(PQ_LIBS),)
TARGET        =
endif

include ../rules.mak
