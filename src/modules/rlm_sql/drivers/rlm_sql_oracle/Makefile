include ../../../../../Make.inc

TARGET		= rlm_sql_oracle
SRCS		= sql_oracle.c
HEADERS		= sql_oracle.h
RLM_SQL_CFLAGS	= $(SQL_ORACLE_INCLUDE) $(INCLTDL)
RLM_SQL_LIBS	= $(SQL_ORACLE_LIBS)

$(DYNAMIC_OBJS): $(HEADERS) 

###
# over-ride the previous assignment if we're not building anything
ifeq ($(SQL_ORACLE_LIBS),)
TARGET        =
endif

include ../rules.mak

