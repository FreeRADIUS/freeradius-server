include ../../../../../Make.inc

TARGET		= rlm_sql_db2
SRCS		= sql_db2.c
HEADERS		= sql_db2.h
RLM_SQL_CFLAGS	= -I/usr/IBMdb2/V7.1/include $(INCLTDL)
RLM_SQL_LIBS	= -L/usr/IBMdb2/V7.1/lib -ldb2

$(DYNAMIC_OBJS): $(HEADERS) 

###
# over-ride the previous assignment if we're not building anything
ifeq ($(PQ_LIBS),)
TARGET        =
endif

include ../rules.mak
