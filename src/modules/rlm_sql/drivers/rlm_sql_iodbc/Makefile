include ../../../../../Make.inc

TARGET		= rlm_sql_iodbc
SRCS		= sql_iodbc.c
HEADERS		= sql_iodbc.h
RLM_SQL_CFLAGS	= $(SQL_ODBC_INCLUDE) $(INCLTDL)
RLM_SQL_LIBS	= $(SQL_ODBC_LIBS)

$(DYNAMIC_OBJS): $(HEADERS) 

###
# over-ride the previous assignment if we're not building anything
ifeq ($(SQL_ODBC_LIBS),)
TARGET        =
endif

include ../rules.mak

