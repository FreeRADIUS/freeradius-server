# must be first
include config.mak

TARGET		= rlm_sql_iodbc
SRCS		= sql_iodbc.c
HEADERS		= sql_iodbc.h
RLM_SQL_CFLAGS	=
RLM_SQL_LIBS	=

$(DYNAMIC_OBJS): $(HEADERS) 

###
# over-ride the previous assignment if we're not building anything
ifeq ($(LIBIODBC),)
TARGET        =
endif

include ../rules.mak

# must be last
config.mak:
	@../checkconfig -l IODBC odbc_init -liodbc -L/usr/local/iodbc/lib

