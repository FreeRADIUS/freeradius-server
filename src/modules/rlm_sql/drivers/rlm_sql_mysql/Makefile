include ../../../../../Make.inc

TARGET		= rlm_sql_mysql
SRCS		= sql_mysql.c
HEADERS		= sql_mysql.h
RLM_SQL_CFLAGS	= $(SQL_MYSQL_INCLUDE)
RLM_SQL_LIBS	= $(SQL_MYSQL_LIBS)

$(DYNAMIC_OBJS): $(HEADERS) 

###
# over-ride the previous assignment if we're not building anything
ifeq ($(SQL_MYSQL_LIBS),)
TARGET		=
endif

include ../rules.mak



