# must be first
include config.mak

TARGET		= rlm_sql_mysql
SRCS		= sql_mysql.c
HEADERS		= sql_mysql.h
RLM_SQL_CFLAGS	= -I/usr/local/mysql/include
RLM_SQL_LIBS	= -L/usr/local/mysql/lib/mysql -lmysqlclient

$(DYNAMIC_OBJS): $(HEADERS) 

###
# over-ride the previous assignment if we're not building anything
ifeq ($(LIBMYSQL),)
TARGET        =
endif

include ../rules.mak

# must be last
config.mak:
	@../checkconfig -l LIBMYSQL mysql_init -lmysqlclient -L/usr/local/mysql/lib/mysql

