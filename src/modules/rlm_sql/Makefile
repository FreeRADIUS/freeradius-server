# must be first
include config.mak

TARGET		= rlm_sql
SRCS		= rlm_sql.c sql.c
HEADERS		= rlm_sql.h
RLM_CFLAGS	=
LIBS		= -lmysqlclient

$(STATIC_OBJS): $(HEADERS)

$(DYNAMIC_OBJS): $(HEADERS) 

###
# over-ride the previous assignment if we're not building anything
ifeq ($(LIBMYSQL),)
TARGET        =
endif

include ../rules.mak

# must be last
config.mak:
	@../checkconfig -l LIBMYSQL mysql_init -lmysqlclient -L/usr/local/lib/mysql
