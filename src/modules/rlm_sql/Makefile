# must be first
include config.mak

TARGET		= rlm_mysql
SRCS		= rlm_mysql.c mysql.c
HEADERS		= rlm_mysql.h
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
