# must be first
include config.mak

TARGET	= rlm_mysql
SRCS	= rlm_mysql.c mysql.c
LIBS	= -lmysql

# over-ride the previous assignment if we're not building anything
ifeq ($(LIBMYSQL),)
TARGET	=
endif

include ../rules.mak

# must be last
config.mak:
	@../checkconfig -l LIBMYSQL mysql_init -lmysql
