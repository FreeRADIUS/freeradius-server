# must be first
include config.mak

TARGET		= rlm_sql_postgresql
SRCS		= sql_postgresql.c
HEADERS		= sql_postgresql.h
RLM_SQL_CFLAGS	=
RLM_SQL_LIBS	=

$(DYNAMIC_OBJS): $(HEADERS) 

###
# over-ride the previous assignment if we're not building anything
ifeq ($(LIBPG),)
TARGET        =
endif

include ../rules.mak

# must be last
config.mak:
	@../checkconfig -l LIBPG pg_init -lpg -L/usr/local/pg/lib

