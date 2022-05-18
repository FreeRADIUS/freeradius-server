TARGET		:= rlm_sql$(L)
SOURCES		:= rlm_sql.c sql.c sql_state.c

SRC_CFLAGS	:= $(rlm_sql_CFLAGS)
TGT_LDLIBS	:= $(rlm_sql_LDLIBS)
LOG_ID_LIB	= 50
