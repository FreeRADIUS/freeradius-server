TARGET		= rlm_sql.a
SOURCES		= rlm_sql.c sql.c
# this uses the RLM_CFLAGS and RLM_LIBS and SOURCES defs to make TARGET.

SUBMAKEFILES := $(wildcard ${top_srcdir}/src/modules/rlm_sql/drivers/rlm_sql_*/all.mk)
