TARGET		= rlm_sql_null$(L)
SOURCES		= rlm_sql_null.c

SRC_CFLAGS	= -I${top_srcdir}/src/modules/rlm_sql

$(call DEFINE_LOG_ID_SECTION,null,4,$(SOURCES))
