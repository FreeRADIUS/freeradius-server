#
#  This module is in the source, but not yet fully integrated with
#  the configure scripts.  For now, manual editing of this file is
#  required to get it to build.
#
include ../../../../../Make.inc

TARGET		=
#TARGET         = rlm_sql_sybase
SRCS           = rlm_sql_sybase.c
RLM_SQL_CFLAGS =   -I/opt/sybase/OCS-12_0/include
RLM_SQL_LIBS   =  -L/opt/sybase/OCS-12_0/lib -ltcl -lcomn -lintl -lnsl -ldl -lm -lcs -lct

include ../rules.mak
