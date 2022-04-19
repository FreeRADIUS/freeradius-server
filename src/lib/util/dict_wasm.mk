TARGET		:= dict.wasm

SRC_CC          := emcc
SRC_CFLAGS      := ''

SOURCES		:= dict_ext.c \
		   dict_fixup.c \
		   dict_print.c \
		   dict_tokenize.c \
		   dict_unknown.c \
		   dict_util.c \
