TARGET		:= trie

SRC_CFLAGS	:= -DTESTING
SOURCES		:= trie.c
TGT_LDLIBS	:= $(LIBS)
TGT_PREREQS	:= libfreeradius-util.a
