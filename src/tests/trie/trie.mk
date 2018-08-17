TARGET		:= trie

SRC_CFLAGS	:= -DTESTING
SOURCES		:= trie.c
TGT_LDLIBS	:= $(LIBS)
TGT_PREREQS	:= libfreeradius-util.a

#
#  The build system maps one source file to one object file.  So in
#  order to build a test binary, we need to create a new source file.
#
#  We could move the test code into a "trie.c" file in this directory.
#  But it's useful for the test code to access internal functions /
#  definitions in the trie library.
#
src/tests/trie/trie.c: ${top_srcdir}/src/lib/util/trie.c
	@[ -e $@ ] || ln -s $^ $(dir $@)

${top_srcdir}/src/tests/trie/trie.c: ${top_srcdir}/src/lib/util/trie.c
	@[ -e $@ ] || ln -s $^ $(dir $@)
