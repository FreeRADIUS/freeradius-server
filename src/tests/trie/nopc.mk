TARGET		:= nopc$(E)

SRC_CFLAGS	:= -DTESTING -DNO_PATH_COMPRESSION -DDEFAULT_BITS=1
SOURCES		:= nopc.c
TGT_LDLIBS	:= $(LIBS)
TGT_PREREQS	:= libfreeradius-util$(L)

#
#  The build system maps one source file to one object file.  So in
#  order to build a test binary, we need to create a new source file.
#
#  We could move the test code into a "trie.c" file in this directory.
#  But it's useful for the test code to access internal functions /
#  definitions in the trie library.
#
src/tests/trie/nopc.c: ${top_srcdir}/src/lib/util/trie.c
	@[ -e $@ ] || ln -s $^ $@

${top_srcdir}/src/tests/trie/nopc.c: ${top_srcdir}/src/lib/util/trie.c
	@[ -e $@ ] || ln -s $^ $@
