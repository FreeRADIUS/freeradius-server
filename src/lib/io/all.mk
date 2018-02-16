TARGET	:= libfreeradius-io.a

SOURCES	:=	ring_buffer.c message.c atomic_queue.c queue.c time.c channel.c worker.c \
		schedule.c network.c control.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.la
TGT_LDLIBS	:= $(LIBS)
TGT_LDFLAGS	:= $(LDFLAGS)

#
#  Install all of the headers, too.
#  Each source file has it's own headers.
#
HEADERS :=	$(SOURCES:.c=.h)

define ADD_UTIL_HEADER
${SRC_INCLUDE_DIR}/io/${1}: src/include/io/${1} | ${SRC_INCLUDE_DIR}/io

install.src.include: ${SRC_INCLUDE_DIR}/io/${1}

src/freeradius-devel/io/${1}: | src/freeradius-devel/io
endef

#
#  Create the installation directory
#
.PHONY: ${SRC_INCLUDE_DIR}/io
${SRC_INCLUDE_DIR}/io:
	${Q}$(INSTALL) -d -m 755 $@

#
#  Create the build directory.
#
.PHONY: src/freeradius-devel/io
src/freeradius-devel/io:
	${Q}[ -e $@ ] || ln -s ${top_srcdir}/src/lib/io src/include

$(foreach x,$(HEADERS),$(eval $(call ADD_UTIL_HEADER,$x)))
