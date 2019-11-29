TARGET	:= libfreeradius-io.a

SOURCES	:=	ring_buffer.c message.c atomic_queue.c queue.c channel.c worker.c \
		schedule.c network.c control.c master.c app_io.c load.c

TGT_PREREQS	:= $(LIBFREERADIUS_SERVER) libfreeradius-util.la
TGT_LDLIBS	:= $(LIBS)
TGT_LDFLAGS	:= $(LDFLAGS)

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/io/*.h))

#
#  Create the build directory.
#
.PHONY: src/freeradius-devel/io
src/freeradius-devel/io:
	${Q}[ -e $@ ] || ln -s ${top_srcdir}/src/lib/io ${top_srcdir}/src/include
