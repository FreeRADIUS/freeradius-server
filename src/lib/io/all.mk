TARGET	:= libfreeradius-io.a

SOURCES	:= \
	app_io.c \
	atomic_queue.c \
	channel.c \
	control.c \
	load.c \
	master.c \
	message.c \
	network.c \
	queue.c \
	ring_buffer.c \
	schedule.c \
	time_tracking.c \
	worker.c

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
