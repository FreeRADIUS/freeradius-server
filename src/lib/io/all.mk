TARGET	:= libfreeradius-io$(L)
TGT_CATEGORY	:= lib-util

SOURCES	:= \
	app_io.c \
	atomic_queue.c \
	channel.c \
	control.c \
	coord.c \
	coord_pair.c \
	load.c \
	master.c \
	message.c \
	network.c \
	queue.c \
	ring_buffer.c \
	schedule.c \
	thread.c \
	worker.c

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL) libfreeradius-internal$(L) $(LIBFREERADIUS_SERVER)
TGT_LDLIBS	:= $(LIBS)
TGT_LDFLAGS	:= $(LDFLAGS)

HEADERS		:= $(subst src/lib/,,$(wildcard src/lib/io/*.h))
