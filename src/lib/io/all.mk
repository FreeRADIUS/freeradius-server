TARGET	:= libfreeradius-io.a

SOURCES	:=	ring_buffer.c message.c atomic_queue.c queue.c time.c channel.c track.c worker.c \
		schedule.c network.c control.c radius_server_udp.c

TGT_PREREQS	:= libfreeradius-util.la
TGT_LDLIBS	:= $(LIBS)
TGT_LDFLAGS	:= $(LDFLAGS)

#
#  Install all of the headers, too.
#  Each source file has it's own headers.
#
HEADERS :=	$(SOURCES:.c=.h)

define ADD_UTIL_HEADER
${SRC_INCLUDE_DIR}/io/${1}: src/include/io/${1}

install.src.include: ${SRC_INCLUDE_DIR}/io/${1}
endef

$(foreach x,$(HEADERS),$(eval $(call ADD_UTIL_HEADER,$x)))
