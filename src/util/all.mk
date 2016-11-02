TARGET	:= libfreeradius-util.a

SOURCES	:=	ring_buffer.c message.c atomic_queue.c queue.c time.c

TGT_PREREQS	:= libfreeradius-radius.la

#
#  Install all of the headers, too.
#  Each source file has it's own headers.
#
HEADERS :=	$(SOURCES:.c=.h)

define ADD_UTIL_HEADER
${SRC_INCLUDE_DIR}/util/${1}: src/include/util/${1}

install.src.include: ${SRC_INCLUDE_DIR}/util/${1}
endef

$(foreach x,$(HEADERS),$(eval $(call ADD_UTIL_HEADER,$x)))
