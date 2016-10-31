TARGET	:= libfreeradius-util.a

SOURCES	:=	ring_buffer.c message.c atomic_queue.c queue.c

TGT_PREREQS	:= libfreeradius-radius.la

${SRC_INCLUDE_DIR}/util/ring_buffer.h: src/include/util/ring_buffer.h

${SRC_INCLUDE_DIR}/util/message.h: src/include/util/message.h

${SRC_INCLUDE_DIR}/util/atomic_queue.h: src/include/util/atomic_queue.h

install.src.include: ${SRC_INCLUDE_DIR}/util/ring_buffer.h ${SRC_INCLUDE_DIR}/util/message.h ${SRC_INCLUDE_DIR}/util/atomic_queue.h
