TARGET	:= libfreeradius-util.a

SOURCES	:=	ring_buffer.c message.c

TGT_PREREQS	:= libfreeradius-radius.la

${SRC_INCLUDE_DIR}/util/ring_buffer.h: src/include/util/ring_buffer.h

${SRC_INCLUDE_DIR}/util/message.h: src/include/util/message.h

install.src.include: ${SRC_INCLUDE_DIR}/util/ring_buffer.h ${SRC_INCLUDE_DIR}/util/message.h
