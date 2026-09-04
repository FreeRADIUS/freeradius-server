TARGET := libfreeradius-bio$(L)
TGT_CATEGORY	:= lib-util

SOURCES	:=		\
	base.c		\
	buf.c		\
	fd.c		\
	fd_open.c	\
	haproxy.c	\
	mem.c		\
	network.c	\
	null.c		\
	packet.c	\
	pipe.c		\
	queue.c		\
	dedup.c		\
	retry.c

TGT_PREREQS	:= $(LIBFREERADIUS_UTIL)
