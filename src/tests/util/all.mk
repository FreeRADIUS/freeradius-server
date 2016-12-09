SUBMAKEFILES := ring_buffer_test.mk message_set_test.mk atomic_queue_test.mk control_test.mk

#
#  This requires pthread.
#
ifneq "$(findstring thread,${CFLAGS})" ""
SUBMAKEFILES += channel_test.mk
endif
