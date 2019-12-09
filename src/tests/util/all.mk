SUBMAKEFILES := ring_buffer_test.mk message_set_test.mk atomic_queue_test.mk 

#
#  This uses an old API, and we don't have time to fix it.
#
#control_test.mk 

#
#  These require pthread.
#
#ifneq "$(findstring thread,${CFLAGS})" ""
#SUBMAKEFILES += channel_test.mk worker_test.mk radius1_test.mk schedule_test.mk radius_schedule_test.mk
#endif
