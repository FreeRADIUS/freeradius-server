TARGETNAME := process_arp

#
#  ARP depends on pcap.
#
ifneq "$(PCAP_LIBS)" ""
TARGET		:= $(TARGETNAME)$(L)
endif

SOURCES		:= base.c
TGT_PREREQS	:= libfreeradius-arp$(L)
TGT_LDLIBS	:= $(PCAP_LIBS)
