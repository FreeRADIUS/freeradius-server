ifneq "$(WITH_DHCP)" "no"
SUBMAKEFILES := libfreeradius-dhcp.mk proto_dhcp.mk rlm_dhcp.mk dhcpclient.mk
endif
