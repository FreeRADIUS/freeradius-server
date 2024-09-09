# -*- text -*-
# Copyright (C) 2024 The FreeRADIUS Server project and contributors
# This work is licensed under CC-BY version 4.0 https://creativecommons.org/licenses/by/4.0
# Version $Id$

#
#  Vendor options used by CTS equipment for DHCP auto provisioning
#
#  Taken from support documentation including
#  https://www.ctsystem.com/wp-content/uploads/CTS_HES_3106_PLUS_-NMS_V0.92_20150812.pdf
#

VENDOR		CTS				9304

BEGIN-VENDOR	CTS

ATTRIBUTE	Protocol				1	uint8
ATTRIBUTE	Server-IP				2	ipaddr
ATTRIBUTE	Server-Login-Name			3	string
ATTRIBUTE	Server-Login-Password			4	string
ATTRIBUTE	Firmware-File-Name			5	string
ATTRIBUTE	Firmware-MD5				6	octets
ATTRIBUTE	Configuration-File-Name			7	string
ATTRIBUTE	Configuration-MD5			8	octets
ATTRIBUTE	Option					9	uint16

END-VENDOR	CTS

