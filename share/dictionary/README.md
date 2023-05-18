# Dictionary files for FreeRADIUS

WARNING: **DO NOT EDIT THE FILES IN THIS DIRECTORY**

The files in this directory are maintained by the FreeRADIUS project.
Newer releases of software may update or change these files. Any edits
you make to these files will be over-written when an updated version
of the software is installed.

Please use the site-local dictionary file (usually `/etc/raddb/dictionary`)
for local attributes.  See that file for more documentation on how it works.

The files in this directory contains dictionary translations for
"binary" protocol data to/from "humanly readable" names.

## File Format

Please see the official documentation for full details of the
dictionary file format.

While these files are _mostly_ compatible with the original dictionary
files used since 1993, we have made some changes, and added new
features.  Those differences cannot be documented in a short "readme"
file.

## Protocol Registry

The following is a list of protocols currently supported in the
dictionaries.  It is here for informational purposes only.

```
git grep -h '^PROTOCOL' | sort -nk 3
```

## Current Protocols

PROTOCOL        RADIUS          1
PROTOCOL        DHCPv4          2
PROTOCOL        DHCPv6          3
PROTOCOL        Ethernet        4
PROTOCOL        TACACS          5	format=string
PROTOCOL        VMPS            6       format=2
PROTOCOL        SNMP            7       format=4
PROTOCOL        ARP             8
PROTOCOL        TFTP            9
PROTOCOL        TLS             10
PROTOCOL        DNS             11
PROTOCOL        LDAP            12
PROTOCOL        BFD		13
PROTOCOL        EAP-SIM         101
PROTOCOL        EAP-AKA         102
PROTOCOL        EAP-FAST         103
PROTOCOL        Control         255
