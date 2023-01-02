#!/usr/bin/env python3
#
# Test script for pyfr
# Copyright 2023 The FreeRADIUS server project
# Author: Jorge Pereira (jpereira@freeradius.org)
#

import pyfr

print("pyfr.version:                     {}".format(pyfr.version))
print("pyfr.version_build:               {}".format(pyfr.version_build))
print("pyfr.libfreeradius_version:       {}".format(pyfr.libfreeradius_version))
print("pyfr.libfreeradius_version_build: {}".format(pyfr.libfreeradius_version_build))
print("pyfr.version_info():              {}".format(pyfr.get_version_info()))
