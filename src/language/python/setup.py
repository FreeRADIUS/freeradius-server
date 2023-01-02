#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vi:ts=4:et

#
# Python bindings for libfreeradius
#
# @copyright Network RADIUS SAS(legal@networkradius.com)
# @author Jorge Pereira <jpereira@freeradius.org>
#

"""Setup script for the PyFr module distribution."""
PACKAGE = "pyfr"
PY_PACKAGE = "fr"
VERSION = "0.0.1"

import os
from distutils.core import setup, Extension

#
# Remove it only for now.
#
STRIP_CFLAGS = [
    "-Werror"
]

def fr_get_env(_env, _strip=[]):
    ret = []
    _e = os.getenv(_env)
    if _e:
        _e.replace("src/", "../../../src/") # Fix path
        for _k in _e.split():
            if _k not in _strip:
                ret.append(_k)
    return ret

BUILD_DIR = ''.join(fr_get_env("top_builddir")) + "/build"
CFLAGS = fr_get_env("CFLAGS", STRIP_CFLAGS)
CPPFLAGS = fr_get_env("CPPFLAGS", STRIP_CFLAGS)
LIBS = fr_get_env("LIBS")
LDFLAGS = fr_get_env("LDFLAGS")
LDFLAGS += [
    "-L{}/lib/local/.libs/".format(BUILD_DIR), # Hardcode just for now
    "-lfreeradius-radius",
    "-lfreeradius-internal",
    "-lfreeradius-util"
]

# TODO: It should be based in some 'version.h.in'
CFLAGS.append("-DMODULE_NAME=\"{}\"".format(PACKAGE))
CFLAGS.append("-DPYFR_VERSION={}".format(VERSION))
CFLAGS.append("-DPYFR_VERSION_MAJOR={}".format(VERSION.split('.')[0]))
CFLAGS.append("-DPYFR_VERSION_MINOR={}".format(VERSION.split('.')[1]))
CFLAGS.append("-DPYFR_VERSION_INCRM={}".format(VERSION.split('.')[2]))

if os.getenv("VERBOSE"):
    print("########## Debug")
    print("CFLAGS   = '{}'".format(' '.join(CFLAGS)))
    print("CPPFLAGS = '{}'".format(' '.join(CPPFLAGS)))
    print("LDFLAGS  = '{}'".format(' '.join(LDFLAGS)))
    print("LIBS     = '{}'".format(' '.join(LIBS)))

if __name__ == "__main__":
    ext = Extension(name = PACKAGE,
                    sources = [
                        "src/module.c",
                        "src/util.c",
                        "src/radius.c"
                    ],
                    include_dirs = [
                        "../../../",
                        "../../"
                    ],
                    libraries = [
                        "freeradius-util",
                        "freeradius-radius",
                        "freeradius-internal"
                    ],
                    extra_compile_args = CFLAGS + CPPFLAGS,
                    extra_link_args = LIBS + LDFLAGS,
                    undef_macros=['NDEBUG'] # The FreeRADIUS API should decided that.
          )

    setup_args = dict(
            name=PACKAGE,
            version=VERSION,
            description = 'PyFr -- A Python Interface To The libfreeradius libraries',
            python_requires='>=3.10',
            platforms = "All",
            ext_modules = [ext],
        )
    setup(**setup_args)
