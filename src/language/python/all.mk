TARGETNAME := build.language.python
TGT_PREREQS := libfreeradius-internal$(L) libfreeradius-util$(L) libfreeradius-radius$(L)

SOURCES = src/language/python/src/module.c \
	  src/language/python/src/radius.c \
	  src/language/python/src/util.c

ifneq "${VERBOSE}" ""
	export DISTUTILS_DEBUG=1
	export VERBOSE=1
endif

export CFLAGS CPPFLAGS LDFLAGS LIBS top_builddir

build/language/python:
	$(Q)mkdir -p $@

build.language.python: $(SOURCES)
	@echo "BUILD LANGUAGE python (pyfr)"
	$(Q)cd src/language/python/ && python3 setup.py -v build

install.language.python: build/language/python build.language.python
	@echo "INSTALL LANGUAGE python (pyfr)"
	$(Q)cd src/language/python/ && python3 setup.py install --record $(top_builddir)/build/language/python/install.txt

uninstall.language.python:
	@echo "UNINSTALL LANGUAGE python (pyfr)"
	$(Q)xargs rm -rfv < $(top_builddir)/build/language/python/install.txt

clean.language.python:
	@echo "CLEAN LANGUAGE python (pyfr)"
	$(Q)cd src/language/python/ && python3 setup.py clean
	$(Q)rm -f *~
	$(Q)rm -rf build

test.language.python: language.python.build
	@echo "TEST LANGUAGE python (pyfr)"
	$(Q)cd src/language/python/ && ./tests/run.sh
