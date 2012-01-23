# We don't use boilermake here because we want to run the test-app
# as a self-contained system that runs boilermake.
#

all: run-tests

APP := ./test-app/build/bin/talk

.PHONY: run-tests
run-tests:
	${MAKE} clean
	${MAKE} -C test-app/
	${APP} > found.txt
	diff expected.txt found.txt
	${MAKE} -C test-app/ DESTDIR=`pwd`/R INSTALL=`pwd`/install-sh install
	find R/* -print > found-install.txt
	diff expected-install.txt found-install.txt
	${APP} > found.txt
	diff expected.txt found.txt
	${MAKE} -C test-app/ DESTDIR=`pwd`/R INSTALL=`pwd`/install-sh uninstall
	find R/* -print > found-install.txt
	diff empty-install.txt found-install.txt
	${MAKE} clean
	${MAKE} -C test-app/ LIBTOOL=JLIBTOOL DESTDIR=`pwd`/R INSTALL=`pwd`/install-sh all
	${APP} > found.txt
	diff expected.txt found.txt
	${MAKE} -C test-app/ LIBTOOL=JLIBTOOL DESTDIR=`pwd`/R INSTALL=`pwd`/install-sh install
# don't do "find", as we have *.la files installed, rather than *.a
	${APP} > found.txt
	diff expected.txt found.txt
	${MAKE} clean
	rm -rf R found found-install.txt

clean: clean.local

clean.local:
	${MAKE} -C test-app/ clean
	${MAKE} -C test-app/ LIBTOOL=x clean
	rm -rf ./R *~ found.txt found-install.txt

check-legacy:
	@grep '$$(' `find test-app/build/make -type f -name "*\.mk" -print` || true
	@grep ' /' `find test-app/build/make -type f -name "*\.mk" -print` || true
	@grep ' build' `find test-app/build/make -type f -name "*\.mk" -print` || true
