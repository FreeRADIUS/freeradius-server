#
#  This Makefile performs some end to end tests against a package installed
#  within the CI environment.
#
#  It reuses the eapol_test build-time tests, but runs them against the assets
#  installed by the distribution packaging.
#
#  We want the run-time environment to be lean, typical of a fresh system
#  installation so that we catch any missing runtime dependancies, assets
#  missing from the packages, issues with the dynamic loader, etc.
#
#  Therefore we skip the usual build framework so that we do not have so
#  configure the build tree and so that our only dependency is some non-ancient
#  version GNU Make. (Any version in a supported distribution will do.)
#

#
#  For the package tests we use the system version of radiusd on the standard
#  port
#
RADIUSD_BIN := $(shell which radiusd || which freeradius)
PORT := 1812
SECRET := testing123
DICT_PATH := /usr/share/freeradius

ifneq (,$(wildcard /etc/raddb/radiusd.conf))
RADDB_PATH := /etc/raddb/
else
RADDB_PATH := /etc/freeradius/
endif

#
#  We prefer to use our exactly eapol_test version
#
EAPOL_TEST := $(shell ./scripts/ci/eapol_test-build.sh)

MAKE_ARGS := RADIUSD_BIN=$(RADIUSD_BIN) PORT=$(PORT) SECRET="$(SECRET)" DICT_PATH=$(DICT_PATH) RADDB_PATH=$(RADDB_PATH)

.PHONY: package-test
package-test:
	cp -r $(RADDB_PATH)/certs/* raddb/certs
	$(MAKE) -C src/tests $(MAKE_ARGS) tests.eap
