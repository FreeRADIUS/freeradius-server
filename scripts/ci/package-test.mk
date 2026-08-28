#
#  This Makefile performs some end to end tests against a package installed
#  within the CI environment.
#
#  It reuses the eapol_test build-time tests, but runs them against the assets
#  installed by the distribution packaging.
#
#  We want the run-time environment to be lean, typical of a fresh system
#  installation so that we catch any missing runtime dependencies, assets
#  missing from the packages, issues with the dynamic loader, etc.
#
#  Therefore we skip the usual build framework so that we do not have so
#  configure the build tree and so that our only dependency is some non-ancient
#  version GNU Make. (Any version in a supported distribution will do.)
#

ifeq "${VERBOSE}" ""
    Q=@
else
    Q=
endif


#  Provide what test.eap needs
top_srcdir:=.
BUILD_DIR:=build
DIR:=src/tests/eapol_test
OUTPUT:=$(BUILD_DIR)/tests/eapol_test
PACKAGE_TEST:=true

ALL_TGTS:=$(addprefix rlm_eap_,$(notdir $(subst -,_,$(patsubst %.conf,%.la,$(wildcard $(DIR)/*.conf)))))

#
#  For the package tests we use the system version of radiusd on the standard
#  port
#
RADIUSD_BIN:=$(shell which radiusd || which freeradius)
PORT:=1812
SECRET:=testing123
DICT_PATH:=/usr/share/freeradius/dictionary/

#
#  We assume a preinstalled version of eapol_test
#
EAPOL_TEST:=$(shell which eapol_test)

# This Makefile, for meta-making
POST_INSTALL_MAKEFILE_ARG:=-f $(CURDIR)/$(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))

POST_INSTALL_RADIUSD_BIN_ARG:=RADIUSD_BIN=$(RADIUSD_BIN)

.PHONY: package-test
package-test: test.eap

include $(DIR)/all.mk

#
#  all.mk gates every EAP test on EAPOL_TEST, and the gate closes quietly, so
#  a missing eapol_test turns into a green run that tested nothing.  all.mk
#  can also blank EAPOL_TEST after the assignment above, so check the value
#  here rather than next to the assignment.
#
ifeq "$(EAPOL_TEST)" ""
$(error Aborting the package test, because neither which nor scripts/ci/eapol_test-build.sh found an eapol_test. Install eapol_test before running scripts/ci/package-test.mk)
endif
