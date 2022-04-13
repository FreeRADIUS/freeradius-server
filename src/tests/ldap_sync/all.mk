#
#
#
TEST := test.ldap_sync

#
#  Find all the LDAP syncs for which we have a configured server
#
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*/all.mk))

define LDAP_FILTER
ifeq "$($(shell echo ${1} | tr a-z A-Z)_TEST_SERVER)" ""
  FILES_SKIP += ${2}
endif
endef

$(foreach x,$(FILES),$(eval $(call LDAP_FILTER,$(firstword $(subst /, ,$x)),$x)))
FILES := $(filter-out $(FILES_SKIP),$(FILES))

#
#  Include the make file for each type of LDAP sync with a test server
#
SUBMAKEFILES := $(FILES)

#
#  Define target to run all ldap_sync tests
#
$(TEST): test.ldap_sync.dir $(patsubst %/all.mk,test.ldap_sync/%,$(FILES))

#
#  Ensure diretory for "touch" files exists
#
test.ldap_sync.dir:
	${Q}mkdir -p $(BUILD_DIR)/tests/test.ldap_sync
