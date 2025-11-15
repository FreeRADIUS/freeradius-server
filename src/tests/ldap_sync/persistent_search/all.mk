#
#	Tests against Persistent Search implementing LDAP directories
#

#
#	Test name
#
TEST := test.ldap_sync/persistent_search
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.ldif))

$(eval $(call TEST_BOOTSTRAP))

#
#	Generic rules to start /stop the radius service
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,radiusd,$(OUTPUT)))

$(TEST).trigger_clear:
	${Q}rm -f $(BUILD_DIR)/tests/ldap_sync/persistent_search/sync_started

$(OUTPUT)/%: $(DIR)/% | $(TEST).trigger_clear $(TEST).radiusd_kill $(TEST).radiusd_start
	$(eval TARGET   := $(notdir $<))
	$(eval EXPECTED := $(patsubst %.ldif,%.out,$<))
	$(eval FOUND    := $(patsubst %.ldif,%.out,$@))
	$(eval ARGV     := $(shell grep "#.*ARGV:" $< | cut -f2 -d ':'))
	$(eval OUT_DIR  := $(BUILD_DIR)/tests/ldap_sync/persistent_search)
	$(eval OUT      := $(shell grep "#.*OUT:" $< | cut -f2 -d ':'))

	${Q}echo "LDAPSYNC-TEST persistent_search $(TARGET)"
	${Q}[ -f $(dir $@)/radiusd.pid ] || exit 1
	${Q}rm -f $(OUT_DIR)/$(OUT).out

#	Wait for the sync to start before applying changes
	${Q}i=0; while [ $$i -lt 100 ] ; \
		do if [ -e $(OUT_DIR)/sync_started ] ;	\
		then					\
		break;					\
		fi;					\
		sleep .1;				\
		i=$$((i+1));				\
	done;

	${Q}ldapmodify $(ARGV) -f $< > /dev/null
	${Q}i=0; while [ $$i -lt 600 ] ; \
		do if [ -e $(OUT_DIR)/$(OUT).out ] ;	\
		then					\
		break;					\
		fi;					\
		sleep .1;				\
		i=$$((i+1));				\
	done ;
	${Q}sleep .1
	${Q}if [ ! -e $(OUT_DIR)/$(OUT).out ] ; then	\
		$(MAKE) --no-print-directory test.ldap_sync/persistent_search.radiusd_kill; \
		cat $(OUT_DIR)/radiusd.log;					\
		echo "LDAP_SYNC FAILED $(TARGET) - expected output file not produced";	\
		rm -rf $(BUILD_DIR)/tests/test.ldap_sync/persistent_search;	\
		exit 1;								\
	fi
	${Q}mv $(OUT_DIR)/$(OUT).out $(FOUND)

	${Q}if [ -e "$(EXPECTED)" ] && ! cmp -s $(FOUND) $(EXPECTED); then	\
		$(MAKE) --no-print-directory test.ldap_sync/persistent_search.radiusd_kill; \
		cat $(OUT_DIR)/radiusd.log;					\
		echo "LDAP_SYNC FAILED $(TARGET)";				\
		rm -rf $(BUILD_DIR)/tests/test.ldap_sync/persistent_search;	\
		exit 1;								\
	fi
	${Q}touch $@

$(TEST):
	${Q}$(MAKE) --no-print-directory $@.radiusd_stop
	@touch $(BUILD_DIR)/tests/$@
