#
#	Tests against Persistent Search implementing LDAP directories
#

#
#	Test name
#
TEST := test.ldap_sync/active_directory
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.sh))

$(eval $(call TEST_BOOTSTRAP))

#
#	Generic rules to start /stop the radius service
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,radiusd,$(OUTPUT)))

$(TEST).trigger_clear:
	${Q}rm -f $(BUILD_DIR)/tests/ldap_sync/active_directory/sync_started

#
#	There is a delay of up to 30 seconds looking for the output file
#	as samba only sends results of persistent LDAP searches on a polled
#	basis.  Real Active Directory sends the results immediately.
#
$(OUTPUT)/%: $(DIR)/% | $(TEST).trigger_clear $(TEST).radiusd_kill $(TEST).radiusd_start
	$(eval TARGET   := $(notdir $<))
	$(eval EXPECTED := $(patsubst %.sh,%.out,$<))
	$(eval FOUND    := $(patsubst %.sh,%.out,$@))
	$(eval OUT      := $(shell grep "#.*OUT:" $< | cut -f2 -d ':'))
	$(eval OUT_DIR  := $(BUILD_DIR)/tests/ldap_sync/active_directory)

	${Q}echo "LDAPSYNC-TEST active_directory $(TARGET)"
	${Q}[ -f $(dir $@)/radiusd.pid ] || exit 1
	${Q}rm -f $(OUT_DIR)/$(OUT).out

#	Wait for the sync to start before applying changes
	${Q}i=0; while [ $$i -lt 100 ] ; \
		do if [ -e $(OUT_DIR)/sync_started ];	\
		then					\
		break;					\
		fi;					\
		sleep .1;				\
		i=$$((i+1));				\
	done;

	${Q}$<
	${Q}i=0; while [ $$i -lt 600 ] ; \
		do if [ -e $(OUT_DIR)/$(OUT).out ] ;	\
		then					\
		break;					\
		fi;					\
		sleep .1;				\
		i=$$((i+1));				\
	done ;
	${Q}sleep .5
	${Q}if [ ! -e $(OUT_DIR)/$(OUT).out ] ; then	\
		$(MAKE) --no-print-directory test.ldap_sync/active_directory.radiusd_kill; \
		cat $(OUT_DIR)/radiusd.log;					\
		echo "LDAP_SYNC FAILED $(TARGET) - expected output file not produced";	\
		rm -rf $(BUILD_DIR)/tests/test.ldap_sync/active_directory;	\
		exit 1;								\
	fi
	${Q}mv $(OUT_DIR)/$(OUT).out $(FOUND)

	${Q}if [ -e "$(EXPECTED)" ] && ! cmp -s $(FOUND) $(EXPECTED); then	\
		$(MAKE) --no-print-directory test.ldap_sync/active_directory.radiusd_kill; \
		cat $(OUT_DIR)/radiusd.log;					\
		echo "LDAP_SYNC FAILED $(TARGET)";				\
		rm -rf $(BUILD_DIR)/tests/test.ldap_sync/active_directory;	\
		exit 1;								\
	fi
	${Q}touch $@

$(TEST):
	${Q}$(MAKE) --no-print-directory $@.radiusd_stop
	@touch $(BUILD_DIR)/tests/$@
