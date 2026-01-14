#
#	Tests against RFC4533 implementing LDAP directories
#

#
#	Test name
#
TEST := test.ldap_sync/rfc4533
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.ldif))
TEST_COUNT := $(words $(FILES))

$(eval $(call TEST_BOOTSTRAP))

#
#	Generic rules to start /stop the radius service
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,radiusd,$(OUTPUT)))

$(TEST).trigger_clear:
	${Q}rm -f $(BUILD_DIR)/tests/ldap_sync/rfc4533/sync_started

$(OUTPUT)/%: $(DIR)/% | $(TEST).trigger_clear $(TEST).radiusd_kill $(TEST).radiusd_start
	$(eval TARGET   := $(notdir $<))
	$(eval EXPECTED := $(patsubst %.ldif,%.out,$<))
	$(eval FOUND    := $(patsubst %.ldif,%.out,$@))
	$(eval ARGV     := $(shell grep "#.*ARGV:" $< | cut -f2 -d ':'))
	$(eval OUT_DIR  := $(BUILD_DIR)/tests/ldap_sync/rfc4533)
	$(eval OUT      := $(shell grep "#.*OUT:" $< | cut -f2 -d ':'))

	${Q}echo "LDAPSYNC-TEST rfc4533 $(TARGET)"
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
	done ;

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
		$(MAKE) --no-print-directory test.ldap_sync/rfc4533.radiusd_kill; \
		cat $(OUT_DIR)/radiusd.log;					\
		echo "LDAP_SYNC FAILED $(TARGET) - expected output file not produced";	\
		rm -rf $(BUILD_DIR)/tests/test.ldap_sync/rfc4533;		\
		exit 1;								\
	fi
	${Q}mv $(OUT_DIR)/$(OUT).out $(FOUND)
	${Q}if [ -e "$(EXPECTED)" ] && ! cmp -s $(FOUND) $(EXPECTED); then	\
		$(MAKE) --no-print-directory test.ldap_sync/rfc4533.radiusd_kill; \
		cat $(OUT_DIR)/radiusd.log;					\
		echo "LDAP_SYNC FAILED $(TARGET)";				\
		rm -rf $(BUILD_DIR)/tests/test.ldap_sync/rfc4533;		\
		exit 1;								\
	fi
	${Q}touch $@

$(TEST):
	$(eval OUT_DIR  := $(BUILD_DIR)/tests/ldap_sync/rfc4533)
	${Q}$(MAKE) --no-print-directory $@.radiusd_stop

#
#	Once all the individual tests are run, there should be cookies in the cookie log.
#	The site config has been set to write a cookie after each 2 changes - so the number
#	of cookies should be at least the number of tests / 2 since OpenLDAP sends a cookie
#	with each search result.
#	Since the tests open two searches, and each receives the cookeis, it can be more than
#	number of tests / 2.
#
	${Q}echo "LDAPSYNC-TEST rfc4533 cookie"
	${Q}if [ ! -e $(OUT_DIR)/cookielog.out ]; then		\
		echo "LDAP_SYNC FAILED $@ - no cookie stored";	\
		exit 1;						\
	fi
	${Q}if [ `grep -v -P 'Cookie = rid=\d{3},csn=\d{14}\.\d{6}Z#\d{6}#\d{3}#\d{6}' $(OUT_DIR)/cookielog.out | wc -l` -ne 0 ]; then	\
		echo "LDAP_SYNC FAILED $@ - invalid cookie stored";	\
		rm -f $(BUILD_DIR)/tests/test.ldap_sync/rfc4533;	\
		$(MAKE) --no-print-direcotry test.ldap_sync/rfc4533.radiusd_kill; \
		exit 1;							\
	fi
	${Q}if [ "`cat $(OUT_DIR)/cookielog.out | wc -l`" -lt "`expr $(TEST_COUNT) / 2`" ]; then \
		echo "LDAP_SYNC_FAILED $@ - insufficient cookies stored";	\
		exit 1;								\
	fi

	@touch $(BUILD_DIR)/tests/$@
