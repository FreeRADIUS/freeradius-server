#
#	Unit tests for totp+radclient against the radiusd/rlm_totp.
#

#
#	Test name
#
TEST  := test.totp
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt.in))

$(eval $(call TEST_BOOTSTRAP))

#
#  Ensure that the digest tests are run if the server or rlm_digest module changes
#
$(FILES.$(TEST)): $(BUILD_DIR)/lib/rlm_totp.la $(BUILD_DIR)/bin/radiusd$(E) $(BUILD_DIR)/bin/radclient$(E)

#
#	Config settings
#
TOTP_BUILD_DIR  := $(BUILD_DIR)/tests/totp
TOTP_RADIUS_LOG := $(RADCLIENT_BUILD_DIR)/radiusd.log
TOTP_GDB_LOG    := $(RADCLIENT_BUILD_DIR)/gdb.log

#
#	Client port
#
RADCLIENT_CLIENT_PORT := 1234

#
#	Get the TOTP token
#
TOTP_KEY := 12345678901234567890
export TOTP_KEY

#
#  Generic rules to start / stop the radius service.
#
CLIENT := radclient
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,radiusd,$(OUTPUT)))

#
#	Run the radclient commands against the radiusd.
#
$(OUTPUT)/%: $(DIR)/% | $(TEST).radiusd_kill $(TEST).radiusd_start
	$(eval TARGET_IN     := $(patsubst %.txt.in,%.txt,$<))
	$(eval TARGET        := $(notdir $(TARGET_IN))$(E))
	$(eval EXPECTED      := $(patsubst %.txt.in,%.out,$<))
	$(eval FOUND         := $(patsubst %.txt.in,%.out,$@))
	$(eval TOTP_GEN_ARGV := $(shell grep "#.*ARGV:" $< | cut -f2 -d ':'))
	$(eval TOTP_TOKEN    := $(shell $(top_srcdir)/scripts/totp/totp-gen.py -k $(TOTP_KEY) $(TOTP_GEN_ARGV)))

	${Q}echo "TOTP-TEST INPUT=$(TARGET) TOKEN=$(TOTP_TOKEN) TOTP_GEN_ARGV=\"$(TOTP_GEN_ARGV)\""
	${Q}[ -f $(dir $@)/radiusd.pid ] || exit 1
#
#	Create the 'expected' with generated otp token
#

	${Q}sed "s/%TOTP_TOKEN%/$(TOTP_TOKEN)/g" $< > $(TARGET_IN)
	${Q}sed "s/%TOTP_TOKEN%/$(TOTP_TOKEN)/g" $(EXPECTED).in > $(EXPECTED)
	${Q}if ! $(TEST_BIN)/radclient -f $(TARGET_IN) -xF -d src/tests/totp/config -D share/dictionary 127.0.0.1:$(totp_port) auth $(SECRET) 1> $(FOUND) 2>&1; then \
		echo "FAILED";                                              \
		cat $(FOUND);                                               \
		rm -f $(BUILD_DIR)/tests/test.totp;		                    \
		$(MAKE) --no-print-directory test.totp.radiusd_kill;        \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "RADCLIENT: $(TEST_BIN)/radclient -f $(TARGET_IN) -xF -d src/tests/totp/config -D share/dictionary 127.0.0.1:$(totp_port) auth $(SECRET)"; \
		exit 1;                                                     \
	fi
#
#	Lets normalize the loopback interface on OSX and FreeBSD
#
	${Q}if [ "$$(uname -s)" = "Darwin" ]; then sed -i.bak 's/via lo0/via lo/g' $(FOUND); fi
	${Q}if [ "$$(uname -s)" = "FreeBSD" ]; then sed -i.bak 's/via (null)/via lo/g' $(FOUND); fi
#
#	Remove all entries with "^_EXIT.*CALLED .*/"
#	It is necessary to match all builds with/without -DNDEBUG
#
	${Q}sed -i.bak '/^_EXIT.*CALLED .*/d' $(FOUND)
#
#	Ignore spurious output from jlibtool when VERBOSE=1
#
	${Q}sed -i.bak '$${/Executing: /d;}' $(FOUND)
#
#	Checking.
#
#	diff between src/test/totp/$test.out & build/test/totp/$test.out
#
	${Q}if ! diff -I 'Sent' -I 'Received' $(EXPECTED) $(FOUND); then  \
		echo "RADCLIENT FAILED $@";                                 \
		echo "RADIUSD:   $(RADIUSD_RUN)";                           \
		echo "RADCLIENT: $(TEST_BIN)/radclient -f $(TARGET_IN) -xF -d src/tests/totp/config -D share/dictionary 127.0.0.1:$(totp_port) auth $(SECRET)"; \
		echo "ERROR: File $(FOUND) is not the same as $(EXPECTED)"; \
		echo "If you did some update on the radclient code, please be sure to update the unit tests."; \
		echo "e.g: $(EXPECTED)";                                    \
		diff -I 'Sent' -I 'Received' $(EXPECTED) $(FOUND);                                  \
		rm -f $(BUILD_DIR)/tests/test.totp;		    \
		$(MAKE) --no-print-directory test.totp.radiusd_kill;   \
		exit 1;                                                     \
	fi
	${Q}touch $@

.NO_PARALLEL: $(TEST)
$(TEST):
	${Q}$(MAKE) --no-print-directory $@.radiusd_stop
	@touch $(BUILD_DIR)/tests/$@
