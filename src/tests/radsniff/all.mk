#
#	Unit tests for radsniff against pcap packets.
#

#
#	.pcap file to be injested.
#
#	It was generated with:
#	e.g:
#
#	TZ=UTC tcpdump -i lo0 -c100 -w radius-auth+acct+coa-100pkts.pcap "port 1812 or port 1813 or port 3799"
#
#	NOTE: The src/tests/radsniff/radius-auth+acct+coa-100pkts.pcap.gz will be fetched during "git pull"
#	if the system has the "git lfs" installed properly. if not, it will be ignored.
#
PCAP_IN := $(BUILD_DIR)/tests/radsniff/radius-auth+acct+coa-100pkts.pcap

ifeq "$(GIT_HAS_LFS)" "no"
test.radsniff:
	$(Q)echo "WARNING: Can't execute 'test.radsniff' without 'git lfs' installed. ignoring."
else

#
#	Test name
#
TEST  := test.radsniff
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

$(eval $(call TEST_BOOTSTRAP))

#
#	Uncompress the input .pcap file
#
#
.PRECIOUS: $(OUTPUT)/%.pcap
$(OUTPUT)/%.pcap: $(DIR)/%.pcap.gz
	$(Q)gunzip -c $< > $@

#
#	Run the radsniff commands
#
$(OUTPUT)/%.txt: $(DIR)/%.txt $(TEST_BIN_DIR)/radsniff $(PCAP_IN)
	$(eval TARGET   := $(notdir $@))
	$(eval FOUND    := $(patsubst %.txt,%.out,$@))
	$(eval CMD_TEST := $(patsubst %.txt,%.cmd,$<))
	$(eval EXPECTED := $<)
	$(eval ARGV     := $(shell grep "^#.*ARGV:" $< | cut -f2 -d ':'))

	$(Q)echo "RADSNIFF-TEST INPUT=$(TARGET) ARGV=\"$(ARGV)\""
#
# 	We need that 'TZ=UTC ...' to libpcap pass the same timestamp in anywhere.
#
	$(Q)if ! TZ='UTC' $(TEST_BIN)/radsniff $(ARGV) -I $(PCAP_IN) -D share/dictionary 1> $(FOUND); then     \
		echo "FAILED";                                                                                \
		cat $(FOUND);                                                                                 \
		echo "RADSNIFF: TZ='UTC' $(TEST_BIN)/radsniff $(ARGV) -I $(PCAP_IN) -D share/dictionary" -xx;  \
		rm -f $@;										      \
		exit 1;                                                                                       \
	fi
	$(Q)if [ -e "$(EXPECTED)" ]; then                                                                     \
		grep -v "^#" $(EXPECTED) > $(FOUND).result || true;                                           \
		if ! cmp $(FOUND) $(FOUND).result; then                                                       \
			echo "RADSNIFF FAILED $@";                                                                \
			echo "RADSNIFF: $(TEST_BIN)/radsniff $(ARGV) -I $(PCAP_IN) -D share/dictionary -xx";        \
			echo "ERROR: File $(FOUND).result is not the same as $(EXPECTED)";                        \
			echo "If you did some update on the radsniff code, please be sure to update the unit tests."; \
			echo "e.g: $(EXPECTED)";                                                                      \
			diff $(FOUND) $(FOUND).result;                                                                \
			rm -f $@;										      \
			exit 1;                                                                                       \
		fi; \
	elif [ -e "$(CMD_TEST)" ] && ! $(SHELL) $(CMD_TEST); then                                             \
		echo "RADSNIFF FAILED $@";                                                                    \
		echo "RADSNIFF:   $(RADIUSD_RUN)";                                                            \
		echo "ERROR: The script $(CMD_TEST) can't validate the content of $(FOUND)";                  \
		echo "If you did some update on the radsniff code, please be sure to update the unit tests."; \
		rm -f $@;										      \
		exit 1;                                                                                       \
	else                                                                                                  \
		echo "ERROR! We should have at least one .txt or .cmd test";                                  \
		exit 1;                                                                                       \
	fi
	$(Q)touch $@
endif
