#
#	Unit tests for radsniff against pcap packets.
#

#
#	Test name
#
TEST  := test.radsniff
FILES := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt $(DIR)/*.gz))

$(eval $(call TEST_BOOTSTRAP))

#
#	Run the radsniff commands
#
.PRECIOUS: $(OUTPUT)/%.pcap
$(OUTPUT)/%.pcap: $(DIR)/%.pcap.gz
	$(Q)gzcat $< > $@

$(OUTPUT)/%.txt: $(DIR)/%.txt $(OUTPUT)/%.pcap $(TESTBINDIR)/radsniff
	$(eval TARGET   := $(patsubst %.txt,%,$(notdir $@)))
	$(eval FOUND    := $@)
	$(eval CMD_TEST := $(patsubst %.txt,%.cmd,$<))
	$(eval EXPECTED := $<)
	$(eval PCAP_IN  := $(patsubst %.txt,%.pcap,$@))
	$(eval ARGV     := $(shell grep "^#.*ARGV:" $< | cut -f2 -d ':'))

	$(Q)echo "RADSNIFF-TEST INPUT=$(TARGET).pcap ARGV=\"$(ARGV)\""
	$(Q)if ! $(TESTBIN)/radsniff $(ARGV) -I $(PCAP_IN) -D share/dictionary 1> $(FOUND) 2>&1; then         \
		echo "FAILED";                                                                                \
		cat $(FOUND);                                                                                 \
		echo "RADSNIFF: $(TESTBIN)/radsniff $(ARGV) -I $(PCAP_IN) -D share/dictionary" -xx;           \
		rm -f $@;										      \
		exit 1;                                                                                       \
	fi
	$(Q)if [ -e "$(EXPECTED)" ]; then                                                                     \
		grep -v "^#" $(EXPECTED) > $(FOUND).result;                                                   \
		if ! cmp -s $(FOUND) $(FOUND).result; then                                                    \
			echo "RADSNIFF FAILED $@";                                                                \
			echo "RADSNIFF: $(TESTBIN)/radsniff $(ARGV) -I $(PCAP_IN) -D share/dictionary -xx";        \
			echo "ERROR: File $(FOUND).result is not the same as $(EXPECTED)";                        \
			echo "If you did some update on the radsniff code, please be sure to update the unit tests."; \
			echo "e.g: $(EXPECTED)";                                                                      \
			diff $(EXPECTED) $(FOUND).result;                                                             \
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
