#
#  Wire protocol fuzzers. Each one needs a test point for packet
#  decoding (see src/protocols/radius/decode.c for an example) and
#  a libfreeradius-<name> library to load. The per-protocol fuzzer
#  source / makefile are generated from src/fuzzer/fuzzer.c and
#  src/fuzzer/fuzzer.mk via FUZZ_PROTOCOL below.
#
FUZZER_PROTOCOLS = radius dhcpv4 dhcpv6 dns tacacs vmps tftp bfd cbor arp

#
#  Standalone fuzzer targets - each has a hand-written fuzzer_<name>.c
#  and fuzzer_<name>.mk under src/fuzzer/. Listed separately so the
#  scheduled fuzzing workflow can pick them up alongside the wire
#  protocols. util uses the same test_point / dictionary machinery
#  as a wire protocol (see src/lib/util/fuzzer.c) but isn't itself
#  a network protocol, so it lives here too.
#
FUZZER_NON_PROTOCOL_TARGETS = util json value cf xlat base16_32_64 tmpl der

#
#  Build these fuzzers, but skip them in CI.
#
FUZZER_NO_TEST = cf xlat tmpl der

#
#  Per-target extra arguments passed to the fuzzer binary. util uses
#  the per-protocol fuzzer.c shape and needs -D to find the dictionary;
#  json / cf / value / xlat are standalone parsers that don't.
#
FUZZER_util_ARGS  := -D share/dictionary
FUZZER_tmpl_ARGS  := -D share/dictionary
FUZZER_xlat_ARGS  := -D share/dictionary
FUZZER_der_ARGS   := -D share/dictionary

#
#  Add the fuzzer only if everything was built with the fuzzing flags.
#
ifneq "$(findstring fuzzer,${CFLAGS})" ""

#
#  Put the output artifacts into the build directory, but only if the
#  variable is not already set by the environment or make files.
#
FUZZER_ARTIFACTS ?= ${BUILD_DIR}/fuzzer

#
#  Time out "test.fuzzer.foo" after this number of seconds
#
FUZZER_TIMEOUT   ?= 10

#
#  A handful of protocols ship a hand-written fuzzer_<proto>.c (committed to
#  git) instead of one generated from fuzzer.c - e.g. to enable the encode /
#  round-trip path, which needs protocol-specific test points. These still use
#  the rest of the FUZZER_PROTOCOL machinery (generated .mk, corpus, prereqs,
#  test rules); only their .c is not generated, and must not be cleaned.
#
FUZZER_PROTOCOL_CUSTOM_SRC = radius

FUZZER_PROTOCOLS_GENERATED = $(filter-out ${FUZZER_PROTOCOL_CUSTOM_SRC},${FUZZER_PROTOCOLS})

#
#  Generate the protocol fuzzer .c from fuzzer.c. Skipped for custom-src
#  protocols, whose .c is hand-written and committed.
#
define FUZZ_PROTOCOL_SRC
src/fuzzer/fuzzer_${1}.c: src/fuzzer/fuzzer.c | src/freeradius-devel/fuzzer
	$${Q}sed 's/XX_PROTOCOL_XX/${1}/g' < $$^ > $$@
endef

#
#  Generate the protocol fuzzer .mk from fuzzer.mk and wire it in. Done for
#  every protocol (including custom-src ones) so they all keep the corpus /
#  prereq / test machinery.
#
define FUZZ_PROTOCOL
src/fuzzer/fuzzer_${1}.mk: src/fuzzer/fuzzer.mk
	$${Q}sed 's/$$$$(PROTOCOL)/${1}/g' < $$^ > $$@

SUBMAKEFILES += fuzzer_${1}.mk
endef

.PHONY: clean.fuzzer
clean.fuzzer:
	@rm -f $(foreach X,${FUZZER_PROTOCOLS},src/fuzzer/fuzzer_${X}.mk)
	@rm -f $(foreach X,${FUZZER_PROTOCOLS_GENERATED},src/fuzzer/fuzzer_${X}.c)

clean: clean.fuzzer

#
#  Standalone fuzzers' build mks
#
SUBMAKEFILES += fuzzer_json.mk fuzzer_value.mk fuzzer_xlat.mk fuzzer_cf.mk fuzzer_base16_32_64.mk fuzzer_tmpl.mk fuzzer_der.mk

$(foreach X,${FUZZER_PROTOCOLS},$(eval $(call FUZZ_PROTOCOL,${X})))
$(foreach X,${FUZZER_PROTOCOLS_GENERATED},$(eval $(call FUZZ_PROTOCOL_SRC,${X})))

$(eval $(call FUZZ_PROTOCOL,util))
$(eval $(call FUZZ_PROTOCOL_SRC,util))

#
#  test.fuzzer.X / .merge rules for the standalone targets. Mirrors
#  the per-protocol shape in fuzzer.mk; per-target extra args come
#  from $(FUZZER_<name>_ARGS) so util can request -D and the others
#  can stay silent. Corpus directories are created on demand; .tar
#  files don't exist for these yet so first runs cold-start.
#
define FUZZ_TEST
$$(FUZZER_ARTIFACTS)/${1}: ; @mkdir -p $$@

src/tests/fuzzer-corpus/${1}: ; @mkdir -p $$@

ifeq "$$(CI)" ""
test.fuzzer.${1}: $$(TEST_BIN_DIR)/fuzzer_${1} src/tests/fuzzer-corpus/${1} $$(FUZZER_ARTIFACTS)/${1}
	@echo TEST-FUZZER ${1} for $$(FUZZER_TIMEOUT)s
	$${Q}$$(TEST_BIN_NO_TIMEOUT)/fuzzer_${1} \
		-artifact_prefix="$$(FUZZER_ARTIFACTS)/${1}/" \
		-max_len=512 $$(FUZZER_ARGUMENTS) \
		-max_total_time=$$(FUZZER_TIMEOUT) \
		$$(FUZZER_${1}_ARGS) \
		src/tests/fuzzer-corpus/${1}
else
test.fuzzer.${1}: $$(TEST_BIN_DIR)/fuzzer_${1} src/tests/fuzzer-corpus/${1} $$(FUZZER_ARTIFACTS)/${1}
	@echo TEST-FUZZER ${1} for $$(FUZZER_TIMEOUT)s
	@mkdir -p $$(BUILD_DIR)/fuzzer
	$${Q}if ! $$(TEST_BIN_NO_TIMEOUT)/fuzzer_${1} \
		-artifact_prefix="$$(FUZZER_ARTIFACTS)/${1}/" \
		-max_len=512 $$(FUZZER_ARGUMENTS) \
		-max_total_time=$$(FUZZER_TIMEOUT) \
		$$(FUZZER_${1}_ARGS) \
		src/tests/fuzzer-corpus/${1} > $$(BUILD_DIR)/fuzzer/${1}.log 2>&1; then \
		tail -20 $$(BUILD_DIR)/fuzzer/${1}.log; \
		echo FAILED; \
		exit 1; \
	fi
endif

test.fuzzer.${1}.merge: $$(TEST_BIN_DIR)/fuzzer_${1} | src/tests/fuzzer-corpus/${1}
	@echo MERGE-FUZZER-CORPUS ${1}
	$${Q}[ -e "src/tests/fuzzer-corpus/${1}_new" ] || mkdir "src/tests/fuzzer-corpus/${1}_new"
	$${Q}$$(TEST_BIN_NO_TIMEOUT)/fuzzer_${1} \
		-max_len=512 $$(FUZZER_ARGUMENTS) \
		-merge=1 \
		"src/tests/fuzzer-corpus/${1}_new" "src/tests/fuzzer-corpus/${1}"
	$${Q}[ ! -e "src/tests/fuzzer-corpus/${1}.tar" ] || rm "src/tests/fuzzer-corpus/${1}.tar"
	$${Q}rm -rf "src/tests/fuzzer-corpus/${1}"
	$${Q}mv "src/tests/fuzzer-corpus/${1}_new" "src/tests/fuzzer-corpus/${1}"
	$${Q}tar -C "src/tests/fuzzer-corpus" -c -f "src/tests/fuzzer-corpus/${1}.tar" "${1}"
	$${Q}rm -rf "src/tests/fuzzer-corpus/${1}_new"
endef

$(foreach X,${FUZZER_NON_PROTOCOL_TARGETS},$(eval $(call FUZZ_TEST,${X})))

.PHONY: fuzzer.help
fuzzer.help:
	@git-lfs env > /dev/null 2>&1 || echo "Please install 'git-lfs' in order to use the fuzzer corpus files."
	@echo To run the fuzzer, please use one of:
	@echo
	@for _p in $(PROTOCOLS); do echo "    make fuzzer.$$_p"; done
	@echo

test.fuzzer: $(addprefix test.fuzzer., $(filter-out $(FUZZER_NO_TEST),$(FUZZER_PROTOCOLS) $(FUZZER_NON_PROTOCOL_TARGETS)))

test.fuzzer.crash: $(addsuffix .crash,$(addprefix test.fuzzer.,$(FUZZER_PROTOCOLS)))

test.fuzzer.merge: $(addsuffix .merge,$(addprefix test.fuzzer.,$(FUZZER_PROTOCOLS) $(FUZZER_NON_PROTOCOL_TARGETS)))

else
.PHONY: fuzzer.help $(foreach X,${FUZZER_PROTOCOLS},fuzzer.${X})
fuzzer.help $(foreach X,${FUZZER_PROTOCOLS},fuzzer.${X}) test.fuzzer:
	@echo "The server MUST be built with '--enable-fuzzer'"
endif

.PHONY: src/freeradius-devel/fuzzer
src/freeradius-devel/fuzzer:
	${Q}[ -e $@ ] || (cd ${top_srcdir}/src/include && ln -s ../fuzzer)
