#
#  The coverage tests require lcov.
#
#  OSX: brew install lcov
#
#  Debian: apt-get install lcov
#
#  @todo - check for lcov before running these tests.
#

#
#  Modify CFLAGS and LDFLAGS
#
CFLAGS += -fprofile-arcs -ftest-coverage
LDFLAGS += -fprofile-instr-generate

#
#  Before doing `make coverage`, you should do a
#  `make clean`.
#
coverage: coverage.test ${BUILD_DIR}/coverage/index.html

.PHONY: coverage.test
coverage.test:
	@$(MAKE) test

#
#  lcov doesn't understand llvm-gcov's extra arguments.  So we need a wrapper script
#
ifneq "$(findstring clang,$(shell $(CC) --version 2>/dev/null))" ""
GCOV_TOOL = --gcov-tool=./scripts/build/llvm-gcov
endif

.PHONY: ${BUILD_DIR}/radiusd.info
${BUILD_DIR}/radiusd.info:
	@lcov --directory . --base-directory . $(GCOV_TOOL) --capture -o $@ > ${BUILD_DIR}/lcov.log

${BUILD_DIR}/coverage/index.html: ${BUILD_DIR}/radiusd.info
	@genhtml $< -o $(dir $@) > ${BUILD_DIR}/genhtml.log
	@echo Please see $@
