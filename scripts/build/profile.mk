#
#  Modify CFLAGS and LDFLAGS
#
CFLAGS += -g -fprofile-instr-generate -fcoverage-mapping
LDFLAGS += -fprofile-instr-generate -fprofile-arcs

#
#  This is where the output profile file goes
#
export LLVM_PROFILE_FILE=${BUILD_DIR}/llvm.prof

#
#  Before doing `make profile`, you should do a
#  `make clean`.
#
profile: all
	${Q}$(MAKE) test

.PHONY: profile.help
profile.help:
	@echo ""
	@echo "Make targets:"
	@echo "    profile                  - build with profiling (should do 'make clean' first)"
	@echo "    profile.show	            - show stupid profile data"
	@echo ""

.PHONY: profile.show
profile.show:
	@llvm-profdata show -all-functions ${BUILD_DIR}/llvm.prof
