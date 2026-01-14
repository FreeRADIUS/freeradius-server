#
#  $(eval $(call DICT_STATS,radius,auth_serv,mib-2.radiusAuthServ,1.3.6.1.2.1.67.1.1.1.1))
#
#  We don't want the outputs to be updated if the build fails.  So we use an intermediate filename.
#  And we use ".cache", because that's ignored by the top level ".gitignore"
#
define DICT_STATS
#
#  Define the structures and declare the extern variables
#
src/protocols/${1}/stats/${2}_stats.h: share/dictionary/${1}/dictionary.stats $(BUILD_DIR)/bin/local/radict$(E)
	@echo STATS ${1} ${2} - structs
	${Q}./scripts/bin/radict -F stats.h -M ${4} -p ${1} ${3} > $$@.cache && mv $$@.cache $$@

#
#  define the "attr_foo" definitions for the dictionary autoload to populate
#
src/protocols/${1}/stats/${2}_da_def.c: share/dictionary/${1}/dictionary.stats $(BUILD_DIR)/bin/local/radict$(E)
	@echo STATS ${1} ${2} - define variables
	${Q}./scripts/bin/radict -F da_def -M ${4} -p ${1} ${3} > $$@.cache && mv $$@.cache $$@

#
#  define the autoload structures which point to the "attr_foo" defintions
#
src/protocols/${1}/stats/${2}_da_autoload.c: share/dictionary/${1}/dictionary.stats $(BUILD_DIR)/bin/local/radict$(E)
	@echo STATS ${1} ${2} - autoload
	${Q}./scripts/bin/radict -F attr_autoload -M ${4} -p ${1} ${3} > $$@.cache && mv $$@.cache $$@

#
#  define the linking structure between the statistics structure and the DAs.
#
src/protocols/${1}/stats/${2}_stats.c: share/dictionary/${1}/dictionary.stats $(BUILD_DIR)/bin/local/radict$(E)
	@echo STATS ${1} ${2} - link
	${Q}./scripts/bin/radict -F stats_link -M ${4} -p ${1} ${3} > $$@.cache && mv $$@.cache $$@

#
#  The output OBJ has to be rebuilt if any of the input files have changed.
#
$(BUILD_DIR)/objs/src/protocols/${1}/stats/base.${OBJ_EXT}: src/protocols/${1}/stats/${2}_stats.h src/protocols/${1}/stats/${2}_da_def.c src/protocols/${1}/stats/${2}_da_autoload.c src/protocols/${1}/stats/${2}_stats.c

endef

#
#  All protocols go into subdirectories of the "protocols" directory.
#
SUBMAKEFILES := $(wildcard ${top_srcdir}/src/protocols/*/all.mk)
