# Copyright 2008, 2009, 2010 Dan Moulding, Alan T. DeKok
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

#
#  You can watch what it's doing by:
#
#	$ VERBOSE=1 make ... args ...
#
ifeq "${VERBOSE}" ""
    Q=@
else
    Q=
endif

# Add these rules only when LIBTOOL is being used.
ifneq "${LIBTOOL}" ""

# JLIBTOOL - check if we're using the local (fast) jlibtool, rather
#   than the GNU (slow) libtool shell script.  If so, add rules
#   to build it.

ifeq "${LIBTOOL}" "JLIBTOOL"
    JLIBTOOL := ${BUILD_DIR}/make/jlibtool
    JLIBTOOL_DEFS := -DPROGRAM_VERSION=$(RADIUSD_VERSION_MAJOR).$(RADIUSD_VERSION_MINOR)

    # Pass compiler and ranlib paths through to jlibtool if they're
    # defined in the environment.  This lets us define a separate
    # compiler to build the toolchain and
    ifdef BUILD_CC
        JLIBTOOL_DEFS += -DBUILD_CC=\"${BUILD_CC}\" -DHOST_LINK_C=\"${BUILD_CC}\"
    endif

    ifdef BUILD_RANLIB
        JLIBTOOL_DEFS += -DBUILD_RANLIB=\"${BUILD_RANLIB}\"
    endif

    ifndef TARGET_CC
        ifdef CC
            TARGET_CC := '${CC}'
        endif
    endif

    ifdef TARGET_CC
        JLIBTOOL_DEFS += -DTARGET_CC=\"${TARGET_CC}\" -DTARGET_LINK_C=\"${TARGET_CC}\"
    endif

    ifdef TARGET_RANLIB
        JLIBTOOL_DEFS += -DTARGET_RANLIB=\"${TARGET_RANLIB}\"
    endif

    # clang on OSX sometimes doesn't know where things are. <sigh>
    ifeq "$(findstring darwin,$(TARGET_SYSTEM))" "darwin"
	JLIBTOOL_DEFS += -L/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
    endif

    # Add a rule to build jlibtool BEFORE any other targets.  This
    # means that we can use it to build the later targets.
    all install: ${JLIBTOOL}

    # Note that we need to use a compilation rule that does NOT
    # include referencing ${LIBTOOL}, as we don't have a jlibtool
    # binary!
    ${JLIBTOOL}: ${top_makedir}/jlibtool.c
	$(Q)mkdir -p $(dir $@)
	$(Q)echo CC jlibtool.c
	$(Q)${BUILD_CC} $< -g3 -o $@ ${JLIBTOOL_DEFS}

    jlibtool: ${JLIBTOOL}

    clean: clean.jlibtool

    .PHONY: clean.jlibtool
    clean.jlibtool:
	$(Q)rm -f ${JLIBTOOL}

    # Tell GNU Make to use this value, rather than anything specified
    # on the command line.
    override LIBTOOL := ${JLIBTOOL}
endif    # else we're not using jlibtool

# When using libtool, it produces a '.libs' directory.  Ensure that it
# is removed on "make clean", too.
#
clean: clean.libs

.PHONY: clean.libs
clean.libs:
	$(Q)rm -rf ${BUILD_DIR}/.libs/

# Re-define compilers and linkers
#

#
#  VERBOSE=1 means "debug the commands that we're running".
#  VERBOSE=2 means "also debug the jlibtool internals".
#
#  For normal VERBOSE=1, we do NOT want to see thousands of lines of
#  the same content of jlibtool environment variables.
#
ifeq "$(VERBOSE)" "2"
LIBTOOL_VERBOSE=--debug
else
LIBTOOL_VERBOSE=--silent
endif

OBJ_EXT = lo

COMPILE.c = ${LIBTOOL} ${LIBTOOL_VERBOSE} --target=${TARGET_SYSTEM} --mode=compile ${TARGET_CC}
HOST_COMPILE.c = ${LIBTOOL} ${LIBTOOL_VERBOSE} --mode=compile ${BUILD_CC}

LINK.c = ${LIBTOOL} ${LIBTOOL_VERBOSE} --target=${TARGET_SYSTEM} --mode=link ${TARGET_CC}
HOST_LINK.c = ${LIBTOOL} ${LIBTOOL_VERBOSE} --mode=link ${BUILD_CC}

COMPILE.cxx = ${LIBTOOL} ${LIBTOOL_VERBOSE} --target=${TARGET_SYSTEM} --mode=compile ${CXX}
LINK.cxx = ${LIBTOOL} ${LIBTOOL_VERBOSE} --target=${TARGET_SYSTEM} --mode=link ${CXX}

PROGRAM_INSTALL = ${LIBTOOL} ${LIBTOOL_VERBOSE} --target=${TARGET_SYSTEM} --mode=install ${INSTALL}


# LIBTOOL_ENDINGS - Given a library ending in ".a" or ".so", replace that
#   extension with ".la".
#
define LIBTOOL_ENDINGS
$(patsubst %.a,%.la,$(patsubst %.$(TARGET_LIB_EXT),%.la,${1}))
endef

# ADD_TARGET_RULE.la - Build a ".la" target.
#
#   USE WITH EVAL
#
define ADD_TARGET_RULE.la
    # So "make ${1}" works
    .PHONY: ${1}
    ${1}: $${${1}_BUILD}/${1}

    # Create libtool library ${1}
    $${${1}_BUILD}/${1}: $${${1}_OBJS} $${${1}_PRLIBS}
	    $(Q)$(strip mkdir -p $(dir $${${1}_BUILD}/${1}))
	    @$(ECHO) LINK $${${1}_BUILD}/${1}
	    $(Q)$${${1}_LINKER} -o $${${1}_BUILD}/${1} $${RPATH_FLAGS} $${LDFLAGS} \
                $${${1}_LDFLAGS} $${${1}_OBJS} $${LDLIBS} $${${1}_LDLIBS} \
                $${${1}_PRLIBS}
	    ${Q}$(DSYMUTIL) $${${1}_BUILD}/.libs/$$(patsubst %.la,%.dylib,${1})
	    ${Q}$(DSYMUTIL) $${${1}_BUILD}/local/.libs/$$(patsubst %.la,%.dylib,${1})
	    $(Q)$${${1}_POSTMAKE}

    ifneq "${ANALYZE.c}" ""
        scan.${1}: $${${1}_PLISTS}
    endif

    .PHONY: $(DIR)
    $(DIR)/: ${1}
endef

# ADD_TARGET_RULE.so - Build a ".so" target.
#
#   USE WITH EVAL
#
define ADD_TARGET_RULE.so
    # So "make ${1}" works
    .PHONY: ${1}
    ${1}: $${${1}_BUILD}/${1}

    # Create libtool library ${1}
    $${${1}_BUILD}/${1}: $${${1}_OBJS} $${${1}_PRLIBS}
	    $(Q)$(strip mkdir -p $(dir $${${1}_BUILD}/${1}))
	    @$(ECHO) LINK $${${1}_BUILD}/${1}
	    $(Q)$${${1}_LINKER} -o $${${1}_BUILD}/${1} -rpath ${libdir} $${LDFLAGS} \
                $${${1}_LDFLAGS} $${${1}_OBJS} $${LDLIBS} $${${1}_LDLIBS} \
                $${${1}_PRLIBS}
	    $(Q)$${${1}_POSTMAKE}

    ifneq "${ANALYZE.c}" ""
        scan.${1}: $${${1}_PLISTS}
    endif

    .PHONY: $(DIR)
    $(DIR)/: ${1}
endef

# ADD_TARGET_RULE.dll - Build a ".dll" target.
#
#   USE WITH EVAL
#
define ADD_TARGET_RULE.dll
$(ADD_TARGET_RULE.so)
endef

# ADD_TARGET_RULE.dylib - Build a ".dylib" target.
#
#   USE WITH EVAL
#
define ADD_TARGET_RULE.dylib
$(ADD_TARGET_RULE.so)
endef

# ADD_TARGET_RULE.wasm - Build a ".wasm" target.
#
#   USE WITH EVAL
#
define ADD_TARGET_RULE.wasm
    # So "make ${1}" works
    .PHONY: ${1}
    ${1}: $${${1}_BUILD}/${1}

    # Create libtool library ${1}
    $${${1}_BUILD}/${1}: $${${1}_OBJS} $${${1}_PRLIBS}
	    $(Q)$(strip mkdir -p $(dir $${${1}_BUILD}/${1}))
	    @$(ECHO) LINK $${${1}_BUILD}/${1}
	    $(Q)$${${1}_LINKER} -o $${${1}_BUILD}/${1} $${LDFLAGS} \
                $${${1}_LDFLAGS} $${${1}_OBJS} $${LDLIBS} $${${1}_LDLIBS} \
                $${${1}_PRLIBS}
	    $(Q)$${${1}_POSTMAKE}

    ifneq "${ANALYZE.c}" ""
        scan.${1}: $${${1}_PLISTS}
    endif

    .PHONY: $(DIR)
    $(DIR)/: ${1}
endef

# ADD_LOCAL_RULE.exe - Parametric "function" that adds a rule to build
#   a local version of the target.
#
#   USE WITH EVAL
#
define ADD_LOCAL_RULE.exe
    ${1}: $${${1}_BUILD}/$${LOCAL}${1}

    # used to fix up RPATH for ${1} on install.
    $${${1}_BUILD}/$${${1}_LOCAL}: $${${1}_OBJS} $${${1}_PRBIN} $${${1}_LOCAL_PRLIBS}
	    $(Q)$(strip mkdir -p $${${1}_BUILD}/${LOCAL}/)
	    $(Q)$${${1}_LINKER} -o $${${1}_BUILD}/$${LOCAL}${1} $${LOCAL_FLAGS} $${LDFLAGS} \
                $${${1}_LDFLAGS} $${${1}_OBJS} $${${1}_LOCAL_PRLIBS} \
                $${LDLIBS} $${${1}_LDLIBS} ${OSX_LDFLAGS}
	    ${Q}$(DSYMUTIL) $${${1}_BUILD}/$${${1}_LOCAL}
	    $(Q)$${${1}_POSTMAKE}

    .PHONY: $(DIR)
    $(DIR)/: ${1}
endef

define ADD_LOCAL_RULE.js
${ADD_LOCAL_RULE.exe}
endef

# ADD_LOCAL_RULE.la - Parametric "function" that adds a rule to build
#   a local version of the target.
#
#   USE WITH EVAL
#
define ADD_LOCAL_RULE.la
    ${1}: $${${1}_BUILD}/$${LOCAL}${1}

    # used to fix up RPATH for ${1} on install.
    $${${1}_BUILD}/$${${1}_LOCAL}: $${${1}_OBJS} $${${1}_LOCAL_PRLIBS}
	    $(Q)$(strip mkdir -p $${${1}_BUILD}/${LOCAL}/)
	    $(Q)$${${1}_LINKER} -o $${${1}_BUILD}/$${LOCAL}${1} $${LOCAL_FLAGS} $${LDFLAGS} \
                $${${1}_LDFLAGS} $${${1}_OBJS} $${LDLIBS} $${${1}_LDLIBS} \
                $${${1}_LOCAL_PRLIBS}
	    $(Q)$${${1}_POSTMAKE}

endef

# By default, if libdir is defined, we build shared libraries.
# However, we can disable shared libraries if explicitly told to.
ifneq "${libdir}" ""
    ifneq "${USE_SHARED_LIBS}" "no"
        USE_SHARED_LIBS := yes
    endif
endif

# Default to building static libraries, too.
ifneq "${USE_STATIC_LIBS}" "no"
    USE_STATIC_LIBS := yes
endif

# Check if we build shared libraries.
ifeq "${USE_SHARED_LIBS}" "yes"
    LOCAL := local/

    # RPATH  : flags use to build executables that are installed,
    #          with no dependency on the source.
    # RELINL : flags use to build executables that can be run
    #          from the build directory / source tree.
    RPATH_FLAGS := -rpath ${libdir}
    LOCAL_FLAGS := -rpath $(subst //,/,$(abspath ${BUILD_DIR})/lib/${LOCAL}/.libs)

    LOCAL_FLAGS_MIN := -rpath ${libdir}

    ifneq "${USE_STATIC_LIBS}" "yes"
        RPATH_FLAGS += --shared
        LOCAL_FLAGS += --shared
    endif
else
    ifneq "${USE_STATIC_LIBS}" "yes"
        $(error Building without static libraries requires you to set 'INSTALL' or 'libdir')
    endif

    RPATH_FLAGS := -static
endif

# UPDATE_TARGET_ENDINGS - Function to turn target into a libtool target
#   e.g. "libfoo.a" -> libfoo.la"
#
#   If the target is an executable, then its extension doesn't change
#   when we use libtool, and we don't do any re-writing.
#
#   USE WITH EVAL
#
define ADD_LIBTOOL_SUFFIX
    ifneq "$$(call LIBTOOL_ENDINGS,$${TGT})" "$${TGT}"
        TGT_NOLIBTOOL := $${TGT}
        TGT := $$(call LIBTOOL_ENDINGS,$${TGT})
        $${TGT}_NOLIBTOOL := $${TGT_NOLIBTOOL}
    endif

    ifneq "$${LOCAL_FLAGS}" ""
        $${TGT}_LOCAL := ${LOCAL}$${TGT}
    endif

    # re-write all of the dependencies to have the libtool endings.
    TGT_PREREQS := $$(call LIBTOOL_ENDINGS,$${TGT_PREREQS})
endef

# ADD_LIBTOOL_TARGET - Function to ensure that the object files depend
#   on our jlibtool target.  This ensures that jlibtool is built before
#   it's used to build the object files.
#
#   USE WITH EVAL
#
define ADD_LIBTOOL_TARGET
    ifneq "${JLIBTOOL}" ""
        $${$${TGT}_OBJS}: $${JLIBTOOL}
    endif

    ifneq "$${$${TGT}_NOLIBTOOL}" ""
        $$(notdir $${$${TGT}_NOLIBTOOL}): $${TGT}
    endif

    # If we need to relink, add the relink targets now.
    ifneq "$${$${TGT}_LOCAL}" ""
        # add rules to relink the target

        $${TGT}_LOCAL_PRLIBS := $$(subst $${BUILD_DIR}/lib/,$${BUILD_DIR}/lib/${LOCAL},$${$${TGT}_PRLIBS})

        $$(eval $$(call ADD_LOCAL_RULE$${$${TGT}_SUFFIX},$${TGT}))

        $$(eval $$(call ADD_CLEAN_RULE,$${$${TGT}_LOCAL}_libtool))

	ifneq "$${$${TGT}_NOLIBTOOL}" ""
            $$(eval $$(call ADD_CLEAN_RULE,$${$${TGT}_NOLIBTOOL}_libtool))
	endif
    endif

endef


endif

#
#  $(call DEFINE_LOG_ID_SECTION,NAME,ID,foo.c bar.c baz.c)
#
define DEFINE_LOG_ID_SECTION
$(eval $(addprefix ${BUILD_DIR}/objs/,$(addsuffix .${OBJ_EXT},$(basename $(call CANONICAL_PATH,$(call QUALIFY_PATH,${DIR},$(strip ${3})))))): LOG_SECTION_ID=$(strip ${2}))
endef
