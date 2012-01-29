SOURCES := acct.c auth.c client.c conffile.c crypt.c exec.c files.c \
		  listen.c log.c mainconfig.c modules.c modcall.c \
		  radiusd.c stats.c soh.c connection.c dhcpd.c \
		  session.c threads.c util.c valuepair.c version.c  \
		  xlat.c process.c realms.c evaluate.c vmps.c detail.c
ifneq ($(OPENSSL_LIBS),)
SOURCES	+= cb.c tls.c tls_listen.c
endif

SRC_CFLAGS	:= -DHOSTINFO=\"${HOSTINFO}\"
SRC_CFLAGS	+= -DRADIUSD_VERSION=\"${RADIUSD_VERSION}\"
SRC_CFLAGS	+= $(OPENSSL_INCLUDE)
TGT_INSTALLDIR  := ${sbindir}
TGT_LDLIBS	:= $(OPENSSL_LIBS)
TGT_LDFLAGS     := $(LIBS) $(LCRYPT)

TGT_PREREQS	:= libfreeradius-radius.a $(filter rlm_%,${ALL_TGTS})

ifneq "${LIBTOOL}" ""
SRC_FLAGS	+= -DWITH_DLOPEN
else
${DIR}/modules.c:	${BUILD_DIR}/make/include/lt_dlmodules.c

# Find the modules
ALL_MODULES	:= $(patsubst %.a,%,$(filter rlm_%,${ALL_TGTS}))
ALL_MODULES	:= $(patsubst %.la,%,$(filter rlm_%,${ALL_MODULES}))

# Filter out ones with additional library dependencies.
# For the future, go through ALL modules and add their library dependencies
# to the TGT_LDLIBS.
ALL_MODULES	:= $(filter-out rlm_perl rlm_ldap rlm_pam rlm_krb5 rlm_python,${ALL_MODULES})

# EAP and SQL require different variable declarations.
EAP_MODULES	:= $(filter rlm_eap_%,${ALL_MODULES})
SQL_MODULES	:= $(filter rlm_sql_%,${ALL_MODULES})

BASE_MODULES	:= $(filter-out ${EAP_MODULES} ${SQL_MODULES},${ALL_MODULES})

#
#  Create the intermediate file which links to the modules.
#  And have it depend on this Makefile, which creates it.
#
${BUILD_DIR}/make/include/lt_dlmodules.c: $(addprefix ${BUILD_DIR}/lib/,$(filter rlm_%,${ALL_TGTS})) $(lastword ${MAKEFILE_LIST})
	@rm -f $@
	@for x in ${BASE_MODULES}; do \
		echo "extern module_t $$x;" >> $@; \
	done
	@for x in ${EAP_MODULES}; do \
		echo "extern EAP_TYPE $$x;" >> $@; \
	done
	@for x in ${SQL_MODULES}; do \
		echo "extern rlm_sql_module_t $$x;" >> $@; \
	done
	@echo "static const lt_dlmodule_t lt_dlmodules[] = {" >> $@
	@for x in ${ALL_MODULES}; do \
		echo "{ \"$$x\", &$$x }," >> $@; \
	done
	@echo "{ NULL, NULL }" >> $@
	@echo "};" >> $@
endif

# Libraries can't depend on libraries (oops), so make the binary
# depend on the EAP code...
ifneq "$(filter rlm_eap_%,${ALL_TGTS})" ""
TGT_PREREQS	+= libfreeradius-eap.a
endif

TARGET		:= radiusd
