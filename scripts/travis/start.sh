##TODO rip this apart into "configure , make , make deb, make scan and make install" functions
export PANIC_ACTION="gdb -batch -x raddb/panic.gdb %e %p 1>&0 2>&0"

#Configure
if [ "${DO_BUILD}" = 'yes' ]; then 
    CFLAGS="${BUILD_CFLAGS}" ./configure -C\
    --enable-werror \
    --prefix=$HOME/freeradius\
    --with-shared-libs=$LIBS_SHARED \
    --with-threads=$LIBS_OPTIONAL \
    --with-udpfromto=$LIBS_OPTIONAL \
    --with-openssl=$LIBS_OPTIONAL \
    --with-pcre=$LIBS_OPTIONAL \
    --enable-reproducible-builds=${REPRODUCIBLE}
fi

if [ "${DO_BUILD}" = 'no' ]; then 
    ./configure -C --without-modules
fi

# Make
if [ "${DO_BUILD}" = 'yes' ]; then 
    make -j8
fi

# Make scan
if [ "${DO_BUILD}" = 'yes' -a ${CC} = 'clang' ]; then 
    make -j8 scan && [ "$(find build/plist/ -name *.html)" = '' ]
fi

if [ "${DO_BUILD}" = 'yes' ]; then 
    make travis-test
fi

if [ "${DO_BUILD}" = 'no' ]; then 
    cd doc/source; doxygen 3>&1 1>&2 2>&3 | grep -iv '^warning:' | tee doxygen_stderr.log && [ ! -n "$(cat doxygen_stderr.log)" ]
fi
