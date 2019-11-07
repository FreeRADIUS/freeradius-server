## Start servers
set -ex

function startservices() {
    mkdir -p /var/run/mysqld
    chown -R mysql.mysql /var/run/mysqld /var/lib/mysql
    mysqld_safe &
    MYSQLD_PID=$!
    if ! [ -e "/var/lib/postgresql/10/main/data/postgresql.conf" ] ; then
        su - postgres -c "/usr/lib/postgresql/10/bin/pg_ctl -D /var/lib/postgresql/10/main/data init"
    fi
    su - postgres -c "/usr/lib/postgresql/10/bin/pg_ctl -D /var/lib/postgresql/10/main/data start"
    slapd
    sleep 1
    echo
    touch /tmp/initialized
}

function checkout() {
    mkdir -p /usr/local/src/repositories
    pushd /usr/local/src/repositories
    git clone --branch=master --depth=50 https://github.com/FreeRADIUS/freeradius-server
    pushd /usr/local/src/repositories/freeradius-server
    ruby -ryaml -e 'YAML.load_file(".travis.yml")["env"]["global"].each { |e| puts "export #{e}" if e.class == String }' | bash
    popd
    popd
}

function run-tests() {
        ### set global environment variables
        export ASAN_OPTIONS="symbolize=1 detect_leaks=1 detect_stack_use_after_return=1"
        export LSAN_OPTIONS="fast_unwind_on_malloc=0:malloc_context_size=50"
        export KQUEUE_DEBUG="yes"
        export M_PERTURB=0x42
        export PANIC_ACTION="gdb -batch -x raddb/panic.gdb %e %p 1>&0 2>&0"
        export SQL_MYSQL_TEST_SERVER="127.0.0.1"
        export SQL_POSTGRESQL_TEST_SERVER="127.0.0.1"
        export LDAP_TEST_SERVER="127.0.0.1"
        export LDAP_TEST_SERVER_PORT="3890"
        export REDIS_IPPOOL_TEST_SERVER="127.0.0.1"
        export ANALYZE_C_DUMP="1"
        export FR_GLOBAL_POOL=4M
        ## before_install
        if [ "${CC}" == 'gcc' ]; then sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 60 && sudo update-alternatives --config gcc; fi
        if [ "${CC}" == 'clang' ]; then sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-8 60 && sudo update-alternatives --config clang; fi
        if [ "${CC}" == 'clang' ]; then sudo update-alternatives --install /usr/bin/llvm-symbolizer llvm-symbolizer /usr/bin/llvm-symbolizer-8 60 && sudo update-alternatives --config llvm-symbolizer; fi
        $CC --version
        make --version
        ## before_script
        ./scripts/travis/build.sh
        ## script
        pwd
        if [ "${DO_BUILD}" = 'yes' -a "${COVERITY_SCAN_BRANCH}" != 1 ]; then make travis-test; fi
        if [ "${DO_BUILD}" = 'no' ]; then cd doc/doxygen; doxygen 3>&1 1>&2 2>&3 | grep -iv '^warning:' | tee doxygen_stderr.log && [ ! -n "$(cat doxygen_stderr.log)" ]; fi
}

if ! test -e /tmp/initialized ; then
    startservices
fi

run-tests

