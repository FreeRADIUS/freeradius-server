# Multi-Server Tests

Integration tests that spin up FreeRADIUS plus its peers (proxies,
backing stores, kafka, etc.) in Docker containers and exercise them via
the radenv test framework.

## Prerequisites

A standard `freeradius4-service/<image>:<sha>` Docker image must be
available locally for the service-mode pass:

```bash
make docker.service.ubuntu24
```

For profiling-mode runs, the standard `freeradius4-profiling/<image>:<sha>`
image is what gets used directly:

```bash
make freeradius-prof.image
```

## Running Tests

### All tests, service mode

```bash
make test.multi-server
```

### CI subset, service mode

```bash
make test.multi-server.ci
```

### Profiling pass (same suites, under a profiler)

```bash
make test.multi-server.profiling       # all suites
make test.multi-server.profiling.ci    # CI subset
```

The profiling pass writes results under
`prof-results/<branch>/<commit>/<run-index>/<suite>/<test>/`. Set
`PROFILING_RESULT_MODE=dev` to use a flat `prof-results/<suite>/<test>/`
layout that each run overwrites.

Profiling runs use every known profiler by default, valgrind then
gperftools, each writing into the same result directory. Set `TOOL` to one
name to run a single profiler:

```bash
make test.multi-server.profiling.ci                                # both profilers
make test.multi-server.accept.short_ci MODE=profiling TOOL=gperftools
make test.multi-server.profiling.ci TOOL=valgrind
```

Every run writes into a `logs/<run>/` and a `listener/<run>/` subdirectory
under the test output dir. `<run>` is the profiler name, or `service` in
service mode.

The profilers write these files into the result directory:

| valgrind (callgrind)      | gperftools                             | contents                         |
|---------------------------|----------------------------------------|----------------------------------|
| `valgrind_profiling.log`  | `gperftools_profiling.log`             | the capture script's own log     |
| `freeradius_valgrind.log` | `freeradius_gperftools.log`            | server stdout/stderr             |
| `callgrind.out.<pid>`     | `freeradius_gperftools.prof.<pid>.<n>` | raw profile                      |
|                           | `pprof.out.<pid>.pb.gz`                | merged profile, symbols resolved |
| `callgrind_report.txt`    | `pprof_report.txt`                     | text report                      |
| `valgrind-exit-status`    | `gperftools-exit-status`               | 0 when the capture completed     |

The gperftools capture runs the server single-threaded (`-s`). The capture
samples CPU time between the ready line of the server and the completion
line of proto_load, so the profile holds the load phase only. The capture
needs `pprof` in the profiling image. Without `pprof`, the capture keeps the
raw dumps and writes a non-zero exit status. The header of
`scripts/profiling/start_gperftools_profiling.sh` documents the capture.

### A specific test

```bash
make test.multi-server.proxy-accept.short_ci          # service mode (default)
make test.multi-server.accept.short_ci MODE=profiling # one test, profiling
```

### Parallel execution

```bash
make -j$(nproc) test.multi-server
```

### Extra flags

Pass debug/verbosity flags to the test framework:

```bash
make test.multi-server TEST_MULTI_SERVER_FLAGS="-xx -vvv"
```

## How It Works

Each test suite is a directory under `tests/` containing:

- `template.yml.j2` - Jinja2 template for test steps (state machine)
- `environment.yml.j2` - Symlink to a Docker Compose template in `environments/`
- `*.test.yml` - Parameter files (one per test variant)

A parameter file is flat YAML defining topology, load profile, and test
timeouts.  All `.j2` files in the suite directory are rendered using
these parameters.  The rendered compose file's `${DATA_PATH}` volume
mounts are scanned and the corresponding config files are copied or
rendered into the build directory.

Build outputs go to `build/tests/multi-server/<suite>/<test>/`.

### Service vs profiling mode

The compose files reference `${FREERADIUS_IMAGE}` and read `${PROFILING:-no}`.
`scripts/run_test.sh` sets both variables from the `MODE` makefile variable,
and exports the SHA-tagged image name directly:

- `MODE=service` (default) selects `freeradius4-service/<image>:<sha>`,
  and `start_freeradius.sh` starts the server directly with `exec`.
- `MODE=profiling` selects `freeradius4-profiling/<image>:<sha>`, and sets
  `PROFILING=yes` and `PROFILING_TOOL=<tool>`. `start_freeradius.sh` then
  starts `start_<tool>_profiling.sh` with `exec`, so the profiler captures
  the run.

The test templates of the profiling suites only export the `TEST_LOADGEN_*`
variables from the params file and `exec start_freeradius.sh`.
`start_freeradius.sh` holds the request count arithmetic and the mode
dispatch. The makefile copies `scripts/start_freeradius.sh` and every
`scripts/profiling/start_<tool>_profiling.sh` into `<test output
dir>/scripts/` in every mode. The compose files bind mount the scripts into
`/usr/local/bin`. A tool without a script fails the build early.

The per-test recipe itself is `scripts/run_test.sh`. `all.mk` resolves the
make-side settings into the environment of `scripts/run_test.sh` (see the
script header), so a developer can repeat one test by hand without make.

The profiling image is the standard `freeradius4-profiling/<image>:<sha>`
output, built by `scripts/docker/m4/profiling.deb.m4` /
`profiling.rpm.m4`. The configure + make + install pass with
callgrind-friendly CFLAGS is in
`scripts/docker/m4/common.freeradius-profile-build.m4` and is included
into both deb and rpm flavours.

## Adding a New Test

1. Create a parameter file in an existing suite directory, e.g.
   `tests/proxy-accept/heavy.test.yml`.  Name it `*.ci.test.yml` if
   it should run in CI.

2. Or create a new suite directory with `template.yml.j2`,
   `environment.yml.j2` (symlink), and parameter files.

The build framework discovers suites automatically by finding
directories containing `template.yml.j2`, and discovers tests by
finding `*.test.yml` files within them.

## File Naming Conventions

- `*.test.yml` - Test parameter file (discovered by `make test.multi-server`)
- `*.ci.test.yml` - CI test parameter file (also discovered by `make test.multi-server.ci`)
- `*.yml.j2` - Jinja2 template (rendered, not treated as a test)

## Suites

| Suite | What it exercises |
| --- | --- |
| `accept` | Plain RADIUS accept (no external services) |
| `pap-auth` | PAP authentication against the `files` module |
| `ldap` | Authentication backed by an LDAP server |
| `mysql` | Authentication backed by a MySQL database |
| `proxy-accept` | Five home servers, proxied auth |
| `proxy-multihop-accept` | Two-hop proxy chain |
| `kafka-produce` | `rlm_kafka` producer against an Apache Kafka broker |
| `kafka-produce-reconnect` | Producer reconnection behaviour |
