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
make test.multi-server.accept.short_ci MODE=profiling PROFILING_TOOL=gperftools
```

A profiling run captures with one profiler, named by `PROFILING_TOOL`
(default `valgrind`). `PROFILING_TOOLS` lists the profilers whose capture
scripts are mounted into the container, so a run can select any of them
without an image change.

Profiling results land under
`prof-results/<branch>/<commit>/<run-index>/<suite>/<test>/<tool>/`, one
directory per profiler.  Set `PROFILING_RESULT_MODE=dev` to use a flat
`prof-results/<suite>/<test>/<tool>/` layout that overwrites each run.

Each profiler writes the same set of files into its own result directory:

| file             | contents                                              |
|------------------|-------------------------------------------------------|
| `capture.log`    | the capture script's own log                          |
| `freeradius.log` | server stdout and stderr                              |
| `profile.out`    | raw profile (callgrind writes `profile.out.<pid>`)    |
| `report.txt`     | text report (`callgrind_annotate` or `pprof -text`)   |
| `exit-status`    | 0 when the capture completed                          |

callgrind also writes `valgrind.log`, valgrind's own engine log, which has
no gperftools counterpart.

Both captures switch sampling on and off from the `server.start` and
`server.stop` triggers, callgrind through `%callgrind.start`/`stop` and
gperftools through `%gperftools.start`/`stop`, so startup and shutdown stay
out of the profile.  The gperftools capture needs `pprof` in the profiling
image to convert the raw profile, and fails at startup without it.  The
header of each `scripts/profiling/start_<tool>_profiling.sh` documents that
capture.

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

Compose envs reference `${FREERADIUS_IMAGE}` and read `${PROFILING:-no}`.
The per-test recipe in `all.mk` sets both based on the `MODE` makefile
variable, exporting the SHA-tagged image name directly:

- `MODE=service` (default) selects `freeradius4-service/<image>:<sha>` and
  leaves `RADIUSD_COMMAND` unset, so the template default (`freeradius -f -l
  stdout`) runs the server directly.
- `MODE=profiling` selects `freeradius4-profiling/<image>:<sha>` and sets
  `RADIUSD_COMMAND` to `bash /usr/local/bin/start_valgrind_profiling.sh`,
  which captures the run with callgrind.

Every test template exports the `TEST_LOADGEN_*` variables from the params
file and then runs `exec ${RADIUSD_COMMAND:-freeradius -f -l stdout}`.
`configs/compose/freeradius-common.yml.j2`, which every suite's compose file
extends, carries `RADIUSD_COMMAND` and defaults `TEST_LOADGEN_MAX_REQUESTS`
to 0, so the test ends when the `max_pps` step finishes unless a suite sets
an exact count. The makefile copies
`scripts/profiling/start_<tool>_profiling.sh` into `<test output
dir>/scripts/` in every mode, and the common compose file bind mounts it into
`/usr/local/bin`.

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
