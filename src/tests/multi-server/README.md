# Multi-Server Tests

Integration tests that spin up multiple FreeRADIUS instances in Docker
containers and verify they can proxy traffic between each other.

## Prerequisites

A `freeradius-build:latest` Docker image must be available locally:

```bash
make docker.ubuntu24.build
docker tag freeradius4/ubuntu24:latest freeradius-build:latest
```

## Running Tests

### All tests

```bash
make test.multi-server
```

### CI tests only (short tests)

```bash
make test.multi-server.ci
```

### A specific test

```bash
make test.multi-server.proxy-accept.short_ci
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

# Multi-Server Profiling Tests

Four suites instrument FreeRADIUS under Valgrind to collect heap and call-graph profiles:

| Suite | What it exercises |
| --- | --- |
| `prof-accept` | Plain RADIUS accept (no external services) |
| `prof-pap-auth` | PAP authentication |
| `prof-ldap` | Authentication backed by an LDAP server |
| `prof-mysql` | Authentication backed by a MySQL database |

Results land in `prof-results/<suite>/<test>/<branch>/<commit>/<run-index>/`.

### Docker image dependencies

Profiling suites require images that are not needed by regular multi-server tests.
The `freeradius-prof.image` target builds or verifies them automatically before any `prof-*` test runs:

- `freeradius40x-build/ubuntu24:latest` — crossbuild base image
- `freeradius4-<profile>/ubuntu24:latest` — FreeRADIUS profiling base image
- `freeradius-prof:latest` — final multi-server profiling image (built by `build_image.sh`)

The `prof-ldap` suite additionally requires:

- `freeradius4/openldap-prof:latest` — built via the `openldap.image` target

To build all profiling images explicitly:

```bash
make freeradius-prof.image
make openldap.image   # prof-ldap only
```

### Running on Linux

Profiling tests run the same way as any other multi-server test:

```bash
make test.multi-server.prof-mysql.short_ci
```

### Running on macOS (Apple Silicon)

The profiling image is based on a `crossbuild.<distro>` base image that is built for
`linux/amd64`. On Apple Silicon you must pass `BUILD_PLATFORM=linux/amd64` so that
Docker pulls and runs the correct platform variant:

```bash
make test.multi-server.prof-mysql.short_ci BUILD_PLATFORM=linux/amd64
```

This applies to all four profiling suites and to the image-build targets as well:

```bash
make freeradius-prof.image BUILD_PLATFORM=linux/amd64
```
