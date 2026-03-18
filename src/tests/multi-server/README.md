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
make test.multi-server.proxy-accept.short.ci
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
