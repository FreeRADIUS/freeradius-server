# Profiling FreeRADIUS From Repo Source Files

## Build Profiling-Deps Image

Build the image with all dependencies (`freeradius4-profiling-deps/ubuntu24`):

### Linux
```bash
cd <freeradius-server-local-repo>
make docker.clean
make docker.profiling.ubuntu24
```

### macOS
```
cd <freeradius-server-local-repo>
make docker.clean
DOCKER_DEFAULT_PLATFORM=linux/amd64 NOCACHE=1 make docker.profiling.ubuntu24
```

## Profile

### Run Container

Terminal 1:

```bash
docker run --rm -it \
    --name fr-profiling \
    -v $(pwd):/freeradius \
    -w /freeradius \
    --platform linux/amd64 \
    freeradius4-profiling-deps/ubuntu24:latest bash
```

### Configure and Build FreeRADIUS

Terminal 1:

```bash
# If not already in the container
docker exec -it fr-profiling bash

./scripts/profiling/bash/config_and_build.sh --fr_src_dir /freeradius
```

### Start Valgrind

Terminal 1:

```bash
# If not already in the container
docker exec -it fr-profiling bash

./scripts/profiling/bash/start_valgrind.sh --fr_src_dir /freeradius --results_dir <custom-results-dir-name>
```

### Run Tests (Example)

Run one or more tests while Valgrind is listening.

Terminal 2:

```bash
docker exec -it fr-profiling bash

cd /freeradius
make test.keywords.3gpp
```
### Stop Valgrind Process

Terminal 1:

```
Ctrl-C
```

## Analyze Results

The `analyze_profiling_results_cest.sh` script computes Callgrind Cycle Estimation
(CEst) cost from one or two result directories and reports per-pattern and
category breakdowns. Pass function-name substrings as patterns (case-insensitive).

```text
./analyze_profiling_results_cest.sh [--md <file>] [--top N] \
    -d <dir1> [-d <dir2> ...] <pat1> [pat2 ...]

  Note:
  --md <file>   also write a Markdown report (console still prints)
  --top N       top-N functions per pattern (default 10)
```

### Single directory

```bash
./scripts/profiling/bash/analyze_profiling_results_cest.sh \
    --md report.md \
    --top 10 \
    -d ./prof-results \
    talloc
```

### Two directories (baseline vs. comparison)

```bash
./scripts/profiling/bash/analyze_profiling_results_cest.sh \
    --md report.md \
    --top 10 \
    -d ./prof-results-baseline \
    -d ./prof-results-new \
    talloc
```

With two directories the script prints a comparison footer showing the
percentage change in total CEst and per-pattern CEst relative to the first
directory (baseline). The `--md` flag writes the same output to a Markdown
file.
