# Profiling FreeRADIUS From Repo Source Files

## Build Profiling-Deps Image

Build the image with all dependencies (`freeradius4-profiling-deps/ubuntu24`):

```bash
cd <freeradius-server-local-repo>
make docker.clean
make docker.profiling.ubuntu24
```

## Profile

### Run Container

Terminal 1:

```bash
docker run --rm -it \
    --name fr-profiling \
    --cap-add=SYS_PTRACE \
    -v $(pwd):/freeradius \
    -w /freeradius \
    --platform linux/amd64 \
    freeradius4-profiling-deps/ubuntu24:latest bash
```

### Configure and Build FreeRADIUS

```bash
docker exec -it fr-profiling bash

./scripts/profiling/config_and_build.sh --fr_src_dir /freeradius
```

### Start Valgrind

Terminal 2:

```bash
docker exec -it fr-profiling bash

./scripts/profiling/start_valgrind.sh --fr_src_dir /freeradius
```

### Run Tests

Run one or more tests while Valgrind is listening.

Terminal 3:

```bash
docker exec -it <container-id> bash

cd /freeradius
make test.keywords.3gpp
```
