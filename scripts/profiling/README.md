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

Inside the container, configure the server with dev CFLAGS and build:

```bash
./configure \
  --enable-developer \
  --disable-verify-ptr \
  CFLAGS="-g3 -O1 -fno-omit-frame-pointer -fno-inline -Dalways_inline= -fno-optimize-sibling-calls -fno-plt -fno-builtin" \
  LDFLAGS="-fno-omit-frame-pointer"

make -j$(nproc)
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
