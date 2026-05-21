#!/bin/bash
for arg in "$@"; do
  case $arg in
    BUILD_PLATFORM=*) BUILD_PLATFORM="${arg#*=}" ;;
  esac
done

# This allows us to build an image on Apple Silicon where the base image was built on an linux/amd64 platform.
# Example usage: BUILD_PLATFORM=linux/amd64 ./build_image.sh
PLATFORM_ARG=""
if [ -n "${BUILD_PLATFORM}" ]; then
    PLATFORM_ARG="--platform=${BUILD_PLATFORM}"
fi

# Resolve the base profiling image tag. Defaults to the standard
# scripts/docker/build/<image>/Dockerfile.profiling output for ubuntu24
# at the current git short SHA, but can be overridden for ad-hoc builds.
BASE_IMAGE="${BASE_IMAGE:-freeradius4-profiling/ubuntu24:$(git rev-parse --short HEAD 2>/dev/null || echo latest)}"

docker build ${PLATFORM_ARG} \
    --build-arg from="${BASE_IMAGE}" \
    -f src/tests/multi-server/scripts/docker/build/Dockerfile.multi-server-prof \
    -t freeradius-prof:latest .
