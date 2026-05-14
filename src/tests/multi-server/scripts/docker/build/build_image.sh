#!/bin/bash
set -euo pipefail

BUILD_PLATFORM=""
IMAGE_TAG="latest"

for arg in "$@"; do
  case $arg in
    BUILD_PLATFORM=*)
      BUILD_PLATFORM="${arg#*=}"
      ;;
    IMAGE_TAG=*)
      IMAGE_TAG="${arg#*=}"
      ;;
  esac
done

# This allows us to build an image on Apple Silicon where the base image was built on an linux/amd64 platform.
# Example usage: BUILD_PLATFORM=linux/amd64 ./build_image.sh
PLATFORM_ARG=""
if [ -n "${BUILD_PLATFORM}" ]; then
    PLATFORM_ARG="--platform=${BUILD_PLATFORM}"
fi

docker build ${PLATFORM_ARG} \
    --build-arg BASE_TAG="${IMAGE_TAG}" \
    -f src/tests/multi-server/scripts/docker/build/Dockerfile.multi-server-prof \
    -t "freeradius-prof:${IMAGE_TAG}" \
    .
