#!/bin/bash
for arg in "$@"; do
  case $arg in
    BUILD_PLATFORM=*) BUILD_PLATFORM="${arg#*=}" ;;
  esac
done

# This allows us to run a container on Apple Silicon where the base image was built on an linux/amd64 platform.
# Example usage: BUILD_PLATFORM=linux/amd64 ./run_container.sh
PLATFORM_ARG=""
if [ -n "${BUILD_PLATFORM}" ]; then
    PLATFORM_ARG="--platform=${BUILD_PLATFORM}"
fi

docker run -it --rm ${PLATFORM_ARG} -v "$(pwd)/prof-results:/etc/prof-results" --name freeradius-radenv-container freeradius-prof:latest
