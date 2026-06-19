ARG from=ubuntu:latest
FROM ${from} as build
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y libtalloc-dev
