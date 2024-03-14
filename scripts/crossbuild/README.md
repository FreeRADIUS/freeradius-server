# Crossbuild

## Summary

The "crossbuild" system is a way to build FreeRADIUS for multiple
different operating systems, using Docker.

The primary purpose is for developers to easily test FreeRADIUS on
different systems.

**Do not use this for running FreeRADIUS in production - see
`scripts/docker` instead.**


## Common Usage

The systems supported can be listed with

    make crossbuild.info

A reminder of the make targets may be seen with

    make crossbuild.help

To make all the known systems (this may take quite a while, at
least on the first run):

    make crossbuild

or for the most common systems (Debian, Ubuntu, CentOS, Rocky):

    make crossbuild.common


## General operation

The system works by building and then starting up Docker
containers for the systems. When a build is triggered (either
generally, as above, or for a specific OS) the current git commits
are copied into the image and then `make test` run.

The Docker containers are left running, and may be stopped with

    make crossbuild.down

The system tries to be as efficient as possible, so will not
rebuild the Docker images from scratch every time, but use an
existing image and copy just the latest git commits in for
testing.


## Global make targets

The following targets will operate on the crossbuild system
globally, or on all images (unless otherwise stated):

  - `make crossbuild`

    Create all docker images (if required), start them, build and
    test FreeRADIUS.


  - `make crossbuild.common`

    As `make crossbuild`, but only build and test the most common
    systems.


  - `make crossbuild.info`

    List all systems, together with the expected state. See
    `crossbuild.reset`.


  - `make crossbuild.down`

    Stop all containers.


  - `make crossbuild.reset`

    If containers are stopped or started outside Docker,
    crossbuild may get confused. This will clear the internal
    state which should try and start everything from be beginning
    again.


  - `make crossbuild.clean`

    Bring down all containers, clear state. This is a general
    "tidy up".


  - `make crossbuild.wipe`

    Don't just stop, but destroy all crossbuild docker images.
    This will mean they need to be recreated again upon next use.


## Per-image make targets

The following make targets may be used on a per-image basis:

 * `make crossbuild.IMAGE`:         build and test image
 * `make crossbuild.IMAGE.log`:     show latest build log
 * `make crossbuild.IMAGE.up`:      start container
 * `make crossbuild.IMAGE.down`:    stop container
 * `make crossbuild.IMAGE.sh`:      shell in container
 * `make crossbuild.IMAGE.refresh`: push latest commits into container
 * `make crossbuild.IMAGE.clean`:   stop container and tidy up
 * `make crossbuild.IMAGE.wipe`:    remove Docker image

For example, `make crossbuild.debian10` to create, build and test
FreeRADIUS on Debian 10. `make crossbuild.debian10.down` will then
stop the container.


## Docker image and container names

Docker images will be created with names in the form:

    freeradius-build/debian10

while containers will have names like:

    fr-crossbuild-debian10


## Re-generating Dockerfiles

The Dockerfiles used for crossbuild are generated from m4
templates. To regenerate one use `make crossbuild.IMAGE.regen`, or
`make crossbuild.regen` to generate them all. The m4 templates are
stored in `scripts/crossbuild/m4/`. This will usually only need to
be used to add a new operating system, not during standard build
testing.
