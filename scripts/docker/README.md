# Docker build server images

## Summary

The dockerfiles in this directory are pre-configured with all the
dependencies necessary to build FreeRADIUS packages.

They are mostly here for the FreeRADIUS development team, but 3rd
party developers may also find them useful if they're shipping their
own packages, or performing debugging on behalf of the development
team.

Each directory has several dockerfiles:

 - Dockerfile.deps will build an image which has full dependencies
   installed, ready for building FreeRADIUS.

 - Dockerfile is based on Dockerfile.deps and will build the
   FreeRADIUS source and run the server.

 - Dockerfile.jenkins is based on Dockerfile.deps and will
   add components required for use in a jenkins build environment.


## Getting started

### Building

As with any Dockerfile you'll first need to build the image:

```bash
cd scripts/docker/build-<os_name>
docker build -f Dockerfile.deps -t freeradius/<os_name>-deps .
```

This will download the OS base image, install/build any dependencies
as necessary, and perform a shallow clone of the FreeRADIUS source.

The image will be tagged in the local ``freeradius/`` repository.

Once built, running ``docker images`` should show the image.

```bash
$ docker images
REPOSITORY                 TAG                 IMAGE ID            CREATED             SIZE
freeradius/centos7-deps    latest              0b7af2e27bef        10 minutes ago      2.15 GB
centos                     centos7             3bee3060bfc8        2 weeks ago         193 MB
```
You will now be able to execute the built image with an interactive
shell from which you can perform debugging or build packages.

From this base source image, the other images can be built. To
compile and run FreeRADIUS:

```bash
docker build -t freeradius:<os_name> .
docker run freeradius:<os_name>
```

To build the jenkins image:

```bash
docker build -f Dockerfile.jenkins -t freeradius:<os_name>-jenkins .
```

Building all these docker images can be done with the supplied
script, for example:

```bash
$ ./dockerbuild build-centos7
```

to build the server, and

```bash
$ ./dockerbuild -j build-centos7
```

to build the jenkins image.

### Running

The ``docker run`` command is used to create new containers from
images.  The command takes flags, and an image identifier.  In the
example below the ``-it`` flags tell docker to open an interactive
terminal on the container.

```bash
$ docker run -it freeradius/centos7-deps
[root@08a222f5fdfe freeradius-server]# ls
acinclude.m4  config.guess  configure.ac  debian      install-sh  main.mk      man      raddb      scripts  suse
aclocal.m4    config.sub    COPYRIGHT     doc         LICENSE     Makefile     mibs     README.md  share    VERSION
autogen.sh    configure     CREDITS       INSTALL.md  m4          Make.inc.in  missing  redhat     src
```

To run FreeRADIUS, use:

```bash
$ docker run freeradius/centos7
Info  : FreeRADIUS Version 4.0.0
Info  : Copyright (C) 1999-2017 The FreeRADIUS server project and contributors
...
```

When ``docker run`` is used to execute an image a new container is
created from the image.  This stores any changes you make, whilst
leaving the original container image unchanged.

You can attach multiple terminals to a docker container with ``docker
attach <hash>`` where hash is the temporary container id (for the
above example ``08a222f5fdfe``) displayed in the interactive shell
provided by ``docker run``.

You may also give your containers explicit container IDs by passing
``--name <name>`` to the ``docker run`` command.

### Debugging

By default if you try to use GDB in a docker container, the pattach
call will fail, and you will not be able to trace processes.

In order to allow tracing, the ``--privileged`` flag must be passed to
``docker run``, this restores any Linux ``cap`` privileges that would
not ordinarily be given.

### Networking

When docker is installed it creates a bridge interface.  By default,
any containers created will get an interface on this bridge.

Docker provides IP addresses for containers on this bridge
automatically, but as they are all in a private IP range they are not
routable from outside the host running docker.

The easiest way to get packets in and out of a container is to pass
the ``-p`` flag to docker run.  This binds a port in the container, to
a port on the docker host (similar to port forwarding).

See
[here](https://docs.docker.com/engine/userguide/networking/#embedded-dns-server)
for more details on docker networking.

### Example

Here are the steps you would follow to debug FreeRADIUS on centos7.

```
cd scripts/docker/build-centos7
docker build -f Dockerfile.deps -t freeradius/centos7-deps .
docker run --privileged -it freeradius/centos7-deps
```
