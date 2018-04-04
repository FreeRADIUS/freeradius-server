# Docker build server images

The dockerfiles in this directory are pre-configured with all the
dependencies necessary to build FreeRADIUS packages.

Each directory has a Dockerfile for the relevant distribution.


## Building images

As with any Dockerfile you'll first need to build the image.

```bash
cd scripts/docker/<os_name>
docker build . -t freeradius/<os_name>:v3.0.x
```

This will download the OS base image, install/build any dependencies
as necessary, and perform a shallow clone of the FreeRADIUS source.

The image will be tagged in the local ``freeradius/`` repository.

Once built, running ``docker images`` should show the image.

```bash
$ docker images
REPOSITORY                 TAG                 IMAGE ID            CREATED             SIZE
freeradius/alpine   v3.0.x              83e45ae94d21        18 hours ago        88.6MB
alpine              latest              3fd9065eaf02        7 weeks ago         4.15MB
```


## Running

The ``docker run`` command is used to create new containers from
images.  The command takes flags, and an image identifier.  In the
example below the ``-it`` flags tell docker to open an interactive
terminal on the container.

```bash
$ docker run -it freeradius/alpine
FreeRADIUS Version 3.0.17
Copyright (C) 1999-2017 The FreeRADIUS server project and contributors
...
```

When ``docker run`` is used to execute an image a new container is
created from the image.  This stores any changes you make, whilst
leaving the original container image unchanged.

You can attach multiple terminals to a docker container with
``docker attach <hash>`` where hash is the temporary container id,
found from running ``docker container ls``.

You may also give your containers explicit container IDs by passing
``--name <name>`` to the ``docker run`` command.


## Debugging

By default if you try to use GDB in a docker container, the pattach
call will fail, and you will not be able to trace processes.

In order to allow tracing, the ``--privileged`` flag must be passed to
``docker run``, this restores any Linux ``cap`` privileges that would
not ordinarily be given.


## Networking

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

