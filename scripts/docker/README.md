# What is FreeRADIUS?

The FreeRADIUS Server Project is a high performance and highly
configurable multi-protocol policy server, supporting RADIUS, DHCPv4
and VMPS. Using RADIUS allows authentication and authorization for a network
to be centralized, and minimizes the number of changes that have to
be done when adding or deleting new users to a network.

FreeRADIUS can authenticate users on systems such as 802.1x
(WiFi), dialup, PPPoE, VPN's, VoIP, and many others.  It supports
back-end databases such as MySQL, PostgreSQL, Oracle, Microsoft
Active Directory, Redis, OpenLDAP. It is used daily to
authenticate the Internet access for hundreds of millions of
people, in sites ranging from 10 to 10 million+ users.

> [wikipedia.org/wiki/FreeRADIUS](https://en.wikipedia.org/wiki/FreeRADIUS)


# How to use this image

## Starting the server

```console
$ docker run --name my-radius -d freeradius/freeradius-server
```

The image contains only the default FreeRADIUS configuration which
has no users, and accepts test clients on 127.0.0.1. In order to
use it in production, you will need to add clients to the `clients.conf`
file, and users to the "users" file in `mods-config/files/authorize`.

Also we support parameters to inform the client address/subnet and secret.

e.g:

```console
$ docker run --name my-radius -e CLIENT_ADDR="172.17.0.0/16" -e CLIENT_SECRET="testing123" -d freeradius/freeradius-server
```

## Defining the configuration

Create a local `Dockerfile` based on the required image and
COPY in the server configuration.

```Dockerfile
FROM freeradius/freeradius-server:latest
COPY raddb/ /etc/raddb/
```

The `raddb` directory could contain, for example:

```
clients.conf
mods-config/
mods-config/files/
mods-config/files/authorize
```

Where `clients.conf` contains a simple client definition

```
client dockernet {
	ipaddr = 172.17.0.0/16
	secret = testing123
}
```

and the `authorise` "users" file contains a test user:

```
bob	Cleartext-Password := "test"
```


## Forwarding ports

To forward external ports to the server, typically 1812/udp and/or
1813/udp, start the server with

```console
$ docker run --name my-radius -p 1812-1813:1812-1813/udp freeradius/freeradius-server
```


## Testing the configuration

It should now be possible to test authentication against the
server from the host machine, using the `radtest` utility supplied
with FreeRADIUS and the credentials defined above:

```console
$ radtest bob test 127.0.0.1 0 testing123
```

which should return an "Access-Accept".


## Running in debug mode

FreeRADIUS should always be tested in debug mode, using option
`-X`. Coloured debug output also requres `-t` be passed to docker.

```console
$ docker run --name my-radius -t -d freeradius/freeradius-server -X
```

Guidelines for how to read and interpret the debug output are on the
[FreeRADIUS Wiki](https://wiki.freeradius.org/radiusd-X).

## Security notes

The configuration in the docker image comes with self-signed
certificates for convenience. These should not be used in a
production environment, but replaced with new certificates. See
the file `raddb/certs/README` for more information.

## Debugging

By default if you try to use `gdb` in a Docker container, the
pattach call will fail, and you will not be able to trace
processes.

In order to allow tracing, the ``--privileged`` flag must be
passed to ``docker run``, this restores any Linux ``cap``
privileges that would not ordinarily be given.


# Image variants

## `freeradius/freeradius-server:<version>`

The de facto image which should be used unless you know you need
another image. It is based on
[Ubuntu Linux](https://hub.docker.com/_/ubuntu/) Docker images.


## `freeradius/freeradius-server:<version>-alpine`

Image based on the [Alpine Linux](https://hub.docker.com/_/alpine/)
Docker images, which are much smaller than most Linux
distributions. To keep the basic size as small as possible, this
image does not include libraries for all modules that have been
built (especially the languages such as Perl or Python). Therefore
these extra libraries will need to be installed with `apk add` in
your own Dockerfile if you intend on using modules that require
them.


# Building Docker images

The FreeRADIUS source contains Dockerfiles for several Linux
distributions. They are in
[`freeradius-server/scripts/docker/<os_name>`](https://github.com/FreeRADIUS/freeradius-server/tree/v3.0.x/scripts/docker).

Build an image with

```bash
$ cd scripts/docker/<os_name>
$ docker build . -t freeradius-<os_name>
```

This will download the OS base image, install/build any dependencies
as necessary, perform a shallow clone of the FreeRADIUS source and
build the server.

Once built, running ``docker images`` should show the image.

```bash
$ docker images
REPOSITORY           TAG            IMAGE ID            CREATED             SIZE
freeradius-ubuntu16  latest         289b3c7aca94        4 minutes ago       218MB
freeradius-alpine    latest         d7fb3041bea2        2 hours ago         88.6MB
```

## Build args

Two ARGs are defined in the Dockerfiles that specify the source
repository and git tag that the release will be built from. These
are

- source: the git repository URL
- release: the git commit/tag

To build the image from a specific repository and git tag, set one
or both of these args:

```console
$ docker build . --build-arg=release=v3.0.x --build-arg=source=https://github.com/FreeRADIUS/freeradius-server.git -t freeradius-<os_name>
```
