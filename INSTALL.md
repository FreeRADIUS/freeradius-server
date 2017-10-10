# Installation
## Introduction

Ignore the installation instructions in this file if you have a
pre-installed binary package.  

When upgrading from older versions of FreeRADIUS, you should read
ALL of this file, especially the section on [Upgrading](#upgrading)
which gives information on how to update your configuration.

**WARNING**  Failure to properly update your configurations may cause
your previously working FreeRADIUS server to no longer authenticate
your users.

Whether you are installing from source or a pre-built binary
package, you should read the section [Running The Server](#running-the-server).


## Simple build from Source

If you do not need to modify the default configuration, then take
the following steps to build and install the server from source:

```bash
./configure
make
make install
```

## Custom build

FreeRADIUS has GNU autoconf support. This means you have to run
``./configure``, and then run ``make``.  To see which configuration options
are supported, run ``./configure --help``, and read it's output.  The
following list is a selection from the available flags:

```text
  --with-logdir=DIR       Directory for logfiles [LOCALSTATEDIR/log] 
  --with-radacctdir=PATH  Directory for detail files [LOGDIR/radacct] 
  --with-raddbdir=DIR     Directory for config files [SYSCONFDIR/raddb] 
  --with-threads          Use threads, if available.  (default=yes) 
  --with-snmp             Compile in SNMP support. (default=yes)
  --with-dhcp             Compile in DHCP support. (default=yes)
  --with-experimental-modules  Use experimental and unstable modules.
                               (default=no) 
  --enable-developer      Turns on super-duper-extra-compile-warnings
                          when using gcc, as well as experimental modules.
```

The ``make install`` stage will install the binaries, the 'man' pages,
and MAY install the configuration files.  If you have not installed a
RADIUS server before, then the configuration files for FreeRADIUS will
be installed.  If you already have a RADIUS server installed, then

**FreeRADIUS WILL NOT over-write your current configuration.**

The ``make install`` process will warn you about the files it could
not install.

If you see a warning message about files that could not be
installed, then you MUST ensure that the new server is using the new
configuration files, and not the old configuration files as this may cause
undesired behavior and failure to authenticate.

The initial output from running in debugging mode (``radiusd -X``) will tell
you which configuration files are being used.  See [Upgrading](#upgrading) for
information about upgrading from older versions.  There MAY be changes
in the dictionary files which are REQUIRED for a new version of the
software.  These files will NOT be installed over your current
configuration, so you MUST verify and install any problem files by
hand, for example using ``diff(1)`` to check for changes.

It is EXTREMELY helpful to read the output of ``./configure``,
``make``, and ``make install``.  If a particular module you expected to be
installed was not installed, then the output of the
``./configure; make; make install`` sequence will tell you why that module
was not installed.  Please do NOT post questions to the FreeRADIUS
users list without first carefully reading the output of this process as it
often contains the information needed to resolve a problem.

## Upgrading

The installation process will not over-write your existing
configuration files.  It will, however, warn you about the files it
did not install. These will require manual integration with the existing files.

It is generally not possible to re-use configurations between
different major versions of the server. (For example - 2.x to 3.x)

For details on what has changed between the version, see ``raddb/README.md``.

We STRONGLY recommend that new major versions be installed in a different 
location than any existing installations.  Any local policies can
then be migrated gradually to the configuration format of the new major
version.  The number of differences in the new configuration mean that is
is both simpler and safer to migrate your configurations rather than to try
and just get the old configuration to work.

## Running the server

If the server builds and installs, but doesn't run correctly, then
you should first use debugging mode (``radiusd -X``) to figure out the problem. 

This is your BEST HOPE for understanding the problem.  Read ALL of
the messages which are printed to the screen, the answer to your
problem will often be in a warning or error message.

We really can't emphasize that last sentence enough.  Configuring a
RADIUS server for complex local authentication isn't a trivial task.
Your BEST and ONLY method for debugging it is to read the debug messages, where
the server will tell you exactly what it's doing, and why.  You should
then compare its behaviour to what you intended, and edit the
configuration files as appropriate.

If you don't use debugging mode, and ask questions on the mailing
list, then the responses will all tell you to use debugging mode.  The
server prints out a lot of information in this mode, including
suggestions for fixes to common problems.  Look especially for
"WARNING" in the output, and read the related messages.

Since the main developers of FreeRADIUS use debugging mode to track
down their configuration problems with the server, it's a good idea
for you to use it, too.  If you don't, there is little hope for you to
solve ANY configuration problem related to the server.

To start the server in debugging mode, do:

```bash
radiusd -X
```

You should see a lot of text printed on the screen as it starts up.
If you don't, or if you see error messages, please read the FAQ:

  https://wiki.freeradius.org/guide/FAQ

If the server says "Ready to process requests.", then it is running
properly.  From another shell (or another window), type

```bash
radtest test test localhost 0 testing123
```

You should see the server print out more messages as it receives the
request, and responds to it.  The 'radtest' program should receive the
response within a few seconds.  It doesn't matter if the
authentication request is accepted or rejected, what matters is that
the server received the request, and responded to it.

You can now edit the configuration files for your local system. You
will usually want to start with ``sites-enabled/default`` for main configurations.
To set which NASes (clients) can communicate with this server, edit ``raddb/clients.conf``.
Please read the configuration files carefully, as many configuration
options are only documented in comments in the file.

Note that is is HIGHLY recommended that you use some sort of version
control system to manage your configuration, such as git or
Subversion. You should then make small changes to the configuration,
checking in and testing as you go. When a config change causes the
server to stop working, you will be able to easily step back and find
out what update broke the configuration.

It is also considered a best practice to maintain a staging or development environment.
This allows you to test and integrate your changes without impacting your active production
environment. You should make the appropirate investment in order to properly support a
critical resource such as your authentication servers.

Configuring and running the server MAY be complicated.  Many modules
have ``man`` pages.  See ``man rlm_pap``, or ``man rlm_*`` for 
information.
Please read the documentation in the doc/ directory.  The comments in
the configuration files also contain a lot of documentation.

If you have any additional issues, the FAQ is also a good place to
start.

  https://wiki.freeradius.org/guide/FAQ

