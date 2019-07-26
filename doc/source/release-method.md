= Release Method

# Topics

1. As of 2.0, the release process is much simpler.  Edit the
Changelog with the version number and any last updates.

```
# vi doc/ChangeLog
# git commit doc/ChangeLog
```

2. Change version numbers in the VERSION file:

```
# vi VERSION
# git commit VERSION
```

3. Make the files

NOTE: It also does `make dist-check`, which checks
the build rules for various packages.

```
# make dist
```

4. Validate that the packages are OK.  If so, tag the release.

NOTE: This does NOT actually do the tagging!  You will
have to run the command it prints out yourself.

```
# make dist-tag
```

5. Sign the packages.  You will need the correct GPG key for this
to work.

```
# make dist-sign
```

6. Push to the FTP site.  You will need write access to the FTP site
for this to work.

```
# make dist-publish
```
