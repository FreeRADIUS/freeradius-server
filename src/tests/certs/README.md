# Test Certificates

The certificates in this directory are for regression tests only.
They let us run the regression tests without re-generating the certs.

These certificates MUST NOT be installed.

These certificates MUST NOT be used in a production environment.

## Regenerating the certificates

Just do:

    make

The Makefile will do the necessary work.

Then:

    git commit .

