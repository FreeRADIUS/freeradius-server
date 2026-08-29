#
#  Build eapol_test and install eapol_test into `/usr/local/bin`.
#
#  eapol_test is the Extensible Authentication Protocol (EAP) client that the
#  EAP tests use to authenticate against the server.  No distribution packages
#  eapol_test.
#
#  When a test run finds no eapol_test, `scripts/ci/eapol_test-build.sh` clones
#  the hostap repository from 'git.w1.fi' and compiles eapol_test.  The clone
#  and the compilation add several minutes to the run, and both fail whenever
#  'git.w1.fi' is unreachable.  The same script checks `PATH` before compiling and
#  uses any eapol_test already installed, so the eapol_test installed below
#  removes the clone and the compilation from every test run.
#
#  `HOSTAPD_GIT_TAG` below must match `HOSTAPD_GIT_TAG` in
#  `.github/workflows/ci.yml`, so that every runner tests the same version of
#  eapol_test.
#
#  Compiling eapol_test requires the libnl development headers, which every
#  template that includes this file installs.
#
COPY scripts/ci/eapol_test-build.sh /tmp/eapol_test-build/
COPY scripts/ci/eapol_test/ /tmp/eapol_test-build/eapol_test/
RUN FORCE_BUILD=1 HOSTAPD_GIT_TAG=hostap_2_11 /tmp/eapol_test-build/eapol_test-build.sh && \
	install -m 0755 /tmp/eapol_test-build/eapol_test/eapol_test /usr/local/bin/eapol_test && \
	rm -rf /tmp/eapol_test-build
