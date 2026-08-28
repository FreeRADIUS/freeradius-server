#
#  Build and install eapol_test, the client the EAP tests drive the server
#  with.
#
#  No package ships eapol_test.  A test run that cannot find a copy clones
#  the whole hostap repository from git.w1.fi and compiles the binary, which
#  adds minutes to the run and fails when that one host is down.
#
#  scripts/ci/eapol_test-build.sh takes any eapol_test on the PATH before it
#  builds one, so installing the binary here makes the clone and compile go
#  away.  The same script builds this copy, and HOSTAPD_GIT_TAG must match
#  the tag in .github/workflows/ci.yml so every runner tests the same
#  eapol_test version.
#
#  The libnl headers the build needs come from the CI extras in the template
#  that includes this file.
#
COPY scripts/ci/eapol_test-build.sh /tmp/eapol_test-build/
COPY scripts/ci/eapol_test/ /tmp/eapol_test-build/eapol_test/
RUN FORCE_BUILD=1 HOSTAPD_GIT_TAG=hostap_2_11 /tmp/eapol_test-build/eapol_test-build.sh && \
	install -m 0755 /tmp/eapol_test-build/eapol_test/eapol_test /usr/local/bin/eapol_test && \
	rm -rf /tmp/eapol_test-build
