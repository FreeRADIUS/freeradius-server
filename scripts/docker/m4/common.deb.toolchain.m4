#
#  Refresh apt lists, upgrade in place, install the build toolchain.
#  Shared by the production, crossbuild, and CI base templates - each
#  adds whatever extras they specifically need on top.
#
RUN apt-get update && apt-get dist-upgrade -y

RUN apt-get install -y --no-install-recommends \
		apt-transport-https \
		build-essential \
		ca-certificates \
		curl \
		devscripts \
		equivs \
		fakeroot \
		git-core \
		gnupg2 \
		lsb-release \
		make \
		quilt

include(`common.deb.libkqueue.m4')dnl
