#
#  Retry transient apt repo failures. apt does no retries out of the box;
#  turn that on and shorten the connect timeout so a hung mirror fails
#  fast and the retry kicks in quickly. Belt-and-braces dpkg / debconf
#  tweaks save a few seconds per image build.
#
RUN printf 'Acquire::Retries "3";\nAcquire::http::ConnectTimeout "5";\nAcquire::https::ConnectTimeout "5";\n' \
		> /etc/apt/apt.conf.d/80-retries && \
	printf 'force-unsafe-io\n' > /etc/dpkg/dpkg.cfg.d/02speedup && \
	echo 'man-db man-db/auto-update boolean false' | debconf-set-selections
