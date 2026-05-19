#
#  Retry transient package-repo failures. dnf retries 10 times by default;
#  cap that at 3 and shorten the per-request timeout from 30s to 15s so a
#  hung mirror fails fast and the retry kicks in quickly. Stall detection
#  (minrate) stays on so a stalled in-flight download still gets killed.
#
RUN printf 'retries=3\ntimeout=15\n' >> /etc/dnf/dnf.conf
