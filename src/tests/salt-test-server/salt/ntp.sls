UTC:
  timezone.system

ntp_daemon:
    # Make sure ntp is installed and running
    pkg:
{% if grains['os'] == 'CentOS' or grains['os'] == 'Ubuntu' or grains['os'] == 'Debian' %}
        - name: ntp
{% elif grains['os'] == 'FreeBSD' %}
        - name: openntpd
{% endif %}
        - installed

# Make sure ntpd is running and enabled (start on boot)
{% if grains['os'] == 'CentOS' or grains['os'] == 'FreeBSD' %}
ntpd:
{% elif grains['os'] == 'Ubuntu' or grains['os'] == 'Debian' %}
ntp:
{% endif %}
    service:
        - running
        - enable: True
