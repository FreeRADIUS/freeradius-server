{% if grains['os'] == 'CentOS' %}
update_firewall:
    file.managed:
        - name: /etc/sysconfig/iptables
        - source: salt://iptables

reload_iptables:
    cmd.wait:
        - cwd: /
        - name: service iptables reload
        - watch:
            - file: /etc/sysconfig/iptables
{% endif %}
