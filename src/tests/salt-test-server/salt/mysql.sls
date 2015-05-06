mysql-server:
    pkg.installed

# On Ubuntu, the default MySQL install only listens on localhost
/etc/mysql/my.cnf:
{% if grains['os'] == 'Ubuntu' %}
    file.sed:
        - before: 127.0.0.1
        - after: 0.0.0.0
        - limit: ^bind-address\s+=
        - require:
            - pkg: mysql-server
{% else %}
    file.exists
{% endif %}

mysql_daemon:
    service:
{% if grains['os'] == 'CentOS' %}
        - name: mysqld
{% elif grains['os'] == 'Ubuntu' or grains['os'] == 'Debian' %}
        - name: mysql
{% endif %}
        - running
        - enable: True
        - watch:
            - file: /etc/mysql/my.cnf
        - require:
            - pkg: mysql-server

## FW rules don't work well with CentOS < 7
# Insert is run each time
#
#    iptables.insert:
#        - position: 1
#        - table: filter
#        - chain: INPUT
#        - j: ACCEPT        # Use 'j' instead of 'jump' because iptables-save outputs 'j' flag.
#        - match: state
#        - connstate: NEW
#        - dport: 3306
#        - proto: tcp
#        - save: True

# Copy DB schema file
/salt/mysql/schema.sql:
    file.managed:
        - source: salt://mysql/schema.sql
        - makedirs: true

# Copy DB setup script
/salt/mysql/setup.sql:
    file.managed:
        - source: salt://mysql/setup.sql
        - makedirs: true

# Create DB
echo "CREATE DATABASE radius" | mysql:
    cmd.run:
        - creates: /var/lib/mysql/radius/db.opt

# Create FreeRADIUS schema
mysql radius < /salt/mysql/schema.sql:
    cmd.run:
        - unless: "echo 'desc radacct' | mysql radius"
        - require:
            - file: /salt/mysql/schema.sql

# Setup DB access
mysql radius < /salt/mysql/setup.sql:
    cmd.run:
        - unless: "echo \"show grants for 'radius';\" | mysql"
        - require:
            - file: /salt/mysql/setup.sql
