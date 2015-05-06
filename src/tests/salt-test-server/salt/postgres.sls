postgresql:
    # Install postgres and make sure it is running and starts on boot
    pkg:
        - installed
    # Only try to start service after DB has been initialized (will fail otherwise)
    service:
        - name: postgresql
        - running
        - enable: True

postgres_set_interface:
    file.sed:
        - name: /etc/postgresql/9.4/main/postgresql.conf
        - before: ^\#listen_addresses = 'localhost'
        - after: listen_addresses = '*'

postgres_password_auth:
    # Add authentication from anywhere
    file.append:
        - name: /etc/postgresql/9.4/main/pg_hba.conf
        - text:
            - host    radius      radius        0.0.0.0/0            md5

postgres_restart:
    # Restart postgres after changes to the config file (reload isn't enough)
    cmd.wait:
        - cwd: /
        - name: service postgresql restart
        - require:
            - pkg: postgresql
            - file: postgres_password_auth
            - file: postgres_set_interface
        - watch:
            - file: /etc/postgresql/9.4/main/postgresql.conf
            - file: /etc/postgresql/9.4/main/pg_hba.conf

# Copy DB schema file
/salt/postgres/schema.sql:
    file.managed:
        - source: salt://postgres/schema.sql
        - makedirs: true

# Copy DB setup script
/salt/postgres/setup.sql:
    file.managed:
        - source: salt://postgres/setup.sql
        - makedirs: true

# Create DB
create_db:
    cmd.run:
        - cwd: /
        - name: createdb radius
        - user: postgres
        - unless: psql --list | grep radius

# Create FreeRADIUS schema
psql radius < /salt/postgres/schema.sql:
    cmd.run:
        - user: postgres
        - unless: "echo '\\dt public.*' | psql radius | grep radacct;"
        - require:
            - file: /salt/postgres/schema.sql

# Setup DB access
psql radius < /salt/postgres/setup.sql:
    cmd.run:
        - user: postgres
        - unless: "echo '\\du' | psql radius | grep radius"
        - require:
            - file: /salt/postgres/setup.sql
