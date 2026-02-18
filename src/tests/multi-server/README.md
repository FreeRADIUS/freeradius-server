If you are reading this, you are probably wondering how to run a multi-server test.  Here's a quick overview.

## Run Test With Makefile

1. Build an image of freeradius-server and tag it as "freeradius-build:latest". All docker compose files for the multi-server tests use "freeradius-build:latest".
```bash
% cd ${FREERADIUS-SERVER-LOCAL-REPO}
% make docker.ubuntu24.build
% docker tag <your-freeradius-build-tag> freeradius-build:latest
```
2. Run make target based on the test name. All testcase config files start with "test-*".
```bash
% cd ${FREERADIUS-SERVER-LOCAL-REPO}/src/tests/multi-server
% make -f all.mk test-5hs-autoaccept
```
or
```bash
% cd ${FREERADIUS-SERVER-LOCAL-REPO}/src/tests/multi-server
% make -f all.mk test-5hs-autoaccept-5min
```

## Run Multi-Server Tests Manually

### Clone Multi-Server Framework Repo
```bash
git clone git@github.com:InkbridgeNetworks/freeradius-multi-server.git
cd ${FREERADIUS-MULTI-SERVER-LOCAL-REPO}
./configure
source .venv/bin/activate
```

### Render Jinja Templates (e.g. test-5hs-autoaccept):

Homeserver config:
```bash
% python3 src/config_builder.py \
    --vars-file "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/environments/jinja-vars/env-5hs-autoaccept.vars.yml" \
    --aux-file "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/environments/configs/freeradius/homeserver/radiusd.conf.j2" \
    --include-path "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/"
 ```
 Load-generator config:
 ```bash
 python3 src/config_builder.py \
    --vars-file "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/environments/jinja-vars/env-5hs-autoaccept.vars.yml" \
    --aux-file "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/environments/configs/freeradius/load-generator/radiusd.conf.j2" \
    --include-path "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/"
```
Test Environment Docker compose:
```bash
 python3 src/config_builder.py \
    --vars-file "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/environments/jinja-vars/env-5hs-autoaccept.vars.yml" \
    --aux-file "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/environments/docker-compose/env-5hs-autoaccept.yml.j2" \
    --include-path "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/"
```

### Run test (e.g. test-5hs-autoaccept):
```bash
% DATA_PATH="${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/environments/configs" \
			make test-framework -- -x -v \
			--compose "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/environments/docker-compose/env-5hs-autoaccept.yml" \
			--test "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/src/tests/multi-server/test-5hs-autoaccept.yml" \
			--use-files \
			--listener-dir "${FREERADIUS-SERVER-LOCAL-REPO-PATH-ABS}/build/tests/multi-server/freeradius-listener-logs/test-5hs-autoaccept"
```
