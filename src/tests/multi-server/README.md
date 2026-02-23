If you are reading this, you are probably wondering how to run a multi-server test.  Here's a quick overview.

## Before You Begin
Running the multi-server tests requires the availability of a Docker image `freeradius-build:latest` to be available on the host running the tests.
```bash
% cd ${FREERADIUS-SERVER-LOCAL-REPO}
% make docker.ubuntu24.build
% docker tag <your-freeradius-docker-image-tag> freeradius-build:latest
```


## Run Test With Makefile
### Run All Tests

2. Run make target based on the test name. All testcase config files start with "test-*".
```bash
% cd ${FREERADIUS-SERVER-LOCAL-REPO}
% make -f src/tests/multi-server/all.mk
```

### Run Specific Tests (Example)
```bash
% cd ${FREERADIUS-SERVER-LOCAL-REPO}
% make -f src/tests/multi-server/all.mk test-5hs-autoaccept
```
or
```bash
% cd ${FREERADIUS-SERVER-LOCAL-REPO}
% make -f src/tests/multi-server/all.mk test-1p-2hs-autoaccept
```

### Optional Debug Logs and Logging Verbosity Level
```bash
% cd ${FREERADIUS-SERVER-LOCAL-REPO}
% make -f src/tests/multi-server/all.mk test-5hs-autoaccept DEBUG=1 VERBOSE=4
```

## Run Multi-Server Tests Manually Without Makefile (Optional)

### Clone Multi-Server Test Framework Repo & Activate Python venv
```bash
git clone git@github.com:InkbridgeNetworks/freeradius-multi-server.git ${FREERADIUS-MULTI-SERVER-LOCAL-REPO}
cd ${FREERADIUS-MULTI-SERVER-LOCAL-REPO}
./configure
source .venv/bin/activate
```

### Render Jinja Templates

In this example we render the Jinja templates used by the environment configuration used by the  `test-5hs-autoaccept` test.
The Docker Compose `env-5hs-autoaccept.yml` file represents the `load-generator -> 5 homeserver` test environment used by the test.

Render FreeRADIUS "homeserver" Virtual Server config:
```bash
% python3 src/config_builder.py \
    --vars-file "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/environments/jinja-vars/env-5hs-autoaccept.vars.yml" \
    --aux-file "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/environments/configs/freeradius/homeserver/radiusd.conf.j2" \
    --include-path "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/"
 ```
 Render FreeRADIUS "load-generator" Virtual Server config:
 ```bash
 python3 src/config_builder.py \
    --vars-file "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/environments/jinja-vars/env-5hs-autoaccept.vars.yml" \
    --aux-file "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/environments/configs/freeradius/load-generator/radiusd.conf.j2" \
    --include-path "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/"
```
Render Docker Compose environment:
```bash
 python3 src/config_builder.py \
    --vars-file "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/environments/jinja-vars/env-5hs-autoaccept.vars.yml" \
    --aux-file "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/environments/docker-compose/env-5hs-autoaccept.yml.j2" \
    --include-path "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/"
```

### Run the test:
```bash
% DATA_PATH="${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/environments/configs" \
			make test-framework -- -x -v \
			--compose "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/environments/docker-compose/env-5hs-autoaccept.yml" \
			--test "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/src/tests/multi-server/test-5hs-autoaccept.yml" \
			--use-files \
			--listener-dir "${FREERADIUS-MULTI-SERVER-LOCAL-REPO_ABS_PATH}/build/tests/multi-server/freeradius-multi-server-test-runtime-logs/test-5hs-autoaccept"
```
