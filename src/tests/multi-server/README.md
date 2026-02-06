Multi-server testcases requires the availability of the "freeradius-multi-server" test framework repo on your system.

freeradius-multi-server repo: https://github.com/InkbridgeNetworks/freeradius-multi-server

Multi-server environment Docker compose environments are based on the fr-build-ubuntu22 image:
```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 make docker.ubuntu22.build
```

### Jinja2 Template Pre-Processing:
```bash
freeradius-multi-server % python3 src/config_builder.py --listener_type file --aux ${FREERADIUS-SERVER-LOCAL-REPO}/src/tests/multi-server/environments/configs/freeradius/homeserver/radiusd.conf.j2 --includepath ${FREERADIUS-SERVER-LOCAL-REPO}/src/tests/multi-server
 ```
 ```bash
freeradius-multi-server % python3 src/config_builder.py --listener_type file --aux ${FREERADIUS-SERVER-LOCAL-REPO}/src/tests/multi-server/environments/configs/freeradius/load-generator/radiusd.conf.j2 --includepath ${FREERADIUS-SERVER-LOCAL-REPO}/src/tests/multi-server
```

### Testcase "run" command:

```bash
(.venv) freeradius-multi-server % DATA_PATH=${FREERADIUS-SERVER-LOCAL-REPO}/src/tests/multi-server/environments/configs make test-framework -- -x -v --compose ${FREERADIUS-SERVER-LOCAL-REPO}/src/tests/multi-server/environments/docker-compose/env-loadgen-5hs.yml --test ${FREERADIUS-SERVER-LOCAL-REPO}/src/tests/multi-server/test-5hs-autoaccept.yml --use-files --listener-dir --listener-dir ${FREERADIUS-SERVER-LOCAL-REPO}/build/tests/multi-server/freeradius-listener-logs/${TEST_NAME}
```
