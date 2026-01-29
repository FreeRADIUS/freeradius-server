Multi-server testcases requires the availability of the "freeradius-multi-server" test framework repo on your system.

freeradius-multi-server repo: https://github.com/InkbridgeNetworks/freeradius-multi-server

Multi-server environment Docker compose environments are based on the fr-build-ubuntu22 image:
```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 make docker.ubuntu22.build
```

### Multi-server test run

```bash
DATA_PATH=${FREERADIUS-SERVER-REPO}/src/tests/multi-server/environments/configs make test-framework -- -x -v --compose ${FREERADIUS-SERVER-REPO}/src/tests/multi-server/environments/docker-compose/env-loadgen-5hs.yml --test ${FREERADIUS-SERVER-REPO}/src/tests/multi-server/test-5hs-autoaccept.yml --use-files --listener-dir $(pwd)/freeradius-listener-logs
```
