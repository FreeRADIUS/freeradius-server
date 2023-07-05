#!/bin/bash
# Other shells not tested

yes | docker compose rm &> /dev/null
if ! [ "$?" -eq 0 ]; then
  echo "Docker failed"
  exit 1
fi

### ARGUMENT PARSING ###
# Note -s and -b require the freeradius docker image to be rebuilt, meaning it must be removed, or renamed with -i.
while getopts ':n:l:i:d:r:o:bm' OPTION; do
  case "$OPTION" in
    n)
      num_requests="$OPTARG"
      ;;
    l)
      log_level="$OPTARG"
      ;;
    i)
      image="$OPTARG"
      ;;
    d)
      temp="$(tail -1 build_config)"
      echo "$OPTARG" > build_config
      echo "$temp" >> build_config
      ;;
    r)
      temp="$(head -1 build_config)"
      echo "$temp" > build_config
      echo "$OPTARG" >> build_config
      ;;
    o)
      output_dir="$OPTARG"
      ;;
    m)
      release=$(git rev-parse HEAD)
      ;;
    b)
      rebuild=1
      ;;
    ?)
      echo "Usage: $0 [-n number_of_requests_per_realm] [-l log_level (0=none, 1,2,3=radiusd -f, -fx, -fxx)] [-b repository_branch_to_build_docker_image] [-s repository_Dockerfile_directory] [-o output_log_dir] [-r freeradius_directory] number_of_realms"
      exit 1
      ;;
  esac
done
shift "$(($OPTIND-1))"

max_container_num=100
num_realms="$1"
# Need the directory name we're running from - docker names our containers based on it (which the proxy needs as hostnames)
compose_dir=${PWD##*/}
compose_dir=${compose_dir:-/}
if [[ "/$num_realms" = "/" ]]; then
  echo "No container num given"
  exit 1
fi
if [ "$num_realms" -gt "$max_container_num" ]; then
  echo "You have tried to create more than $max_container_num docker containers, exiting load testing script without running"
  exit 1
fi
if [[ "/$num_requests" = "/" ]]; then
  num_requests=5000
fi
if [[ "/$log_level" = "/" ]]; then
  log_level=1
fi

if [[ "/$image" != "/" ]]; then
  sed -i "s|:.*###image|: $image ###image|g" docker-compose.yml
else
  image=$(cat docker-compose.yml | grep -m 1 "###image" | awk '{print $2}')
fi

if [ "1$rebuild" -eq 11 ] || ! docker images | grep "$image" > /dev/null; then
  docker image rm "$image"
  # Can't cache, we want the most recent commit
  docker build "$(head -1 build_config)" --build-arg=release="$(tail -1 build_config)" --build-arg=source=https://github.com/FreeRADIUS/freeradius-server.git --no-cache -t "$image"
fi

sed -i "s|-.*###PWD|- $PWD/test:/test ###PWD|g" docker-compose.yml 


### CONFIG ###
# Used to pass values to containers, since they can only see the test/ directory
echo "$compose_dir"  >  "test/config"
echo "$num_requests" >> "test/config"
echo "$log_level"    >> "test/config"

### DOCKER ###
docker compose up -d --scale home="$num_realms" --scale client="$num_realms" &>/dev/null
if ! [ "$?" -eq 0 ]; then
  echo "Docker failed"
  exit 1
fi

# Check for when all of the client containers have exited
while docker compose ps | grep client > /dev/null; do
  sleep 3
done

docker compose stop &>/dev/null
rm -f test/containers/proxy-running

# Move all the output to an external directory if specified
if [[ "/$output_dir" != "/" ]]; then
  mv test/containers/* "$output_dir"
fi

# Check that the number of clients that were created is the same as the number of clients that were created and exited successfully
if [ $(docker compose ps --all | grep -c client) -eq $(docker compose ps --all | grep -c "client.*Exited (0)") ]; then
  echo "TLS load test succeeded"
  yes | docker compose rm &> /dev/null
  exit 0
else
  echo "TLS load test failed"
  yes | docker compose rm &> /dev/null
  exit 1
fi
