#!/bin/bash
# Other shells not tested
# Arguments in caps are exported to containers or relevant in docker-compose.yml

export IMAGE=${IMAGE:-freeradius-tls-test}
yes | docker compose rm
if ! [ "$?" -eq 0 ]; then
  echo "Docker failed"
  exit 1
fi

### ARGUMENT PARSING ###
# Note -s and -b require the freeradius docker image to be rebuilt, meaning it must be removed, or renamed with -i.
while getopts ':n:l:d:r:o:bm' OPTION; do
  case "$OPTION" in
    n)
      NUM_REQUESTS="$OPTARG"
      ;;
    l)
      LOG_LEVEL="$OPTARG"
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
    	# As per the docker script, release must be a branch and not a commit.
      release=$(git rev-parse --abbrev-ref HEAD)
      ;;
    b)
      rebuild=1
      ;;
    ?)
      echo "Usage: $0 [-n number_of_requests_per_realm] [-l log_level (0=none, 1,2,3=radiusd -f, -fx, -fxx)] [-d Dockerfile_directory_to_build] [-r Github_branch_to_build] [-b (to force building image)] [-s repository_Dockerfile_directory] [-o output_log_dir] [-r freeradius_directory] number_of_realms"
      exit 1
      ;;
  esac
done
shift "$(($OPTIND-1))"

max_container_num=100
num_realms="$1"
if [[ "/$num_realms" = "/" ]]; then
  echo "No container num given"
  exit 1
fi
if [ "$num_realms" -gt "$max_container_num" ]; then
  echo "You have tried to create more than $max_container_num docker containers, exiting load testing script without running"
  exit 1
fi
export NUM_REQUESTS=${NUM_REQUESTS:-5000}
export LOG_LEVEL=${LOG_LEVEL:-1}

if [ "1$rebuild" -eq 11 ] || ! docker images | grep "$IMAGE" > /dev/null; then
  docker image rm "$IMAGE" &>/dev/null
  # Can't cache, we always want to update to the most recent commit
  docker build "$(head -1 build_config)" --build-arg=release="$(tail -1 build_config)" --build-arg=source=https://github.com/FreeRADIUS/freeradius-server.git --no-cache -t "$IMAGE"
fi

### DOCKER ###
docker compose up -d --scale home="$num_realms" --scale client="$num_realms"
if ! [ "$?" -eq 0 ]; then
  echo "Docker failed"
  exit 1
fi

# Check for when all of the client containers have exited
while docker compose ps | grep client; do
  sleep 3
done

docker compose stop

# Move all the output to an external directory if specified
if [[ "/$output_dir" != "/" ]]; then
  docker logs test-container-proxy-1 > "$output_dir"/proxy.log
  i=1
  while [ "$i" -le $num_realms ]; do
    docker logs test-container-client-"$i" > "$output_dir"/client_"$i".log&
    docker logs test-container-home-"$i" > "$output_dir"/home_"$i".log&
    i=$((i+1))
  done
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
