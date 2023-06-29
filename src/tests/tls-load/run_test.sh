#!/bin/bash
# Other shells not tested

yes | sudo docker compose rm

### ARGUMENT PARSING ###
# Note -s and -b require the freeradius docker image to be rebuilt, meaning it must be removed, or renamed with -i.
while getopts ':n:l:i:b:s:o:' OPTION; do
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
    s)
      subdir="$OPTARG"
      ;;
    b)
      branch="$OPTARG"
      ;;
    o)
      output_dir="$OPTARG"
      ;;
    ?)
      echo "Usage: $0 [-n number_of_requests_per_realm] [-l log_level (0=none, 1,2,3=radiusd -f, -fx, -fxx)] [-b repository_branch_to_build_docker_image] [-s repository_Dockerfile_directory] [-o output_log_dir] number_of_realms"
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
if [[ "/$num_requests" = "/" ]]; then
  num_requests=1000
fi
if [[ "/$log_level" = "/" ]]; then
  log_level=1
fi
if [[ "/$subdir" != "/" ]]; then
  sed -i "s|#\(.*\):\(.*\) ###build|#\1:$subdir ###build|g" docker-compose.yml
fi
if [[ "/$branch" != "/" ]]; then
  sed -i "s|#\(.*\):\(.*\) ###build|#$branch:\2 ###build|g" docker-compose.yml
fi
if [[ "/$image" != "/" ]]; then
  sed -i "s|:.*###image|: $image ###image|g" docker-compose.yml
fi
if [ "$num_realms" -gt "$max_container_num" ]; then
  echo "You have tried to create more than $max_container_num docker containers, exiting load testing script without running"
  exit 1
fi

sed -i "s|-.*###PWD|- $PWD/test:/test ###PWD|g" docker-compose.yml 


### CONFIG ###
# Used to pass values to containers, since they can only see the test/ directory
echo "$compose_dir"  | sudo tee    "test/config"
echo "$num_requests" | sudo tee -a "test/config"
echo "$log_level"    | sudo tee -a "test/config"

### DOCKER ###
sudo docker compose up -d --scale home="$num_realms" --scale client="$num_realms"

# Check for when all of the client containers have exited
while sudo docker compose ps | grep client; do
  sleep 3
done
sudo docker compose stop
sudo rm test/containers/proxy-running

# Move all the output to an external directory if specified
if [[ "/$output_dir" != "/" ]]; then
  mv test/containers/* "$output_dir"
fi

# Check that the number of clients that were created is the same as the number of clients that were created and exited successfully
if [ $(sudo docker compose ps --all | grep -c client) -eq $(sudo docker compose ps --all | grep -c "client.*Exited (0)") ]; then
  echo "Test succeeded"
  exit 0
else
  echo "Test failed"
  exit 1
fi


