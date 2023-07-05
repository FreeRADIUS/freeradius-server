# TLS Load Testing

Runs local radiusd load testing for TLS using docker compose.  
Requires Docker.  
### Usage:  
`bash run_test.sh -f base_freeradius_dir (number of concurrent clients/servers running)`  
### Options:  
- `-n`: number of messages to send per client (default is 1000)
- `-l`: log level for home/proxy servers (default is 1, 1=`radiusd -f`, 2=`radiusd -fx`, 3=`radiusd -fxx`, other=no log files generated)
- `-o`: where to put log files after running (if left empty, output will not be generated)
- `-i`: name of generated docker image (only needed if you have generated your own docker image to run, rather than the one from the repository)
- `-d`: folder path to the Dockerfile to build
- `-r`: the Github branch to build from
- `-m`: build from the most recent Github branch (HEAD) (overrides -r)
- `-b`: force rebuilding the docker image, even if it already exists
- Setting `IMAGE=` can be used to change the image used
 
### Output:  
- `client_*.log`: Output of radclient for each running client
- `home_*.log`: Output from radiusd of home servers
- `proxy.log`: Output from radiusd of proxy server

### Result:
The script will exit 0 if all clients succeed or 1 if any client fails, and will print a corresponding message.  
