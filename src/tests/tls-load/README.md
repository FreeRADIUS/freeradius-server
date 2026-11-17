# TLS Load Testing

Runs local radiusd load testing for TLS using docker compose.  
Requires Docker.  
### Usage:  
`./run_test.sh -o output (number of concurrent clients/servers running)`  
### Options:  
- `-n`: number of messages to send per client (default is 1000)
- `-l`: log level for home/proxy servers (default is 1, 1=`radiusd -f`, 2=`radiusd -fx`, 3=`radiusd -fxx`, other=no log files generated)
- `-o`: where to put log files after running (if left empty, output will not be generated)
 
### Output:  
- `client_*.log`: Output of radclient for each running client
- `home_*.log`: Output from radiusd of home servers
- `proxy.log`: Output from radiusd of proxy server

### Result:
The script will exit 0 if all clients succeed or 1 if any client fails, and will print a corresponding message.  
