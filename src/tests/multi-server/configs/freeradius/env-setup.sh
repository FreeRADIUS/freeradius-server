apt-get update
apt-get install -y iputils-ping iproute2 ipcalc
IP_CIDR=$(ip -o -f inet addr show eth0 | awk '{print $4}')
TEST_SUBNET=$(ipcalc -n "$IP_CIDR" | grep Network | awk '{print $2}')
export TEST_SUBNET
echo "TEST_SUBNET=$TEST_SUBNET" >> /etc/environment
echo "Detected TEST_SUBNET: $TEST_SUBNET"
