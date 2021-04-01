#!/bin/sh
#set -x

: ${TYPE=auth}
: ${TEST_NAME=1.basic-auth}
: ${PORT=12340}
: ${SECRET=testing123}

cd $TEST_PATH

BIN_PATH=../../../build/bin/local
OUTPUT=radclient.log

RES=result-$TEST_NAME.log

clean() {
    kill $tailcoa $tailhome $tailproxy 2>&1 > /dev/null
    wait $tailcoa $tailhome $tailproxy 2>&1 > /dev/null # suppress terminated messages
    echo "" > detail_test
    rm ./$TEST_NAME.reply.tmp fr-*-$TEST_NAME.log fail ok $RES radclient.log 2>&1 > /dev/null
}

# Combine a list of several repeated attributes to a single attribute with delimeter:
# This:
#	Acct-Session-Id = "coa-buffered-reader:accounting:coa-request"
#	Acct-Session-Id = "default:send-coa"
# Become:
#	Acct-Session-Id = "coa-buffered-reader:accounting:coa-request"  "default:send-coa"
aggregate() {
    sort -s -t= -k1,1 ./detail_test | awk -F= '
        prev!=$1 && prev{
          print prev FS val;
          prev=val=""}
        {
          val=val?val OFS $2:$2;
          prev=$1
        }
        END{
          if(val){
            print prev FS val}
        }' >> $RES
}

echo "Running test: $TEST_NAME for port: $PORT type: $TYPE"

clean

tail -f fr-coa.log 2> /dev/null > fr-coa-$TEST_NAME.log &
tailcoa=$(echo $!)
tail -f fr-home.log 2> /dev/null > fr-home-$TEST_NAME.log &
tailhome=$(echo $!)
tail -f fr-proxy.log 2> /dev/null > fr-proxy-$TEST_NAME.log &
tailproxy=$(echo $!)

$BIN_PATH/radclient -f $TEST_NAME.request -xF -D ./ 127.0.0.1:$PORT $TYPE $SECRET 1> $OUTPUT

delay=$(grep delay $TEST_NAME.reply | awk '{print $2}')

sed '/delay/d' $TEST_NAME.reply > $TEST_NAME.reply.tmp

sleep $delay 2>&1 > /dev/null

cat radclient.log > $RES
aggregate

while read -r line; do
    if ! grep "$line" $RES >/dev/null 2>&1; then
        echo "This test failed!" >> fail
        echo "Testing $TEST_NAME failed. Cannot find $line in $RES." > fail
    fi
done < $TEST_NAME.reply.tmp

if [ ! -f fail ]; then echo "This test succeded!" >> ok; fi

mkdir $TEST_NAME.result 2>&1 > /dev/null
cp ./$TEST_NAME.reply.tmp fr-*-$TEST_NAME.log fail ok \
    $RES radclient.log detail_test $TEST_NAME.result 2>&1 > /dev/null

clean

test -f $TEST_NAME.result/ok # exit with the status code
