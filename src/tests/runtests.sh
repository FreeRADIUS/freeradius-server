#!/bin/bash

PORT=12340
HOME_PORT=12350

# Sends a signal which checks if the process is active (doesn't kill anything)
function pidactive () {
    kill -0 $1 2> /dev/null
    return
}

# Kill a particular process
function pidkill () {
    kill $1 || return
    #adjust depending how long it takes to die gracefully
    sleep 1    
    if pidactive $1; then
        #escalating
        kill -9 $1
    fi  
}

# Starts the server
function start_radiusd () {
    ../main/radiusd -Xmd ./raddb/ -i 127.0.0.1 -p $PORT > radiusd.log 2>&1 &
    PID=$!
#wait for the process to startup or die...
    sleep 3
    if ! pidactive $PID; then
	wait $PID
	tail -5 radiusd.log
	echo "Command failed with $?"
        exit 1
    fi
}

rm -f verbose.log
RCODE=0

rm -rf .cache
mkdir .cache

#
#  Bootstrap the tests
#
for NAME in $@
do
  TOTAL=`grep TESTS $NAME | sed 's/.*TESTS//'`

  #
  #  Each test may have multiple variants.
  #
  for NUMBER in `echo $TOTAL`
  do
    cp $NAME .request

    #
    #  Add the name of the test, and the variant to the request
    #
    echo "Test-Name = \"$NAME\"," >> .request
    echo 'Test-Number = ' $NUMBER >> .request

    mv .request .cache/$NAME:$NUMBER
  done
done

#
#  Now run the tests
#
echo "Starting radiusd..."
cp users raddb/
start_radiusd
echo "Running tests..."


(cd .cache;ls -1  > ../.foo)
rm -f .bar
for x in `cat .foo`
do
   echo "-f .cache/$x" >> .bar
done

../main/radclient `cat .bar` -xFd ./raddb 127.0.0.1:$PORT auth testing123 > radclient.log 2>&1

for x in `cat .foo`
do
  RESULT=`egrep ^\\.cache/$x radclient.log | sed 's/.* //'`
  if [ "$RESULT" = "2" ]; then
      echo "$x : Success"
    else
      echo "$x : FAILED"
      RCODE=1
  fi
done


pidkill $PID

if [ "$RCODE" = "0" ]
then
    rm -f radiusd.log radclient.log 
    echo "All tests succeeded"
else
    echo "See radclient.log for more details"
fi

exit $RCODE
