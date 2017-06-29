#!/bin/sh

: ${BIN_PATH=./}
: ${PORT=12340}
: ${HOME_PORT=12350}
: ${SECRET=testing123}

rm -f verbose.log
RCODE=0

echo "Running tests:"
for NAME in $@
do
  TOTAL=`grep TESTS $NAME | sed 's/.*TESTS//'`

  #
  #  Each test may have multiple variants.
  #
  for NUMBER in `echo $TOTAL`
  do
    cp $NAME .request
    BASE=`echo $NAME | sed 's,.*/,,'`

    #
    #  Add the name of the test, and the variant to the request
    #
    echo "Test-Name = \"$BASE\"," >> .request
    echo 'Test-Number = ' $NUMBER >> .request

    rm ./radclient.log > /dev/null 2>&1
    $BIN_PATH/radclient -f .request -xF -D ./ 127.0.0.1:$PORT auth $SECRET 1> ./radclient.log
    if [ "$?" = "0" ]; then
      echo "${BASE}_${NUMBER} : Success"
    else
      echo "${BASE}_${NUMBER} : FAILED"
      cat ./radclient.log
      RCODE=1
    fi
  done
done


if [ "$RCODE" = "0" ]
then
    rm -f radiusd.log radclient.log
    echo "All tests succeeded"
else
    echo "See radclient.log for more details"
fi

exit $RCODE
