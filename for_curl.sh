#!/bin/bash
set -xe                  # enable brace expansion
while :
do
    # curl --location -s -k 'GET' http://127.0.0.1:8000/.git/config  --header "X-Forwarded-For: 123.45.67.89" -A 'dd-test-scanner-log'
    curl --location -s -k 'GET' http://127.0.0.1:8000/ --header "X-Forwarded-For: 123.45.67.89" -A 'dd-test-scanner-log'
    # BLOCKED
    curl --request GET 'http://127.0.0.1:8000/block' --header "X-Forwarded-For: 123.45.67.89" -A 'dd-test-scanner-log'
    echo "BLOCKED $i"
    sleep 0.2s
#    # NORMAL
#    curl --request GET 'http://127.0.0.1:8000/normal' --header "X-Forwarded-For: 123.45.67.88"
#    echo "NORMAL $i"
#    sleep 0.5s
#    # ATTACK
#    curl --request GET 'http://127.0.0.1:8000/attack' --header "X-Forwarded-For: 123.45.67.87" -A 'dd-test-scanner-log'
#    echo "ATTACK $i"
#    sleep 0.5s
    #curl -s -k 'GET' -H 'header info' -b 'stuff' 'http://example.com/id='$i
done
wait
