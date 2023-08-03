#!/bin/bash
set -xe                  # enable brace expansion
while :
do
    # curl --location -s -k 'GET' http://127.0.0.1:8000/.git/config  --header "X-Forwarded-For: 123.45.67.89" -A 'dd-test-scanner-log'
    curl --location -s -k 'GET' http://127.0.0.1:8000/ --header "X-Forwarded-For: 123.45.67.89"
    sleep 0.5s
done
wait
