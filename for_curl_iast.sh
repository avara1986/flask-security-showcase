#!/bin/bash
set -xe                  # enable brace expansion
while :
do
    curl -s -k GET http://127.0.0.1:8000/source_header/vuln_path_traversal --header 'pt-file: /home/alberto.vara/projects/dd-python/dd-trace-py/tests/appsec/iast/fixtures/path_traversal_test_file.txt'
    sleep 0.2s
    curl -s -k GET http://127.0.0.1:8000/source_queryparam/vuln_path_traversal?pt_file=/home/alberto.vara/projects/dd-python/dd-trace-py/tests/appsec/iast/fixtures/path_traversal_test_file.txt
    sleep 0.2s
    curl -s -k GET http://127.0.0.1:8000/source_header/vuln_sqli --header 'password: admin1234'
    sleep 0.2s
    curl -s -k GET http://127.0.0.1:8000/source_queryparam/vuln_sqli?table=students
    sleep 0.1s
    curl -s -k -X POST http://127.0.0.1:8000/source_body/vuln_sqli -d "password=test1234"
    sleep 0.1s
    curl -s -k -X POST http://127.0.0.1:8000/source_body/vuln_cmdi -d "cmd=ls"
    sleep 0.2s
    curl -s -k GET http://127.0.0.1:8000/source_pathparam/vuln_sqli/admin1234
    sleep 0.2s
    curl -s -k GET http://127.0.0.1:8000/source_pathparam/vuln_cmdi/path_traversal_test_file.txt
    sleep 0.2s
    curl -s -k GET http://127.0.0.1:8000/source_queryparam/vuln_cmdi?filename=path_traversal_test_file.txt
    sleep 0.1s
    curl -s -k GET http://127.0.0.1:8000/weak_randomness
    sleep 0.1s
    curl -s -k GET http://127.0.0.1:8000/insecure_cookie
    sleep 0.1s
    curl -s -k GET http://127.0.0.1:8000/empty_cookie
    sleep 0.1s
    curl -s -k GET http://127.0.0.1:8000/no_httponly_cookie
    sleep 0.1s
    curl -s -k GET http://127.0.0.1:8000/no_samesite_cookie

    curl -s -k POST "http://127.0.0.1:8000/iast/propagation" -d "string1=Hi&password=root1234"

done
wait
