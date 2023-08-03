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
    sleep 0.2s
    curl -s -k GET http://127.0.0.1:8000/source_pathparam/vuln_sqli/admin1234
    sleep 0.2s
    curl -s -k GET http://127.0.0.1:8000/source_pathparam/vuln_cmdi/path_traversal_test_file.txt
    sleep 0.2s
    curl -s -k GET http://127.0.0.1:8000/source_queryparam/vuln_cmdi?filename=path_traversal_test_file.txt

done
wait
