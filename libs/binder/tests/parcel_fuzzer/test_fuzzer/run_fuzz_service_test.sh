#!/bin/bash
color_success=$'\E'"[0;32m"
color_failed=$'\E'"[0;31m"
color_reset=$'\E'"[00m"

FUZZER_NAME=test_service_fuzzer_should_crash
FUZZER_OUT=fuzzer-output

if [ ! -f "$FUZZER_NAME" ]
then
    echo -e "${color_failed}Binary $FUZZER_NAME does not exist"
    echo "${color_reset}"
    exit 1
fi

echo "INFO: Running fuzzer : test_service_fuzzer_should_crash"

./test_service_fuzzer_should_crash -max_total_time=30 &>${FUZZER_OUT}

echo "INFO: Searching fuzzer output for expected crashes"
if grep -q "Expected crash in set" ${FUZZER_OUT};
then
    echo -e "${color_success}Success: Found expected crash. fuzzService test successful!"
else
    echo -e "${color_failed}Failed: Unable to find successful fuzzing output from test_service_fuzzer_should_crash"
    echo "${color_reset}"
    exit 1
fi
