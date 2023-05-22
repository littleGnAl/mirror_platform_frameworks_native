#!/bin/bash
color_success=$'\E'"[0;32m"
color_failed=$'\E'"[0;31m"

if [ -z "$ANDROID_BUILD_TOP" ]; then
    echo "Missing ANDROID_BUILD_TOP env variable. Run 'lunch' first."
    return
fi

echo "INFO: Building fuzzer : test_service_fuzzer_should_crash"
FUZZER_NAME=test_service_fuzzer_should_crash
make ${FUZZER_NAME}

FUZZER_OUT=/tmp/fuzzer-output
echo "INFO: Running fuzzer : test_service_fuzzer_should_crash"
${ANDROID_HOST_OUT}/fuzz/$(get_build_var HOST_ARCH)/${FUZZER_NAME}/${FUZZER_NAME} -max_total_time=30 &>${FUZZER_OUT}

if grep -q "Expected crash in set" ${FUZZER_OUT};
then
  echo -e "${color_success}Success: Found expected crash. fuzzService test successful!"
else
  echo -e "${color_failed}Failed: Unable to find successful fuzzing output from test_service_fuzzer_should_crash"
fi

rm ${FUZZER_OUT}
