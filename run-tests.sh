#!/bin/bash
#
#

c3c compile-test --libdir .. --lib mftah $(find ./test/ -type f -name '*.c3t')
TEST_RESULT=$?
[[ -e testrun ]] && \rm testrun

[[ $TEST_RESULT -ne 0 ]] && exit 1


for integration in `find ./test/ -type f -name '*.c3'`; do
    echo -e "\n\n=============================================================\nExecuting integration test '${integration}'..."

    c3c compile-run --libdir .. --lib mftah "${integration}"

    artifact="$(basename "${integration}" | sed -r 's/\.c3$//')_test"
    [[ -e "${artifact}" ]] && \rm "${artifact}" 
done

