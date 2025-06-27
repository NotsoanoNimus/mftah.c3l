#!/bin/bash
#
#

if [[ -z "$1" ]] || [[ -n "$1" && "$1" == "unit" ]]; then
    c3c compile-test -O3 --libdir .. --lib mftah $(find ./test/ -type f -name '*.c3t')
    TEST_RESULT=$?
    [[ -e testrun ]] && \rm testrun

    [[ $TEST_RESULT -ne 0 ]] && exit 1
fi

if [[ -z "$1" ]] || [[ -n "$1" && "$1" == "int" ]]; then
    for integration in `find ./test/ -type f -name '*.c3'`; do
        echo -e "\n\n=============================================================\nExecuting integration test '${integration}'..."
    
        c3c compile-run -O3 --libdir .. --lib mftah "${integration}"
    
        artifact="$(basename "${integration}" | sed -r 's/\.c3$//')_test"
        [[ -e "${artifact}" ]] && \rm "${artifact}" 
    done
fi
