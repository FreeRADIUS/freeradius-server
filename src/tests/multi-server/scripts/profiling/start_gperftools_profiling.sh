#!/bin/bash

# Skeleton for the gperftools capture.

rm -f /etc/prof-results/gperftools_profiling.log

exec > /etc/prof-results/gperftools_profiling.log 2>&1

echo "INFO: gperftools profiling has not been performed, capture has not been implemented ($(date))"

exit 0
