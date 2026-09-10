# common_profiling.sh

# log_status() writes STATUS to <profiling_tool>-exit-status
# Status codes documented in the respective profiling tool scripts.
log_status() {
    echo "$STATUS" > "$RESULTS/${PROFILING_TOOL}-exit-status"
    echo "INFO: profiling finished at $(date) with status $STATUS"
    exit "$STATUS"
}

shutdown_freeradius() {
    # Graceful shutdown of freeradius process (equivalent to Ctrl+C)
    echo "INFO: sending SIGINT to freeradius ${FR_PID} for graceful shutdown"
    kill -SIGINT "$FR_PID"

    SHUTDOWN_TIMEOUT=60
    SHUTDOWN_ELAPSED=0
    while kill -0 "$FR_PID" 2>/dev/null; do
    sleep 1
    SHUTDOWN_ELAPSED=$(( SHUTDOWN_ELAPSED + 1 ))
    if [ "$SHUTDOWN_ELAPSED" -ge "$SHUTDOWN_TIMEOUT" ]; then
        echo "WARNING: sending SIGKILL, freeradius did not exit within ${SHUTDOWN_TIMEOUT}s after SIGINT"
        kill -SIGKILL "$FR_PID" 2>/dev/null
        break
    fi
    done

    FR_STATUS=0
    wait "$FR_PID" 2>/dev/null || FR_STATUS=$?
    echo "INFO: freeradius exited with status ${FR_STATUS} after ${SHUTDOWN_ELAPSED}s"
}
