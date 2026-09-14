# common_profiling.sh

# log_status_and_exit() writes STATUS to <profiling_tool>-exit-status and exits with that status
# Status codes documented in the respective profiling tool scripts.
log_status_and_exit() {
    echo "$STATUS" > "$RESULTS/${PROFILING_TOOL}-exit-status"
    echo "INFO: profiling finished at $(date) with status $STATUS"
    exit "$STATUS"
}

# Shutdown FreeRADIUS process based on PID
shutdown_freeradius() {

    # Function env variables
    SHUTDOWN_TIMEOUT=60
    SHUTDOWN_ELAPSED=0
    FR_STATUS=0

    # Graceful shutdown of freeradius process
    echo "INFO: sending SIGINT to freeradius ${FR_PID} for graceful shutdown"
    kill -SIGINT "$FR_PID"

    while kill -0 "$FR_PID" 2>/dev/null; do
    sleep 1
    SHUTDOWN_ELAPSED=$(( SHUTDOWN_ELAPSED + 1 ))
    if [ "$SHUTDOWN_ELAPSED" -ge "$SHUTDOWN_TIMEOUT" ]; then
        echo "WARNING: sending SIGKILL, freeradius did not exit within ${SHUTDOWN_TIMEOUT}s after SIGINT"
        kill -SIGKILL "$FR_PID" 2>/dev/null
        break
    fi
    done

    # Wait until freeradius process finished
    echo "INFO: waiting for freeradius process ${FR_PID} to exit"
    wait "$FR_PID" 2>/dev/null || FR_STATUS=$?
    echo "INFO: freeradius exited with status ${FR_STATUS} after ${SHUTDOWN_ELAPSED}s"
}
