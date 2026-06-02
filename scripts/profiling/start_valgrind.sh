#!/bin/bash
#
# Run FreeRADIUS under valgrind/callgrind for CPU profiling.
#
# Usage: start_valgrind.sh --fr_src_dir <dir> [--results_dir <name>]
#
#   --fr_src_dir   Root of the FreeRADIUS source tree. Must be the working
#                  directory used when building (i.e. where ./scripts/bin/radiusd
#                  lives). Results are written to <dir>/<results_dir>/.
#   --results_dir  Name of the output directory created under fr_src_dir.
#                  Defaults to "prof-results".
#
# Run this from inside the freeradius4-profiling-deps container with the
# source tree mounted at <dir>.

fr_src_dir=""
results_dir="prof-results"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fr_src_dir)
            fr_src_dir="$2"
            shift 2
            ;;
        --results_dir)
            results_dir="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$fr_src_dir" ]]; then
    echo "Usage: $0 --fr_src_dir <dir> [--results_dir <name>]" >&2
    exit 1
fi

mkdir -p "${fr_src_dir}/${results_dir}"

trap 'echo "Stopping..."; kill "$valgrind_pid" 2>/dev/null; wait "$valgrind_pid" 2>/dev/null; exit 0' INT TERM

valgrind \
  --tool=callgrind \
  --log-file="${fr_src_dir}/${results_dir}/valgrind.log" \
  --callgrind-out-file="${fr_src_dir}/${results_dir}/callgrind.out.%p" \
  --trace-children=yes \
  --separate-threads=no \
  --dump-instr=yes \
  --collect-jumps=yes \
  --cache-sim=yes \
  --branch-sim=yes \
  --keep-debuginfo=yes \
  --instr-atstart=yes \
  ./scripts/bin/radiusd -f -l stdout -S resources.talloc_skip_cleanup=yes \
  > "${fr_src_dir}/${results_dir}/freeradius.log" 2>&1 &
valgrind_pid=$!

wait "$valgrind_pid"

