#!/bin/bash
#
#  Print the CPU time and memory use of the Docker VM and of every running
#  container, once per second.
#
#  Each output row is:
#
#    <epoch seconds>,<id>,<CPU time in microseconds>,<memory in bytes>
#
#  <id> is "vm" for the Docker VM, and the container ID for a container.
#  Because the CPU time is a running total, the CPU use over an interval is
#  the difference between two rows.
#
#  Because the script reads the cgroup v2 files of every container, run the
#  script in the cgroup namespace of the host:
#
#    docker run --cgroupns=host ... sample_resource_usage.sh
#
#  measure_gperftools_capture_rate.sh runs the script during each test.
#

TCK=$(getconf CLK_TCK)

#
#  Each second, vmstat prints one line, and the loop then takes one sample.
#  The loop body uses shell builtins only, because a process started for
#  each sample would add load to the Docker VM.
#
vmstat -n 1 | while read -r first _; do
	[[ $first == [0-9]* ]] || continue
	now=$EPOCHREALTIME

	read -r _ user nice system _ _ irq softirq steal _ < /proc/stat
	while read -r key value _; do
		case $key in
		MemTotal:) total=$value ;;
		MemAvailable:) available=$value; break ;;
		esac
	done < /proc/meminfo
	echo "$now,vm,$(( (user + nice + system + irq + softirq + steal) * 1000000 / TCK )),$(( (total - available) * 1024 ))"

	for dir in /sys/fs/cgroup/docker/*/; do
		id=${dir%/}
		id=${id##*/}
		[ ${#id} -eq 64 ] || continue
		{ read -r _ usec < "$dir/cpu.stat" && read -r memory < "$dir/memory.current"; } 2>/dev/null || continue
		echo "$now,$id,$usec,$memory"
	done
done
