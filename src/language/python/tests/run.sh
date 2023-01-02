#!/bin/bash

for _f in tests/*.py; do
	echo "CALL $_f"
	$_f
done
