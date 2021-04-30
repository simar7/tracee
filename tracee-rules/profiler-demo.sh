#!/bin/sh


echo ">>> good build (no cryptominer)"
sleep 2
set -x
timeout 2 ./dist/tracee-rules \
       	--input-tracee file:./good-build.json \
	--input-tracee format:json \
	--tracee-profile file:./profile.json \
	--tracee-profile format:json
set +x
echo "no unusual event detected"

sleep 2

echo ">>> bad build (with cryptominer)"
sleep 2
set -x
timeout 2 ./dist/tracee-rules \
	--input-tracee file:./bad-build.json \
	--input-tracee format:json \
	--tracee-profile file:./profile.json \
	--tracee-profile format:json
set +x
