#!/bin/sh
# Reproduces docs/design.md section 2. Usage: run.sh /path/to/cancho
# Needs python3 (a throwaway listener on 127.0.0.1:9001).
set -u
L=${1:?path to the cancho compiler}
here=$(cd "$(dirname "$0")" && pwd)
out=$(mktemp -d)
for f in unnarrowed narrowed_literal narrowed_argv_host narrowed_prefix two_narrows listen_and_connect listen_under_host_prefix; do
  echo "== authority: $f"; "$L" authority "$here/$f.cho" 2>&1 | sed -n 1,4p
done
for f in narrowed_argv_host narrowed_prefix; do
  "$L" build "$here/$f.cho" -o "$out/$f" >/dev/null 2>&1 || { echo "build failed: $f"; continue; }
  for host in 127.0.0.1 127.0.0.2 10.0.0.1 localhost; do
    python3 -c "
import socket,time
s=socket.socket();s.setsockopt(1,2,1);s.bind(('127.0.0.1',9001));s.listen(5);time.sleep(2)" &
    sleep 0.5
    "$out/$f" "$host" 2>/dev/null; echo "run: $f $host -> exit $?"
    wait
  done
done
for f in listen_and_connect listen_under_host_prefix; do
  "$L" build "$here/$f.cho" -o "$out/$f" >/dev/null 2>&1 || { echo "build failed: $f"; continue; }
  "$out/$f" 2>/dev/null; echo "run: $f -> exit $?"
done
