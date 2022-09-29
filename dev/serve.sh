#!/bin/bash -xe
export RUNTIME_DIRECTORY=$(dirname "$0")/../tmp/run
exec systemfd --no-pid -s http::3000 -- cargo watch -- cargo run -- serve "$@"
 
