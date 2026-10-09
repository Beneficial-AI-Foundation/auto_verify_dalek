#!/usr/bin/env bash
# Kept for the double_dynamic_01 checkpoint: `bash harness/run_double_dynamic.sh --resume`.
# New runs: bash harness/run_dynamic.sh double  (see that script for options).
cd "$(dirname "$0")/.."
RUN=double_dynamic_01 exec bash harness/run_dynamic.sh double "$@"
