#!/usr/bin/env bash

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export VSIM_HOME="$ROOT_DIR/vSim"
export PYTHONPATH="$VSIM_HOME"
export PATH="$ROOT_DIR/.vsim310-venv/bin:$PATH"
export MPLCONFIGDIR="${MPLCONFIGDIR:-/tmp/vsim-mpl}"
