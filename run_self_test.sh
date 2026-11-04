#!/usr/bin/env bash
set -e
python3 "$(dirname "$0")/sqlite_salvager.py" --self-test
