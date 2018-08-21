#!/usr/bin/env bash

set -ex

# This script makes sure that the source code is in sync with the various scripts
./scripts/gen_parcel_helper.py
./scripts/format.sh
