#!/bin/bash
# SPDX-FileCopyrightText: © 2014-2021 David Parsons
# SPDX-License-Identifier: MIT

set -e

echo "Get macOS VMware Tools 3.0.5"
echo "==============================="
echo "(c) David Parsons 2015-21"

# Ensure we only use unmodified commands
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

# Make sure only root can run our script
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# CD to script folder
cd "$(dirname "${BASH_SOURCE[0]}")"

echo Getting VMware Tools...
./gettools.py
cp ./tools/vmtools/darwin*.* /usr/lib/vmware/isoimages/

# CD to original folder
cd -

echo Finished!
