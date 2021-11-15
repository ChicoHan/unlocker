#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2014-2021 David Parsons
# SPDX-License-Identifier: MIT

set -e

printf "\nEFI Unlocker 1.0.2 for VMware Fusion\n"
printf "======================================\n"
printf "(c) David Parsons 2018-21\n\n"

# Ensure we only use unmodified commands
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

version=$(defaults read /Applications/VMware\ Fusion.app/Contents/Info.plist CFBundleShortVersionString)
build=$(defaults read /Applications/VMware\ Fusion.app/Contents/Info.plist CFBundleVersion)
IFS='.' read -r -a product <<< "$version"

printf "VMware product version: %s.%s\n\n" "$version" "$build"
#printf "Major:    ${product[0]}\n"
#printf "Minor:    ${product[1]}\n"
#printf "Revision: ${product[2]}\n"
#printf "Build:    ${build}\n"

# Check version is 8+
if [[ ${product[0]} -lt 8 ]]; then
   printf "VMware Fusion version 8 or greater required!\n"
   exit 1
fi

if [[ ${product[0]} -eq 8 ]]; then
    printf "Extracting firmware...\n"
    /Applications/VMware\ Fusion.app/Contents/Library/vmware-vmx -e EFI32 > EFI32.ROM
    /Applications/VMware\ Fusion.app/Contents/Library/vmware-vmx -e EFI64 > EFI64.ROM
else
    printf "Copying firmware...\n"
    cp -v /Applications/VMware\ Fusion.app/Contents/Library/roms/EFI32.ROM .
    cp -v /Applications/VMware\ Fusion.app/Contents/Library/roms//EFI64.ROM .
fi

printf "Patching 32-bit ROM...\n"
./uefipatch/UEFIPatch.macos EFI32.ROM ./uefipatch/efi-patches.txt -o EFI32-MACOS.ROM
rm -fv EFI32.ROM

printf "\nPatching 64-bit ROM...\n"
./uefipatch/UEFIPatch.macos EFI64.ROM ./uefipatch/efi-patches.txt -o EFI64-MACOS.ROM
rm -fv EFI64.ROM

printf "\nFinished!\n"
