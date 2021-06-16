#!/usr/bin/env bash
set -e

printf "EFI Unlocker 1.0.2 for VMware Workstation\n"
printf "=========================================\n"
printf "(c) Dave Parsons 2018-21\n\n"

# Ensure we only use unmodified commands
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

version=$(grep -i player.product.version /etc/vmware/config | cut -d'"' -f2- | rev | cut -c 2- | rev)
build=$(grep -i product.buildnumber /etc/vmware/config | cut -d'"' -f2- | rev | cut -c 2- | rev)
IFS='.' read -r -a product <<< "$version"

printf "VMware product version: %s.%s\n\n" "$version" "$build"
#printf "Major:    ${product[0]}\n"
#printf "Minor:    ${product[1]}\n"
#printf "Revision: ${product[2]}\n"
#printf "Build:    ${build}\n"

# Check version is 14+
if [[ ${product[0]} -lt 12 ]]; then
   printf "VMware Workatation/Player version 12 or greater required!\n"
   exit 1
fi

if [[ ${product[0]} -eq 12 ]]; then
    printf "Extracting firmware...\n"
    /usr/lib/bin/vmware-vmx -e EFI32 > EFI32.ROM
    /usr/lib/bin/vmware-vmx -e EFI64 > EFI64.ROM
else
    printf "Copying firmware...\n"
    cp -v /usr/lib/vmware/roms/EFI32.ROM .
    cp -v /usr/lib/vmware/roms/EFI64.ROM .
fi

printf "Patching 32-bit ROM...\n"
./uefipatch/UEFIPatch.linux EFI32.ROM efi-patches.txt -o EFI32-MACOS.ROM
rm -fv EFI32.ROM

printf "\nPatching 64-bit ROM...\n"
./uefipatch/UEFIPatch.linux EFI64.ROM efi-patches.txt -o EFI64-MACOS.ROM
rm -fv EFI64.ROM

printf "\nFinished!\n"
