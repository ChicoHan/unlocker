@echo off

:: SPDX-FileCopyrightText: © 2014-2021 David Parsons
:: SPDX-License-Identifier: MIT

setlocal ENABLEEXTENSIONS
echo.
echo EFI Unlocker 1.0.2 for VMware
echo =============================
echo (c) David Parsons 2018-2021

echo.
set KeyName="HKLM\SOFTWARE\Wow6432Node\VMware, Inc.\VMware Player"
for /F "tokens=2*" %%A in ('REG QUERY %KeyName% /v InstallPath') do set InstallPath=%%B
echo VMware is installed at: %InstallPath%
for /F "tokens=2*" %%A in ('REG QUERY %KeyName% /v ProductVersion') do set ProductVersion=%%B
echo VMware product version: %ProductVersion%

for /F "tokens=1,2,3,4 delims=." %%a in ("%ProductVersion%") do (
   set Major=%%a
   set Minor=%%b
   set Revision=%%c
   set Build=%%d
)

:: echo Major: %Major%, Minor: %Minor%, Revision: %Revision%, Build: %Build%

:: Check version is 12+
if %Major% lss 12 (
    echo VMware Workstation/Player version 12 or greater required!
    exit /b
)

pushd %~dp0

:: If version is 12 extract the firmware from vmware-vmx
if %Major% eq 12 (
    "%InstallPath%x64\vmware-vmx.exe -e EFI32 > EFI32.ROM"
    "%InstallPath%x64\vmware-vmx.exe -e EFi64 > EFI64.ROM"
)
else (
    xcopy /F /Y "%InstallPath%x64\EFI32.ROM" .
    xcopy /F /Y "%InstallPath%x64\EFI64.ROM" .
)

echo.
echo Patching 32-bit ROM...
./uefipatch/UEFIPatch.exe EFI32.ROM ./uefipatch/efi-patches.txt -o EFI32-MACOS.ROM
del /f EFI32.ROM

echo.
echo Patching 64-bit ROM...
./uefipatch/UEFIPatch.exe EFI64.ROM ./uefipatch/efi-patches.txt -o EFI64-MACOS.ROM
del /f EFI64.ROM

popd
echo.
echo Finished
pause
