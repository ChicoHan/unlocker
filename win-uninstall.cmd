@echo off

:: SPDX-FileCopyrightText: © 2014-2021 David Parsons
:: SPDX-License-Identifier: MIT

setlocal ENABLEEXTENSIONS
echo.
echo Unlocker 4.0.0 for VMware Workstation
echo =====================================
echo (c) David Parsons 2011-21

net session >NUL 2>&1
if %errorlevel% neq 0 (
    echo Administrator privileges required! 
    exit
)

echo.
set KeyName="HKLM\SOFTWARE\Wow6432Node\VMware, Inc.\VMware Player"
for /F "tokens=2*" %%A in ('REG QUERY %KeyName% /v InstallPath') do set InstallPath=%%B
echo VMware is installed at: %InstallPath%
for /F "tokens=2*" %%A in ('REG QUERY %KeyName% /v ProductVersion') do set ProductVersion=%%B
echo VMware product version: %ProductVersion%

pushd %~dp0

echo.
echo Stopping VMware services...
net stop vmware-view-usbd > NUL 2>&1
net stop VMwareHostd > NUL 2>&1
net stop VMAuthdService > NUL 2>&1
net stop VMUSBArbService > NUL 2>&1
taskkill /F /IM vmware-tray.exe > NUL 2>&1

echo.
echo Restoring files...
xcopy /F /Y .\backup\x64\*.* "%InstallPath%x64\"
xcopy /F /Y .\backup\*.* "%InstallPath%"

echo.
echo Starting VMware services...
net start VMUSBArbService > NUL 2>&1
net start VMAuthdService > NUL 2>&1
net start VMwareHostd > NUL 2>&1
net start vmware-view-usbd > NUL 2>&1

popd
echo.
echo Finished!
pause
