@echo off
setlocal ENABLEEXTENSIONS
echo Get macOS VMware Tools 3.0.5
echo ===============================
echo (c) Dave Parsons 2011-21


net session >NUL 2>&1
if %errorlevel% neq 0 (
    echo Administrator privileges required!
    exit /b
)

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
.\python-win-embed-amd64\python.exe gettools.py
xcopy /F /Y .\assets\vmtools\darwin*.* "%InstallPath%"
popd
