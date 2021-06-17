# macOS Unlocker V3.0 for VMware Workstation

---
**IMPORTANT**
---
Always uninstall the previous version of the Unlocker before using a new version or 
running an update of the software. Failure to do this could render VMware unusable. 

You use this software at your own risk and there are no guarantees this will work 
in future versions of VMware Workstation.

## 1. Introduction
Unlocker 3 is designed for VMware Workstation 11-16 and Player 7-16.

Version 3 has been tested against:

* Workstation 11/12/14/15/16 on Windows and Linux
* Workstation Player 7/12/14/15/16 on Windows and Linux


It is important to understand that the unlocker does not add any new capabilities to VMware Workstation and Player
but enables support for macOS that is disabled in the VMware products that do not run on Apple Hardware. 
These capabiltiites are normally exposed in Fusion and ESXi when running on Apple hardware. The unlocker cannot add 
support for new versions of macOS, add paravirtualized GPU support or any other features that are not already in the
VMware compiled code.

What the unlocker can do is enable certain flags and data tables that are required to see the macOS type when setting 
the guest OS type, and modify the implmentation of the virtual SMC controller device.
The patch code carries out the following modifications dependent on the product
being patched:

* Fix vmware-vmx and derivatives to allow macOS to boot
* Fix vmwarebase .dll or .so to allow Apple to be selected during VM creation
* Download a copy of the latest VMware Tools for macOS

**Note:** VMware Workstation and Player do not recognise the darwin.iso via install tools menu item.
You will have to manually mount the darwin.iso by selectig the ISO file in the guest's settings.

In all cases make sure VMware is not running, and any background guests have been shutdown.

The code is written in Python with some Bash and Command files.

## 2. Prerequisites
The code requires Python 3.8 to work. Most Linux distros ship with a compatible
Python interpreter and should work without requiring any additional software.

Windows Unlocker has a packaged minimal version of the Python and so does not require Python to be installed.


## 3. Windows
On Windows you will need to either run cmd.exe as Administrator or using
Explorer right click on the command file and select "Run as administrator".

- win-install.cmd   - patches VMware
- win-uninstall.cmd - restores VMware
- win-update-tools.cmd - retrieves latest macOS guest tools

## 4. Linux
On Linux you will need to be either root or use sudo to run the scripts.

You may need to ensure the Linux scripts have execute permissions
by running chmod +x against the 2 files.

- lnx-install.sh   - patches VMware
- lnx-uninstall.sh - restores VMware
- lnx-update-tools.sh - retrieves latest macOS guest tools
   
## 5. Thanks
Thanks to Zenith432 for originally building the C++ unlocker and Mac Son of Knife
(MSoK) for all the testing and support.

Thanks also to Sam B for finding the solution for ESXi 6 and helping me with
debugging expertise. Sam also wrote the code for patching ESXi ELF files and
modified the unlocker code to run on Python 3 in the ESXi 6.5 environment.


## History
27/09/18 3.0.0
- First release

02/10/18 3.0.1
- Fixed gettools.py to work with Python 3 and correctly download darwinPre15.iso

10/10/18 3.0.2 
- Fixed false positives from anti-virus software with Windows executables   
- Allow Python 2 and 3 to run the Python code from Bash scripts

14/05/21 3.0.3
- New simpfiled code for development and deployment
- Removed Python 2 support and requires minmal Python 3.8

01/06/21 3.0.4
- Fixed embedded Python error on Windows

(c) 2011-2021 Dave Parsons
