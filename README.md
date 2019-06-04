# smbInfinidat
Powershell module for InfiniBox SMB, to retrieve share information and create async replicas for SMB volumes.

## Prerequisites
the script uses powershell 6 and above

## Installation
please run the following to check which locations are available for modules to be loaded from:
```PS:> $env:PSModulePath
C:\Users\username\Documents\PowerShell\Modules;C:\Program Files\PowerShell\Modules;c:\program files\powershell\6\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules

```
its preffered to use the documents path folder under your username. \
If some of the folders in the path does not exist make sure to create them first. \
Now create a folder named smbInfinidat under the Modules folder. \
Put smbInfinidat.psd1 and smbInfinidat.psm1 in this folder. \
now you can run ```  Get-Module -ListAvailable ``` \
and you should be able to see the new module listed and can use `import-module smbInfinidat` to import it \

## Usage
The module has 2 commands: \
Get-smbShares - will retrieve SMB shares metadata information \
New-smbReplica - will create an Async replica to another InfiniBox for a SMB volume 

