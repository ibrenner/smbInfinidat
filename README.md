# smbInfinidat
Powershell module for InfiniBox SMB, to retrieve share information and create async replicas for SMB volumes.

## Prerequisites
The script uses powershell 6 and above

## Installation
Please run `$env:PSModulePath` to check which locations are available for modules to be loaded from:
```
PS:> $env:PSModulePath
C:\Users\username\Documents\PowerShell\Modules;C:\Program Files\PowerShell\Modules;c:\program files\powershell\6\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules

```
*Please note that different OSs (windows, Mac...) will display different path locations.*  
\
Its preffered to use the documents path folder under your username. \
If some of the folders in the path does not exist make sure to create them first. \
Now create a folder named smbInfinidat_v2 under the Modules folder. \
Put smbInfinidat_v2.psd1 and smbInfinidat_v2.psm1 in this folder. \
Now you can run ```  Get-Module -ListAvailable ``` and you should be able to see the new module listed and can use `import-module smbInfinidat_v2` to import it 

## Usage
The module has the following commands: \
Get-InfiniboxSmbShares - will retrieve SMB shares metadata information \
New-InfiniboxSmbReplica - will create an Async replica to another InfiniBox for a SMB volume \
New-InfiniboxSmbShare - will create a SMB share \
Remove-InfiniboxSmbShare - will delete a SMB share 

## Example 
The following will retrieve all share information related to test fileserver 
```
 Get-smbShares -src_system ibox2411 -src_username admin -fileserver test
  ```

The following will create an Async replica for filesystem named test1 with rpo set to 2 minutes and sync interval at 1 minute 
```
New-smbReplica -src_system ibox24 -src_username admin -tgt_system ibox14 -tgt_username iscsi -tgt_pool pool1 -fileserver testfs -fs test1 -rpo 120 -sync_interval 60 -new_tgt_name tstrepvo
```
