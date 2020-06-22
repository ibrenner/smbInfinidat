$ErrorActionPreference = "Stop"

 function Get-Vol{
    param(
        $ibox,
        $fileserver,
        $fs,
        $hd
    )
    $fs1 = irm -Uri "https://$($ibox)/api/plugins/smb/filesystem?fileserver_name=$($fileserver)&name=$($fs)" -Method Get  -Headers $hd -SkipCertificateCheck
    return $fs1
}

function Get-iboxver{
    param(
        $ibox,
        $hd
    )
    $iboxver = irm -Uri "https://$($ibox)/api/rest/system" -Method Get  -Headers $hd -SkipCertificateCheck
    if([System.Version]$iboxver.result.version -lt [System.Version]"4.0.40"){
        [Console]::ForegroundColor = 'red'
        [Console]::Error.WriteLine("Error: InfiniBox $($ibox) doesn't support SMB")
        [Console]::ResetColor()
        break 
    }
}

function New-Replica{
        param(
            $srcibox,
            $srcvol, 
            $dstibox,
            $dstpool,
            $rpo,
            $interval,
            $newname,
            $hdrs
            )
        $link = irm -Method Get -Uri "https://$($srcibox)/api/rest/links?remote_system_name=eq:$($dstibox)" -Headers $hdrs -SkipCertificateCheck 
        $rempool = irm -Method Get -Uri "https://$($srcibox)/api/rest/remote/$($link.result.id)/api/rest/pools?name=eq:$($dstpool)" -Headers $hdrs -SkipCertificateCheck 
        if(!$newname){
            $rand = get-random -Minimum 1000 -Maximum 99999
            $newname = "$($srcvol.result.name)_$($rand)"
        }
        if($rempool.result){
            $json = @{
                "sync_interval" = $interval
                "entity_type" = "VOLUME"
                "replication_type" = "ASYNC"
                "link_id" = $link.result.id
                "rpo_type"= "TIME"
                "rpo_value" = $rpo
                "remote_pool_id" = $rempool.result.id
                "entity_pairs" = @(
                    @{
                    "local_entity_id" =  $($srcvol.result.volume_id)
                    "remote_base_action" = "CREATE"
                    "remote_entity_name" = $newname
                    "local_base_action" = "NO_BASE_DATA"
                    }
                )
            }
            $json_payload = $json | ConvertTo-Json
            $replica = iwr -Method Post -Uri "https://$($srcibox)/api/rest/replicas" -Headers $hdrs -Body $json_payload -SkipCertificateCheck
            return $replica
            }
        else{
                Write-Host "Error: Pool Not Found" -ForegroundColor Red 
                break
        }}

function CheckPSVer{
    $powershell_version = $PSVersionTable.PSVersion.Major
    if ($powershell_version -ge 6){
	    Write-Host "Found Powershell version $($powershell_version)"
    } else {
	    Write-Host  "This script requires PowerShell version 6 or above" -ForegroundColor Red 
	    Write-Host "Installed version: $($powershell_version)" -ForegroundColor Red 
	    Exit 1
        }
    }

function EncodeCreds{
    param(
        [ValidateNotNull()]
        [parameter(Mandatory)]
        $user,
        $password,
        $ibox
    )
    if(!$password){ 
        $p = Read-Host "Enter password for $($user)@$($ibox)" -AsSecureString
        $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p))
    }
    $userpass  = [System.Text.Encoding]::UTF8.GetBytes("$($user):$($password)")
    $enc = [System.Convert]::ToBase64String($userpass)
    return $enc
}

# creating the headers
function New-Headers{
    param(
        $src_enccreds,
        $tgt_enccreds
    )
    $h1 = "Basic $($src_enccreds)"
    $h2 = "Basic $($tgt_enccreds)"
    $hd = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $hd.Add("Authorization", $h1)
    $hd.Add("X-Remote-Authorization", $h2)
    $hd.Add("Accept","application/json")
    $hd.Add("Content-Type","application/json")
    return $hd
}

function ConvertTime{
    param(
    $time
    )
    return ($time*1000)
}

function Get-ShareMeta{
   param(
   $ibox,
   $hd,
   $fileserver,
   $filesystem
   )
   $cl = irm -Uri "https://$($ibox)/api/plugins/smb/cluster" -Method Get -SkipCertificateCheck -Headers $hd
   $shr1 = irm -Uri "https://$($ibox)/api/plugins/smb/share?page_size=800" -Method Get -SkipCertificateCheck -Headers $hd
   foreach($share in $shr1.result){
    foreach($cls in $cl.result){
         if ($share.cluster_uuid -eq $cls.cluster_uuid) {
                 $share | Add-Member -MemberType NoteProperty -name "fileserver_name" -Value $cls.fileserver_name -Force
                 }
               }}

   if($fileserver -and $filesystem){
       return ($shr1.result |  ?{$_.fileserver_name -eq $fileserver -and $_.filesystem_name -eq $filesystem })
    }
    elseif($filesystem){
        return ($shr1.result |  ?{$_.filesystem_name -eq $filesystem})
    }
    elseif($fileserver){
        return ($shr1.result | ?{$_.fileserver_name -eq $fileserver})
   }
   else{
        return $shr1.result
   }
 }


 <#
    .SYNOPSIS
    The New-InfiniboxSmbReplica function creates an Async replica for SMB volume.
    .DESCRIPTION
    Creates Async replication for SMB volume. 
    .INPUTS
    source and destination properties (ibox and credentials), fileserver, filesystem, RPO, sync interval and new target name.
    .OUTPUTS
    Success or Failure of the operation.
    .NOTES
    Version:        1.0
    Author:         Idan Brenner
    Creation Date:  06/10/2019
    Purpose/Change: Updated for new connection mgmt
    *******Disclaimer:******************************************************
    This script is offered "as is" with no warranty. 
    While it has been tested and working in my environment, it is recommended that you first test 
    it in a lab environment before using in a production environment. 
    ************************************************************************
  #>
function New-InfiniboxSmbReplica{
    Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$src_system,

    [Parameter(Mandatory=$True,Position=2)]
    [string]$src_username,

    [Parameter(Mandatory=$False,Position=3)]
    [string]$src_password,

    [Parameter(Mandatory=$True,Position=4)]
    [string]$tgt_system,

    [Parameter(Mandatory=$True,Position=5)]
    [string]$tgt_username,

    [Parameter(Mandatory=$False,Position=6)]
    [string]$tgt_password,

    [Parameter(Mandatory=$True,Position=7)]
    [string]$tgt_pool,

    [Parameter(Mandatory=$True,Position=8)]
    [string]$fileserver,

    [Parameter(Mandatory=$True,Position=9)]
    [string]$filesystem,

    #Sets RPO in seconds format
    [Parameter(Mandatory=$True,Position=10)]
    [int]$rpo,

    #Sets sync interval in seconds format
    [Parameter(Mandatory=$True,Position=11)]
    [int]$sync_interval,

    [Parameter(Mandatory=$False,Position=12)]
    [string]$new_tgt_name

       )

      
CheckPSVer
$screds = EncodeCreds -User $src_username -Password $src_password -ibox $src_system
$dcreds = EncodeCreds -User $tgt_username -Password $tgt_password -ibox $tgt_system
$headers = New-Headers $screds $dcreds
$rposec = ConvertTime -time $rpo
$intervalsec = ConvertTime -time $sync_interval
Get-iboxver -ibox $src_system -hd $headers


$smbtst = irm -Uri "https://$($src_system)/api/rest/tenants?name=SMB" -Headers $headers -SkipCertificateCheck
if($smbtst.result){
    $vol = Get-Vol -ibox $src_system -fileserver $fileserver -fs $filesystem -hd $headers
    if($vol.result){
        try{
        $replica = New-Replica -srcibox $src_system -srcvol $vol -dstibox $tgt_system -dstpool $tgt_pool -rpo $rposec -interval $intervalsec -newname $new_tgt_name -hdrs $headers
        if($replica.StatusCode -eq 201){
            Write-Host "Replica for filesystem $($filesystem) created" -ForegroundColor Green
            }
        }
        catch{
            $err = ($_ | ConvertFrom-Json)
            [Console]::ForegroundColor = 'red'
            [Console]::Error.WriteLine($err.error)
            [Console]::ResetColor()
            break
            }
         }
    else{ 
        Write-Host "Wrong Fileserver or Filesystem" -ForegroundColor Red
        break
        }}
    else{
        Write-Host "SMB Not configured on $($src_system)" -ForegroundColor Red
    }
    }


<#
    .SYNOPSIS
    Getting Share metadata information.
    .DESCRIPTION
    The Get-smbShares function gets the smb shares metadata information from InfiniBox.
    .INPUTS
    source properties (ibox and credentials), fileserver, filesystem and output type.
    .OUTPUTS
    Share metadata information.
    .NOTES
    Version:        1.0
    Author:         Idan Brenner
    Creation Date:  06/10/2019
    *******Disclaimer:******************************************************
    This script is offered "as is" with no warranty.
    While it has been tested and working in my environment, it is recommended that you first test 
    it in a lab environment before using in a production environment. 
    ************************************************************************
#>
function Get-InfiniboxSmbShares{
 Param(
    
    [Parameter(Mandatory=$True,Position=1)]
    [string]$src_system,

    [Parameter(Mandatory=$True,Position=2)]
    [string]$src_username,

    [Parameter(Mandatory=$False,Position=3)]
    [string]$src_password,

    [Parameter(Mandatory=$False,Position=4)]
    [string]$fileserver,
    
    [Parameter(Mandatory=$False,Position=5)]
    [string]$filesystem,

    [Parameter(Mandatory=$False,Position=6)]
    [string]$outputfile,

    [Parameter(Mandatory=$False,Position=7)]
    [switch]$csv
       
       )
 
CheckPSVer
$screds = EncodeCreds -User $src_username -Password $src_password -ibox $src_system
$headers = New-Headers $screds $dcreds
Get-iboxver -ibox $src_system -hd $headers

$smbtst = irm -Uri "https://$($src_system)/api/rest/tenants?name=SMB" -Headers $headers -SkipCertificateCheck
if($smbtst.result){
    $shr = Get-ShareMeta -ibox $src_system -hd $headers -fileserver $fileserver -filesystem $filesystem
    if($shr){
        if($csv -and $outputfile){
            Write-Host "inside"
             $shr | ConvertTo-Csv| Out-File -FilePath $outputfile     
             }
        elseif($outputfile){
            $shr | Out-File -FilePath $outputfile    
            }
        elseif($csv){
             $shr | ConvertTo-Csv
             }
        else{
            $shr
        }
    }
    else{
        Write-Host "Wrong Fileserver or Filesystem" -ForegroundColor Red
        break
        }
    }
else{
    Write-Host "SMB Not configured on $($src_system)" -ForegroundColor Red
    }
}
    