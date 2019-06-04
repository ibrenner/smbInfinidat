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
        $password
    )
    if(!$password){ 
        $p = Read-Host "Enter password for $($user)" -AsSecureString
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
   if($fileserver){
     $shr1 = irm -Uri "https://$($ibox)/api/plugins/smb/share?fileserver_name=$($fileserver)" -Method Get -SkipCertificateCheck -Headers $hd
     return $shr1
     }
   elseif($filesystem){
        $shr1 = irm -Uri "https://$($ibox)/api/plugins/smb/share?filesystem_name=$($filesystem)" -Method Get -SkipCertificateCheck -Headers $hd
        return $shr1
   }
   elseif($fileserver -and $filesystem){
       $shr1 = irm -Uri "https://$($ibox)/api/plugins/smb/share?filesystem_name=$($filesystem)&fileserver_name=$($fileserver)" -Method Get -SkipCertificateCheck -Headers $hd
        return $shr1
   }
   else{
        $shr1 = irm -Uri "https://$($ibox)/api/plugins/smb/share" -Method Get -SkipCertificateCheck -Headers $hd
        return $shr1
   }
   
       
   
}


<#
    .Description
    The New-smbReplica function creates an Async replica for SMB volume.
#>
function New-smbReplica{
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
    [string]$fs,

    #Sets RPO in seconds format
    [Parameter(Mandatory=$True,Position=10)]
    [int]$rpo,

    #Sets sync interval in seconds format
    [Parameter(Mandatory=$True,Position=11)]
    [int]$sync_interval,

    [Parameter(Mandatory=$True,Position=12)]
    [string]$new_tgt_name

       )

      
CheckPSVer
$screds = EncodeCreds -User $src_username -Password $src_password
$dcreds = EncodeCreds -User $tgt_username -Password $tgt_password
$headers = New-Headers $screds $dcreds
$rposec = ConvertTime -time $rpo
$intervalsec = ConvertTime -time $sync_interval
try{
    $smbtst = iwr -Uri "https://$($src_system)/api/rest/tenants?name=SMB" -Headers $headers -SkipCertificateCheck
}
catch{
    [Console]::ForegroundColor = 'red'
    $smbvalid_err = ($_ | ConvertFrom-Json)
    if($smbvalid_err.error.code -eq "UNKNOWN_PATH"){
    [Console]::Error.WriteLine("Error: SMB Not Found")
    [Console]::ResetColor()
        break
    } else{
    [Console]::Error.WriteLine($smbvalid_err.error.message)
    [Console]::ResetColor()
        break
}}

$vol = Get-Vol -ibox $src_system -fileserver $fileserver -fs $fs -hd $headers
try{
$replica = New-Replica -srcibox $src_system -srcvol $vol -dstibox $tgt_system -dstpool $tgt_pool -rpo $rposec -interval $intervalsec -newname $new_tgt_name -hdrs $headers
if($replica.StatusCode -eq 201){
    Write-Host "Replica for filesystem $($fs) created" -ForegroundColor Green
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



    
<#
    .Description
    The Get-smbShares function gets the smb shares metadata information from InfiniBox.
#>
function Get-smbShares{
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
    [string]$outputfile
       
       )
 
CheckPSVer
$screds = EncodeCreds -User $src_username -Password $src_password
$headers = New-Headers $screds $dcreds

try{
    $smbtst = iwr -Uri "https://$($src_system)/api/rest/tenants?name=SMB" -Headers $headers -SkipCertificateCheck
}
catch{
    [Console]::ForegroundColor = 'red'
    $shr_err = ($_ | ConvertFrom-Json)
    if($shr_err.error.code -eq "UNKNOWN_PATH"){
    [Console]::Error.WriteLine("Error: SMB Not Found")
    [Console]::ResetColor()
        break
    } else{
    [Console]::Error.WriteLine($shr_err.error.message)
    [Console]::ResetColor()
        break
}}

$shr = Get-ShareMeta -ibox $src_system -hd $headers -fileserver $fileserver -filesystem $filesystem
if($outputfile){
    $shr.result | Out-File -FilePath $outputfile    
    }else{
    $shr.result
    }
    }








