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

   if($fileserver){
     return ($shr1.result | ?{$_.fileserver_name -eq $fileserver})

     }
   elseif($filesystem){
        return ($shr1.result |  ?{$_.filesystem_name -eq $filesystem})
   }
   elseif($fileserver -and $filesystem){
        return ($shr1.result |  ?{$_.fileserver_name -eq $fileserver -and $_.filesystem_name -eq $filesystem })
   }
   else{
        return $shr1.result
   }
   
   
}


<#
    .Description
    The New-smbReplica function creates an Async replica for SMB volume.
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
$screds = EncodeCreds -User $src_username -Password $src_password -ibox $src_system
$dcreds = EncodeCreds -User $tgt_username -Password $tgt_password -ibox $tgt_system
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
    [Console]::Error.WriteLine("Error: InfiniBox $($src_system) doesn't support SMB")
    [Console]::ResetColor()
        break
    } else{
    [Console]::Error.WriteLine($smbvalid_err.error.message)
    [Console]::ResetColor()
        break
}}

$vol = Get-Vol -ibox $src_system -fileserver $fileserver -fs $fs -hd $headers
if($vol.result){
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
     }}



    
<#
    .Description
    The Get-smbShares function gets the smb shares metadata information from InfiniBox.
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

try{
    $smbtst = iwr -Uri "https://$($src_system)/api/rest/tenants?name=SMB" -Headers $headers -SkipCertificateCheck
}
catch{
    [Console]::ForegroundColor = 'red'
    $shr_err = ($_ | ConvertFrom-Json)
    if($shr_err.error.code -eq "UNKNOWN_PATH"){
    [Console]::Error.WriteLine("Error: InfiniBox $($src_system) doesn't support SMB")
    [Console]::ResetColor()
        break
    } else{
    [Console]::Error.WriteLine($shr_err.error.message)
    [Console]::ResetColor()
        break
}}

$shr = Get-ShareMeta -ibox $src_system -hd $headers -fileserver $fileserver -filesystem $filesystem
if($outputfile){
    $shr | Out-File -FilePath $outputfile    
    }
elseif($csv){
     $shr | ConvertTo-Csv
     }
elseif($csv -and $outputfile){
     $shr | ConvertTo-Csv| Out-File -FilePath $outputfile     
     }
else{
    $shr
}
   
   
    }
    








