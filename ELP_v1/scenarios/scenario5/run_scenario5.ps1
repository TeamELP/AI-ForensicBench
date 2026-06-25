param(
    [string]$ScenarioPath  = ".\scenario5.json",
    [string]$TargetService = "Spooler"
)

$Global:StageSummary = @()

# ==============================
# Admin Check
# ==============================
$principal = New-Object Security.Principal.WindowsPrincipal `
    ([Security.Principal.WindowsIdentity]::GetCurrent())

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run PowerShell as Administrator." -ForegroundColor Red
    exit
}

# 스크립트 최상단 (Admin Check 직후)
$Global:ScriptStartTime = Get-Date

# ==============================
# Audit Policy
# ==============================
# Logon (4624)
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# Logoff (4634, 4647) — 현재 없음
auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# Special Logon (4672) — 현재 없음
auditpol /set /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# File System (4656, 4663)
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# Registry (4656, 4663)
auditpol /set /subcategory:"{0CCE921E-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# Handle Manipulation (4656)
auditpol /set /subcategory:"{0CCE9222-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# Process Creation (4688)
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

# ==============================
# Load Scenario JSON
# ==============================
if (-not (Test-Path $ScenarioPath)) {
    Write-Error "Scenario file not found: $ScenarioPath"
    exit
}

$Scenario  = Get-Content $ScenarioPath -Raw -Encoding UTF8 | ConvertFrom-Json
$Artifacts = $Scenario.artifacts_definition

$BaseDir    = $Artifacts.base_directory
$HostsFile  = $Artifacts.hosts_file
$ServiceLog = $Artifacts.service_log
$SvcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$TargetService"

# Create required directories
@($BaseDir, (Split-Path $ServiceLog -Parent)) | Sort-Object -Unique | ForEach-Object {
    if ($_ -and -not (Test-Path $_)) {
        New-Item $_ -ItemType Directory -Force | Out-Null
    }
}

# Create initial svc.log content (target for Stage 14 deletion)
"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] SysControl Service Started"            | Set-Content  $ServiceLog -Encoding UTF8
"[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] TargetService=$TargetService - Active" | Add-Content  $ServiceLog -Encoding UTF8

# ==============================
# SACL Setup
# ==============================

# 1. BaseDir - FullControl audit
try {
    $fsAudit = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "FullControl",
        "ContainerInherit,ObjectInherit", "None", "Success,Failure"
    )
    $baseAcl = Get-Acl $BaseDir
    $baseAcl.AddAuditRule($fsAudit)
    Set-Acl $BaseDir $baseAcl
    Write-Host "[SACL] BaseDir audit rule set: $BaseDir" -ForegroundColor Green
} catch {
    Write-Host "[SACL] BaseDir audit rule failed: $_" -ForegroundColor Yellow
}

# 2. hosts file - write audit (triggers EID 4656/4663 in Stage 6)
try {
    $hostsAudit = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "WriteData,AppendData",
        "None", "None", "Success,Failure"
    )
    $hostsAcl = Get-Acl $HostsFile
    $hostsAcl.AddAuditRule($hostsAudit)
    Set-Acl $HostsFile $hostsAcl
    Write-Host "[SACL] hosts file audit rule set: $HostsFile" -ForegroundColor Green
} catch {
    Write-Host "[SACL] hosts file audit rule failed: $_" -ForegroundColor Yellow
}

# 3. Registry - Get-Acl/Set-Acl 방식 (AccessSystemSecurity 불필요)
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$TargetService"
    $regAcl  = Get-Acl $regPath
    $regAudit = New-Object System.Security.AccessControl.RegistryAuditRule(
        "Everyone",
        [System.Security.AccessControl.RegistryRights]"SetValue,CreateSubKey",
        [System.Security.AccessControl.InheritanceFlags]::None,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AuditFlags]::Success
    )
    $regAcl.AddAuditRule($regAudit)
    Set-Acl $regPath $regAcl
    Write-Host "[SACL] Registry audit rule set: $regPath" -ForegroundColor Green
} catch {
    Write-Host "[SACL] Registry audit rule failed: $_" -ForegroundColor Yellow
}

# svc.log 생성 직후 (스크립트 상단 초기화 블록 끝에 추가)
try {
    $logAudit = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone",
        "Delete,WriteData",
        "None", "None", "Success,Failure"
    )
    $logAcl = Get-Acl $ServiceLog
    $logAcl.AddAuditRule($logAudit)
    Set-Acl $ServiceLog $logAcl
    Write-Host "[SACL] svc.log audit rule set: $ServiceLog" -ForegroundColor Green
} catch {
    Write-Host "[SACL] svc.log audit rule failed: $_" -ForegroundColor Yellow
}

Start-Sleep -Seconds 3



# ==============================
# GT Structure
# ==============================
$GTDir  = "C:\GT"
$GTPath = "$GTDir\ground_truth_scenario5.json"

if (-not (Test-Path $GTDir)) { New-Item $GTDir -ItemType Directory -Force | Out-Null }

$Global:GT = @{
    schema_version = "2.0"
    scenario_id    = $Scenario.scenario_id
    scenario_name  = $Scenario.scenario_name
    user           = $env:USERNAME
    host           = $env:COMPUTERNAME
    target_service = $TargetService
    generated_at   = (Get-Date).ToString("o")
    records        = @()
}

$AllowedSecurityIDs = @($Scenario.environment_context.required_logging_configuration.security_events | ForEach-Object { [int]$_ })
$AllowedSysmonIDs   = @($Scenario.environment_context.required_logging_configuration.sysmon_events   | ForEach-Object { [int]$_ })
$AllowedSystemIDs   = @($Scenario.environment_context.required_logging_configuration.system_events   | ForEach-Object { [int]$_ })

# ==============================
# Add-ToList Helper
# ==============================
function Add-ToList {
    param([System.Collections.ArrayList]$List, $Items)
    if ($Items) { $Items | ForEach-Object { [void]$List.Add([int]$_) } }
}

# ==============================
# Event Collector (Security + Sysmon + System)
# ==============================
function Collect-ObservedEvents {
    param($Start, $End)
    $secIds    = [System.Collections.ArrayList]::new()
    $sysmonIds = [System.Collections.ArrayList]::new()
    $systemIds = [System.Collections.ArrayList]::new()

    try {
        $sec = Get-WinEvent -FilterHashtable @{
            LogName='Security'; StartTime=$Start; EndTime=$End
        } -ErrorAction SilentlyContinue | Where-Object { [int]$_.Id -in $AllowedSecurityIDs }
        Add-ToList $secIds ($sec | Select-Object -ExpandProperty Id -Unique)
    } catch {}

    try {
        $sysmon = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$Start; EndTime=$End
        } -ErrorAction SilentlyContinue | Where-Object { [int]$_.Id -in $AllowedSysmonIDs }
        Add-ToList $sysmonIds ($sysmon | Select-Object -ExpandProperty Id -Unique)
    } catch {}

    try {
        $sysEvt = Get-WinEvent -FilterHashtable @{
            LogName='System'; StartTime=$Start; EndTime=$End
        } -ErrorAction SilentlyContinue | Where-Object { [int]$_.Id -in $AllowedSystemIDs }
        Add-ToList $systemIds ($sysEvt | Select-Object -ExpandProperty Id -Unique)
    } catch {}

    return [ordered]@{
        system   = $systemIds
        sysmon   = $sysmonIds
        security = $secIds
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

    $stageMeta = $Scenario.scenario_flow | Where-Object { $_.stage_id -eq $StageId }

    # [수정 1] JSON action_type 우선, 없으면 파라미터 fallback
    $resolvedActionType = if ($stageMeta -and $stageMeta.action_type) {
        $stageMeta.action_type
    } else {
        $ActionType
    }

    $status = "success"

    # [수정 2] Stage 1은 스크립트 시작 시간으로 소급, 나머지는 현재 시간
    $start = if ($StageId -eq 1) { $Global:ScriptStartTime } else { Get-Date }

    try { & $Action } catch {
        $status = "failed"
        Write-Host "  [FAILED] Stage $StageId - $_" -ForegroundColor Red
    }

    Start-Sleep -Seconds 8
    $end = Get-Date

    $events = Collect-ObservedEvents $start $end.AddSeconds(60)

    if ($stageMeta -and $stageMeta.expected_logs) {
        $expSec    = @()
        $expSysmon = @()
        $expSystem = @()
        if ($stageMeta.expected_logs.security) { $expSec    = @($stageMeta.expected_logs.security | ForEach-Object { [int]$_ }) }
        if ($stageMeta.expected_logs.sysmon)   { $expSysmon = @($stageMeta.expected_logs.sysmon   | ForEach-Object { [int]$_ }) }
        if ($stageMeta.expected_logs.system)   { $expSystem = @($stageMeta.expected_logs.system   | ForEach-Object { [int]$_ }) }

        $fSec = [System.Collections.ArrayList]::new()
        Add-ToList $fSec ($events.security | Where-Object { [int]$_ -in $expSec } | Sort-Object -Unique)
        $events.security = $fSec

        $fSysmon = [System.Collections.ArrayList]::new()
        Add-ToList $fSysmon ($events.sysmon | Where-Object { [int]$_ -in $expSysmon } | Sort-Object -Unique)
        $events.sysmon = $fSysmon

        $fSystem = [System.Collections.ArrayList]::new()
        Add-ToList $fSystem ($events.system | Where-Object { [int]$_ -in $expSystem } | Sort-Object -Unique)
        $events.system = $fSystem
    }

    $Global:GT.records += [ordered]@{
        stage_id           = $StageId
        stage_name         = $StageName
        action_type        = $resolvedActionType   # [수정 1] JSON 값 사용
        description        = if ($stageMeta) { $stageMeta.description } else { "" }
        attack             = $Attack
        stage_start_time   = $start.ToString("o")
        stage_end_time     = $end.ToString("o")
        artifact_paths     = $ArtifactPaths
        user               = $env:USERNAME
        host               = $env:COMPUTERNAME
        execution_status   = $status
        observed_event_ids = $events
        expected_event_ids = if ($stageMeta) { $stageMeta.expected_logs } else { $null }
        primary_log_signal = $PrimarySignal
        notes              = if ($stageMeta) { $stageMeta.notes } else { "" }
    }

    $Global:StageSummary += [PSCustomObject]@{
        ID     = $StageId
        Name   = $StageName
        Status = $status
    }

    Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 7)
}

# ==============================
# Show-Summary
# ==============================
function Show-Summary {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor White
    Write-Host "  STAGE SUMMARY" -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
    foreach ($s in $Global:StageSummary) {
        $icon  = switch ($s.Status) {
            "success" { "[OK    ]" } "partial" { "[PART  ]" }
            "failed"  { "[FAILED]" } default   { "[?     ]" }
        }
        $color = switch ($s.Status) {
            "success" { "Green" } "partial" { "Yellow" }
            "failed"  { "Red"   } default   { "Gray"   }
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
# --------------------------------------------------
# Stage 1: authorized_logon  (attack=false)
# Current session 4624 LogonType=2 already recorded.
# Capture LogonId as anchor for Stage 15 4634 matching.
# --------------------------------------------------
Invoke-Stage 1 "authorized_logon" "logon" `
    $null {
   
    # 현재 세션의 LogonId는 Properties[7]
    $recent = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624 } `
        -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties[8].Value -in @(2, 10) } |  # LogonType은 index 8
        Select-Object -First 1
    if ($recent) {
        Write-Host "  [INFO] Session 4624 found: $($recent.TimeCreated)" -ForegroundColor DarkGreen
        $Global:SessionLogonId = $recent.Properties[7].Value  # LogonId 보존
    }
} $false "EID 4624 LogonType=2 (Interactive Logon)"


# --------------------------------------------------
# Stage 2: system_discovery  T1082
# systeminfo.exe -> EID 4688 + Sysmon 1 (PPID=powershell.exe)
# --------------------------------------------------
Invoke-Stage 2 "system_discovery" "process_start" `
    "systeminfo execution artifact" {
    $out = & systeminfo 2>&1
    Write-Host "  [INFO] systeminfo: $(($out | Measure-Object -Line).Lines) lines" -ForegroundColor DarkGreen
} $true "EID 4688 + Sysmon 1: systeminfo.exe (PPID=powershell.exe)"


# --------------------------------------------------
# Stage 3: service_enumeration  T1007
# sc.exe query -> EID 4688 + Sysmon 1 (PPID=powershell.exe)
# --------------------------------------------------
Invoke-Stage 3 "service_enumeration" "process_start" `
    "sc.exe query execution artifact" {
    $out = & sc.exe query type= all state= all 2>&1
    $cnt = ($out | Select-String "SERVICE_NAME").Count
    Write-Host "  [INFO] sc.exe query: $cnt services" -ForegroundColor DarkGreen
} $true "EID 4688 + Sysmon 1: sc.exe query (PPID=powershell.exe)"



# --------------------------------------------------
# Stage 4: service_config_modification_retry_success  T1562.001
# Remove Deny ACE then retry -> success
# -> EID 4688 + EID 4663 (WriteKey Success audit)
# --------------------------------------------------
Invoke-Stage 4 "service_config_modification_retry_success" "process_start" `
    "$SvcRegPath (Write Success)" {
    $result = & sc.exe config $TargetService start= disabled 2>&1
    Write-Host "  [INFO] sc.exe config: $($result -join ' ')" -ForegroundColor DarkGreen
    "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Config: $TargetService start=disabled" |
        Add-Content $ServiceLog -Encoding UTF8
} $true "EID 7040 + EID 4688: Service StartType Modification"


# --------------------------------------------------
# Stage 5: hosts_file_tampering  T1565.001
# Add-Content (powershell.exe in-process, child=null)
# -> Sysmon EID 11 (FileCreate) + EID 4656/4663 (hosts file write audit)
# --------------------------------------------------
Invoke-Stage 5 "hosts_file_tampering" "file_modification" `
    $HostsFile {

    $entry = "127.0.0.1 target.internal"

    # temp hosts 생성 → Sysmon EID 11 유도
    $tempHosts = "$env:TEMP\hosts.tmp"

    Copy-Item $HostsFile $tempHosts -Force

    Add-Content -Path $tempHosts `
        -Value $entry `
        -Encoding ASCII

    # overwrite
    Copy-Item $tempHosts $HostsFile -Force

    Write-Host "  [INFO] hosts entry added via temp overwrite: $entry" `
        -ForegroundColor DarkGreen

} $true "Sysmon EID 11 + EID 4656/4663: $HostsFile"


# --------------------------------------------------
# Stage 6: service_stop_attempt_fail  T1489
# WinDefend is PPL (Protected Process Light) -> sc.exe stop fails even as Admin
# -> EID 4688 only; EID 7036 NOT generated (service state unchanged)
# --------------------------------------------------
Invoke-Stage 6 "service_stop_attempt_fail" "process_start" `
    "sc.exe stop WinDefend (Expected Fail - PPL Protected)" {
    $result = & sc.exe stop "WinDefend" 2>&1
    Write-Host "  [EXPECTED FAIL] sc.exe stop WinDefend: $($result -join ' ')" -ForegroundColor DarkYellow
} $true "EID 4688: sc.exe stop failed (EID 7036 absent)"


# --------------------------------------------------
# Stage 7: privilege_escalation_adjustment  T1078
# --------------------------------------------------
Invoke-Stage 7 "service_recovery_policy_manipulation" "service_policy_modification" `
    "sc.exe failure configuration change" {

    Write-Host "  [Stage 7] Modifying service recovery policy..." -ForegroundColor Cyan

    cmd /c 'sc failure Spooler reset= 0 actions= restart/5000' 2>$null

    Start-Sleep -Seconds 2

    cmd /c 'sc failureflag Spooler 1' 2>$null

    Write-Host "  [INFO] Service recovery policy modified" -ForegroundColor DarkGreen

} $true "EID 4688 + EID 4663: Service Recovery Policy Modification"


Invoke-Stage 8 "service_stop_retry_success" "process_start" `
    "sc.exe stop $TargetService (Success)" {

    $result = & sc.exe stop $TargetService 2>&1

    Write-Host "  [INFO] sc.exe stop: $($result -join ' ')" -ForegroundColor DarkGreen

    $timeout = [DateTime]::Now.AddSeconds(30)
    do {
        Start-Sleep -Seconds 1
        $svc = Get-Service $TargetService -ErrorAction SilentlyContinue
    } until ($svc.Status -eq 'Stopped' -or [DateTime]::Now -gt $timeout)

    if ($svc.Status -ne 'Stopped') {
        Write-Host "  [WARN] $TargetService did not stop within 30s" -ForegroundColor Yellow
    }

} $true "EID 4688 + EID 7036 Stopped: $TargetService"

# --------------------------------------------------
# Stage 9: service_restart_loop_attempt  T1499
# sc.exe start/stop x3 -> EID 4688 x6 + EID 7036 Running/Stopped x6
# --------------------------------------------------
Invoke-Stage 9 "service_restart_loop_attempt" "process_start" `
    "sc.exe start/stop loop x3" {

    1..3 | ForEach-Object {

        # --- START ---
        & sc.exe start $TargetService | Out-Null
        try {
            (Get-Service $TargetService -ErrorAction Stop).WaitForStatus(
                'Running', [TimeSpan]::FromSeconds(10)
            )
        } catch { }
        Start-Sleep -Milliseconds 800    # SCM → EID 7036 flush 대기

        $s = Get-Service $TargetService -ErrorAction SilentlyContinue
        Write-Host "  [start $_] $($s.Status)" -ForegroundColor DarkYellow

        # --- STOP ---
        & sc.exe stop $TargetService | Out-Null
        try {
            (Get-Service $TargetService -ErrorAction Stop).WaitForStatus(
                'Stopped', [TimeSpan]::FromSeconds(10)
            )
        } catch { }
        Start-Sleep -Milliseconds 800    # SCM → EID 7036 flush 대기

        $s = Get-Service $TargetService -ErrorAction SilentlyContinue
        Write-Host "  [stop  $_] $($s.Status)" -ForegroundColor DarkYellow
    }

} $true "EID 4688 x6 + EID 7036 Running/Stopped x6"

# --------------------------------------------------
# Stage 10: service_restart_loop_retry  T1499
# for loop x5 -> EID 4688 x10 + EID 7036 x10 (Running/Stopped alternating)
# EID 7036 ServiceName field links to Stage 12
# --------------------------------------------------
Invoke-Stage 10 "service_restart_loop_retry" "process_start" `
    "sc.exe start/stop loop x5" {

    for ($i = 0; $i -lt 5; $i++) {

        # --- START ---
        & sc.exe start $TargetService | Out-Null
        try {
            (Get-Service $TargetService -ErrorAction Stop).WaitForStatus(
                'Running', [TimeSpan]::FromSeconds(10)
            )
        } catch { }
        Start-Sleep -Milliseconds 800   # SCM → EID 7036 flush 대기

        # --- STOP ---
        & sc.exe stop $TargetService | Out-Null
        try {
            (Get-Service $TargetService -ErrorAction Stop).WaitForStatus(
                'Stopped', [TimeSpan]::FromSeconds(10)
            )
        } catch { }
        Start-Sleep -Milliseconds 800   # SCM → EID 7036 flush 대기
    }

    Write-Host "  [INFO] start/stop loop x5 complete ($TargetService)" -ForegroundColor DarkGreen

} $true "EID 4688 x10 + EID 7036 x10 Running/Stopped"


# --------------------------------------------------
# Stage 11: service_disruption_observed  T1489
# Service disruption monitoring / persistence of impact
# Generates additional 4688 + Sysmon 1 intentionally
# --------------------------------------------------
Invoke-Stage 11 "service_disruption_observed" "service_status_check" `
    "sc.exe query $TargetService" {

    $output = & sc.exe query $TargetService 2>&1

    $stateLine = $output |
        Where-Object { $_ -match "RUNNING|STOPPED|PENDING|PAUSED" } |
        Select-Object -First 1

    $state = if ($stateLine) { $stateLine.ToString().Trim() } else { "STATE_NOT_FOUND" }

    Write-Host "  [INFO] $TargetService current state: $state" -ForegroundColor DarkGreen

    # 새 파일 생성 → Sysmon EID 11 발생
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Disruption monitoring observed: $state"
    $statusFile = "$BaseDir\disruption_status.log"

    $logEntry | Out-File $statusFile -Encoding UTF8 -Force

    # svc.log 에도 추가 기록
    if (Test-Path $ServiceLog) {
        Add-Content $ServiceLog -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    }

    Write-Host "  [INFO] Status written to disruption_status.log" -ForegroundColor DarkGreen

} $true "EID 4688 + Sysmon 1 + Sysmon 11 (FileCreate: disruption_status.log)"


# --------------------------------------------------
# Stage 12: log_deletion_attempt_fail  T1070.001
# wevtutil.exe cl Security -> event log access attempt
# -> Sysmon EID 1 (process create) + EID 4656 (AccessDenied expected)
#
# [Lab note] High-integrity Admin holds SeSecurityPrivilege so wevtutil may succeed.
# EID 4688 is recorded regardless of outcome.
# --------------------------------------------------
# Stage 12 Action
Invoke-Stage 12 "log_deletion_attempt_fail" "process_start" `
    "wevtutil cl Security (Expected Fail - backup path unreachable)" {

    $buPath = "C:\NonExistentStage12Dir\security_backup.evtx"
    $result = & wevtutil.exe cl Security /bu:$buPath 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [EXPECTED FAIL] wevtutil cl Security: $($result -join ' ')" `
            -ForegroundColor DarkYellow
    } else {
        Write-Host "  [ERROR] wevtutil succeeded - Security log cleared!" `
            -ForegroundColor Red
    }

} $true "EID 4688 + Sysmon 1: wevtutil cl Security /bu: (backup path unreachable)"

# --------------------------------------------------
# Stage 13: log_deletion_retry_partial_success  T1070.001
# Remove-Item (powershell.exe in-process, child=null)
# -> Sysmon EID 26 (FileDeleteDetected) + EID 4663 (Delete Success)
# cleanup_targets achieved: svc.log deleted
# cleanup_survivors preserved: hosts file not deleted
# --------------------------------------------------
Invoke-Stage 13 "log_deletion_retry_partial_success" "file_delete" `
    $ServiceLog {
    if (Test-Path $ServiceLog) {
        Remove-Item -Path $ServiceLog -Force
        Write-Host "  [INFO] svc.log deleted: $ServiceLog" -ForegroundColor DarkGreen
    } else {
        Write-Host "  [WARN] svc.log not found (already deleted): $ServiceLog" -ForegroundColor Yellow
    }
} $true "Sysmon EID 26 FileDelete + EID 4663: $ServiceLog"


# --------------------------------------------------
# Stage 14: session_termination  (attack=false)
# EID 4647 (user-initiated logoff) + EID 4634 (session disconnect)
# 4634 LogonId = Stage 1 4624 LogonId -> full session scope confirmed
# --------------------------------------------------
Invoke-Stage 14 "session_termination" "logoff" `
    $null {
    Write-Host "  [INFO] Session termination stage -- EID 4647/4634 auto-generated on session close" `
        -ForegroundColor DarkGreen
} $false "EID 4647 (Logoff Initiated) + EID 4634 (Session Terminated)"


# ==============================
# Cleanup
# ==============================

# Restore hosts file (cleanup_survivors: evidence trace remains, actual entry removed)
try {
    $raw = [System.IO.File]::ReadAllText($HostsFile, [System.Text.Encoding]::ASCII)
    $raw = $raw -replace "(?m)^127\.0\.0\.1\s+target\.internal\r?\n?", ""
    [System.IO.File]::WriteAllText($HostsFile, $raw, [System.Text.Encoding]::ASCII)
    Write-Host "[CLEANUP] hosts file restored" -ForegroundColor Green
} catch {
    Write-Host "[CLEANUP] hosts file restore failed: $_" -ForegroundColor Yellow
}

# Restore TargetService (start=auto then start)
try {
    & sc.exe config $TargetService start= auto 2>&1 | Out-Null
    & sc.exe start  $TargetService 2>&1 | Out-Null
    Write-Host "[CLEANUP] $TargetService restored (start=auto, started)" -ForegroundColor Green
} catch {
    Write-Host "[CLEANUP] $TargetService restore failed: $_" -ForegroundColor Yellow
}

# BaseDir preserved (svc.log already deleted in Stage 14; directory kept as artifact evidence)

# ==============================
# Save GT
# ==============================
$Global:GT.total_stages = $Global:GT.records.Count
$Global:GT | ConvertTo-Json -Depth 6 | Out-File $GTPath -Encoding UTF8
Write-Host "GT saved to $GTPath" -ForegroundColor Yellow

Show-Summary
