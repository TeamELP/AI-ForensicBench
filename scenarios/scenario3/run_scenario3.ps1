param(
    [string]$ScenarioPath = ".\scenario3.json"
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

# ==============================
# Audit Policy
# ==============================
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE921E-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

# ==============================
# Load Scenario JSON
# ==============================
if (-not (Test-Path $ScenarioPath)) {
    Write-Error "Scenario file not found."
    exit
}

$Scenario  = Get-Content $ScenarioPath -Raw | ConvertFrom-Json
$Artifacts = $Scenario.artifacts_definition

$BaseDir  = $Artifacts.base_directory
$Decoy1   = $Artifacts.decoy_file_1
$TempFile = $Artifacts.temp_file

@(
    $BaseDir,
    (Split-Path $Decoy1 -Parent),
    (Split-Path $TempFile -Parent)
) | ForEach-Object {
    if ($_ -and -not (Test-Path $_)) {
        New-Item $_ -ItemType Directory -Force | Out-Null
    }
}

Remove-Item $Decoy1 -Force -ErrorAction SilentlyContinue

# ==============================
# SACL - 파일 시스템
# ==============================
try {
    $acl   = Get-Acl $BaseDir
    $audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "FullControl",
        "ContainerInherit,ObjectInherit", "None", "Success,Failure"
    )
    $acl.AddAuditRule($audit)
    Set-Acl $BaseDir $acl
    Write-Host "[SACL] 파일 감사 규칙 설정 완료: $BaseDir" -ForegroundColor Green

    $decoyParent = Split-Path $Decoy1 -Parent
    if ($decoyParent -ne $BaseDir) {
        $acl2 = New-Object System.Security.AccessControl.DirectorySecurity
        $acl2.AddAuditRule($audit)
        Set-Acl $decoyParent $acl2
        Write-Host "[SACL] Decoy 부모 디렉터리 감사 규칙 설정 완료: $decoyParent" -ForegroundColor Green
    }

    $tempParent = Split-Path $TempFile -Parent
    if ($tempParent -ne $BaseDir -and $tempParent -ne $decoyParent) {
        if (-not (Test-Path $tempParent)) { New-Item $tempParent -ItemType Directory -Force | Out-Null }
        $acl3 = Get-Acl $tempParent
        $acl3.AddAuditRule($audit)
        Set-Acl $tempParent $acl3
        Write-Host "[SACL] TempFile 부모 디렉터리 감사 규칙 설정 완료: $tempParent" -ForegroundColor Green
    }

    Start-Sleep -Seconds 3
} catch {
    Write-Host "[SACL] 파일 감사 규칙 설정 실패: $_" -ForegroundColor Yellow
}

# ==============================
# SACL - 레지스트리
# ==============================
try {
    $regPath  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $regAcl   = Get-Acl $regPath
    $regAudit = New-Object System.Security.AccessControl.RegistryAuditRule(
        "Everyone", "SetValue,Delete",
        "ContainerInherit,ObjectInherit", "None", "Success,Failure"
    )
    $regAcl.AddAuditRule($regAudit)
    Set-Acl $regPath $regAcl
    Write-Host "[SACL] 레지스트리 감사 규칙 설정 완료: $regPath" -ForegroundColor Green
    Start-Sleep -Seconds 3
} catch {
    Write-Host "[SACL] 레지스트리 감사 규칙 설정 실패: $_" -ForegroundColor Yellow
}

# ==============================
# GT Structure
# ==============================
$GTDir  = "C:\GT"
$GTPath = "$GTDir\ground_truth_scenario3.json"

if (-not (Test-Path $GTDir)) { New-Item $GTDir -ItemType Directory -Force | Out-Null }

$Global:GT = @{
    schema_version = "2.0"
    scenario_name  = $Scenario.scenario_name
    user           = $env:USERNAME
    host           = $env:COMPUTERNAME
    generated_at   = (Get-Date).ToString("o")
    records        = @()
    scenario_id    = $Scenario.scenario_id
}

$AllowedSecurityIDs   = @($Scenario.environment_context.required_logging_configuration.security_events   | ForEach-Object { [int]$_ })
$AllowedSysmonIDs     = @($Scenario.environment_context.required_logging_configuration.sysmon_events     | ForEach-Object { [int]$_ })


# ==============================
# ProcAccess P/Invoke
# ==============================
if (-not ([System.Management.Automation.PSTypeName]'ProcAccess').Type) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class ProcAccess {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
"@
}

# Add-ToList: ArrayList에 항목 추가 헬퍼
# New-IdList 함수 방식은 PS가 빈 ArrayList를 파이프라인에서 열거해 $null로 만드는 문제가 있어
# ::new() 직접 생성 방식으로 대체
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
    $securityIds      = [System.Collections.ArrayList]::new()
    $sysmonIds        = [System.Collections.ArrayList]::new()
   

    try {
        $sec = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            StartTime = $Start
            EndTime   = $End
        } -ErrorAction SilentlyContinue | Where-Object { [int]$_.Id -in $AllowedSecurityIDs }
        Add-ToList $securityIds ($sec | Select-Object -ExpandProperty Id -Unique)
    } catch {}

    try {
        $sys = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            StartTime = $Start
            EndTime   = $End
        } -ErrorAction SilentlyContinue | Where-Object { [int]$_.Id -in $AllowedSysmonIDs }
        Add-ToList $sysmonIds ($sys | Select-Object -ExpandProperty Id -Unique)
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
    $resolvedDesc       = if ($stageMeta -and $stageMeta.description) { $stageMeta.description } else { "" }
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
        if ($stageMeta.expected_logs.security)       { $expectedSec = @($stageMeta.expected_logs.security       | ForEach-Object { [int]$_ }) }
        if ($stageMeta.expected_logs.sysmon)         { $expectedSys = @($stageMeta.expected_logs.sysmon         | ForEach-Object { [int]$_ }) }
      
        $fSec = [System.Collections.ArrayList]::new(); Add-ToList $fSec ($events.security       | Where-Object { [int]$_ -in $expectedSec } | Sort-Object -Unique); $events.security       = $fSec
        $fSys = [System.Collections.ArrayList]::new(); Add-ToList $fSys ($events.sysmon         | Where-Object { [int]$_ -in $expectedSys } | Sort-Object -Unique); $events.sysmon         = $fSys
    
    }

   $Global:GT.records += [ordered]@{
        stage_id             = $StageId
        stage_name           = $StageName
        action_type          = $resolvedActionType
        description          = if ($stageMeta) { $stageMeta.description } else { "" }

        attack               = $Attack
        stage_start_time     = $start.ToString("o")
        stage_end_time       = $end.ToString("o")
        artifact_paths       = $ArtifactPaths
        user                 = $env:USERNAME
        host                 = $env:COMPUTERNAME
        execution_status     = $status
        observed_event_ids   = $events
        expected_event_ids   = if ($stageMeta) { $stageMeta.expected_logs } else { $null }
        primary_log_signal   = $PrimarySignal
        notes                = if ($stageMeta) { $stageMeta.notes } else { "" }
    }
    $Global:StageSummary += [PSCustomObject]@{
        ID     = $StageId
        Name   = $StageName
        Status = $status
    }

    Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 7)  # ← scenario3는 3~7초
}

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
    Write-Host ("  Total:{0}  OK:{1}  Partial:{2}  Failed:{3}" `
        -f $total, $ok, $partial, $failed) -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
}


# ==============================
# Network Probe Helper
# Resolve-DnsName → DnsQuery API 경유 → Sysmon EID 22 발생
# nslookup → raw UDP, EID 22 미발생
# ==============================
function Invoke-NetworkProbe {
    param([string]$Target, [int]$Port)

    # Sysmon 22: Resolve-DnsName → Windows DNS Client API 경유
    $fakeDomain = "beacon-$(Get-Random -Max 9999).cdn-update-svc.net"
    Resolve-DnsName -Name $fakeDomain -ErrorAction SilentlyContinue | Out-Null

    # Sysmon 3: nslookup 외부 프로세스 (port 53 UDP → RST 없이 패킷 전송, Sysmon 3 확실히 발생)
    Start-Process -FilePath "nslookup" `
        -ArgumentList "$fakeDomain $Target" `
        -WindowStyle Hidden -Wait
}
# ===================================================
# STAGE FLOW
# ===================================================

# Stage 1
Invoke-Stage 1 "powershell_spawn" "process_start" `
    "powershell.exe 실행 흔적" {
    Start-Process powershell -WindowStyle Hidden
} $true "Process Create: powershell.exe"

# Stage 2
Invoke-Stage 2 "encoded_command_execution" "command_execution" `
    "인코딩 명령 실행 흔적" {
    powershell -EncodedCommand "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA=="
} $true "EncodedCommand Execution: powershell.exe"


# Stage 3
Invoke-Stage 3 "initial_network_connection" "network_connection" `
    "DNS 쿼리 흔적" {
    Invoke-NetworkProbe -Target "127.0.0.1" -Port 53
} $true "Network Connection: DNS Port 53"

# Stage 4
Invoke-Stage 4 "secondary_network_connection" "network_connection" `
    "DNS 쿼리 흔적" {
    Invoke-NetworkProbe -Target "127.0.0.1" -Port 53
} $true "Network Connection: DNS Port 53"


# Stage 5
Invoke-Stage 5 "process_access_explorer" "process_access" `
    "explorer.exe 프로세스 접근" {
    $target = (Get-Process explorer | Select-Object -First 1).Id
    $h = [ProcAccess]::OpenProcess(0x1F0FFF, $false, $target)
    if ($h -ne [IntPtr]::Zero) { [ProcAccess]::CloseHandle($h) }
} $true "ProcessAccess: explorer.exe PROCESS_ALL_ACCESS"

# Stage 6
Invoke-Stage 6 "process_access_svchost" "process_access" `
    "svchost.exe 프로세스 접근" {
    $target = (Get-Process svchost | Select-Object -First 1).Id
    $h = [ProcAccess]::OpenProcess(0x1F0FFF, $false, $target)
    if ($h -ne [IntPtr]::Zero) { [ProcAccess]::CloseHandle($h) }
} $true "ProcessAccess: svchost.exe PROCESS_ALL_ACCESS"

# Stage 7
Invoke-Stage 7 "irregular_network_activity" "network_connection" `
    "DNS 쿼리 흔적" {
    Invoke-NetworkProbe -Target "127.0.0.1" -Port 53
} $true "Network Connection: Irregular Port 53"

# Stage 8
Invoke-Stage 8 "decoy_file_creation_1" "file_create" `
    $Decoy1 {
    New-Item $Decoy1 -ItemType File -Force | Out-Null
    Add-Content $Decoy1 "telemetry"
} $true "File Create: TelemetryCache.bin"

# Stage 9
Invoke-Stage 9 "secondary_process_spawn" "process_start" `
    "powershell.exe 실행 흔적" {
    Start-Process powershell -ArgumentList "-NoProfile -EncodedCommand UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA==" -WindowStyle Hidden
} $true "Process Create: powershell.exe EncodedCommand"

# Stage 10
Invoke-Stage 10 "network_retry_pattern" "network_connection" `
    "DNS 쿼리 흔적" {
    Invoke-NetworkProbe -Target "127.0.0.1" -Port 80
} $true "Network Connection: HTTP Port 80 Retry"

# Stage 11
Invoke-Stage 11 "privilege_escalation_attempt" "process_execution" `
    "whoami 실행 흔적" {
    Start-Process powershell -ArgumentList "-NoProfile -Command whoami" -WindowStyle Hidden
} $true "Process Create: whoami.exe"

# Stage 12
Invoke-Stage 12 "post_escalation_network" "network_connection" `
    "DNS 쿼리 흔적" {
    Invoke-NetworkProbe -Target "127.0.0.1" -Port 80
} $true "Network Connection: HTTP Port 80 Post Escalation"

# Stage 13
Invoke-Stage 13 "runkey_persistence" "registry_modification" `
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsCache" {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name "WindowsCache" -Value "powershell.exe" -Force
} $true "Registry Modify: HKCU Run Key WindowsCache"


# Stage 14
Invoke-Stage 14 "scheduled_task_creation" "task_creation" `
    "WindowsCacheTask 스케줄 작업 생성" {
    schtasks /create /tn "WindowsCacheTask" `
        /tr "powershell.exe" /sc onlogon /f | Out-Null
} $true "Scheduled Task Create: WindowsCacheTask"


# Stage 15
Invoke-Stage 15 "file_cleanup_1" "file_delete" `
    "$Decoy1 삭제" {
    cmd /c "del /f `"$Decoy1`""
} $true "File Delete: TelemetryCache.bin"

# Stage 16
Invoke-Stage 16 "intermittent_network_1" "network_connection" `
    "DNS 쿼리 흔적" {
    Invoke-NetworkProbe -Target "127.0.0.1" -Port 443
} $true "Network Connection: HTTPS Port 443"


# Stage 17
Invoke-Stage 17 "intermittent_network_2" "network_connection" `
    "DNS 쿼리 흔적" {
    Invoke-NetworkProbe -Target "127.0.0.1" -Port 443
} $true "Network Connection: HTTPS Port 443 Intermittent"

# Stage 18
Invoke-Stage 18 "final_process_activity" "process_start" `
    "cmd.exe 실행 흔적" {
    Start-Process cmd -WindowStyle Hidden
} $true "Process Create: cmd.exe"

# Stage 19
Invoke-Stage 19 "termination" "process_exit" `
    $null {
    Write-Host "Session Ended"
} $false "Process Exit"

# ==============================
# Cleanup
# ==============================
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsCache" -ErrorAction SilentlyContinue
schtasks /delete /tn "WindowsCacheTask" /f 2>$null | Out-Null



# ==============================
# Save GT
# ==============================
# Save GT 섹션 바로 위에 추가
$Global:GT.total_stages = $Global:GT.records.Count
$Global:GT | ConvertTo-Json -Depth 6 | Out-File $GTPath -Encoding UTF8
Write-Host "GT saved to $GTPath" -ForegroundColor Yellow
