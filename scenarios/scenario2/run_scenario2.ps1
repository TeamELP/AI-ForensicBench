param(
    [string]$ScenarioPath = ".\scenario2.json"
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
    Write-Error "Scenario file not found."
    exit
}

$Scenario  = Get-Content $ScenarioPath -Raw | ConvertFrom-Json
$Artifacts = $Scenario.artifacts_definition

$BaseDir  = $Artifacts.base_directory
$Sniffer  = $Artifacts.sniffer_path
$Pcap1    = $Artifacts.pcap_file_1
$Pcap2    = $Artifacts.pcap_file_2
$Analysis = $Artifacts.analysis_output
$CredOut  = $Artifacts.credential_output
$Cleanup  = $Artifacts.temp_cleanup_targets

# Ensure directories exist
@(
    $BaseDir,
    (Split-Path $Pcap1    -Parent),
    (Split-Path $Analysis -Parent),
    (Split-Path $CredOut  -Parent)
) | Where-Object { $_ } | ForEach-Object {
    if (-not (Test-Path -LiteralPath $_)) {
        New-Item -LiteralPath $_ -ItemType Directory -Force | Out-Null
    }
}

# ==============================
# GT Structure
# ==============================
$GTDir  = "C:\GT"
$GTPath = "$GTDir\ground_truth.json"

if (-not (Test-Path $GTDir)) {
    New-Item $GTDir -ItemType Directory -Force | Out-Null
}

$Global:GT = @{
    scenario_id   = $Scenario.scenario_id
    scenario_name = $Scenario.scenario_name
    generated_at  = (Get-Date).ToString("o")
    records       = @()
}

$Global:StageSummary = @()

# ==============================
# 1단계 필터링 - [int] 캐스팅 추가
# ==============================
$AllowedSecurityIDs = @($Scenario.environment_context.required_logging_configuration.security_events | ForEach-Object { [int]$_ })
$AllowedSysmonIDs   = @($Scenario.environment_context.required_logging_configuration.sysmon_events   | ForEach-Object { [int]$_ })

# ==============================
# ArrayList 헬퍼
# ==============================
function Add-ToList {
    param([System.Collections.ArrayList]$List, $Items)
    if ($Items) {
        $Items | ForEach-Object { [void]$List.Add([int]$_) }
    }
}

# ==============================
# Event Collector - 2단계 필터링
# ==============================
function Collect-ObservedEvents {
    param($Start, $End)
    $securityIds = [System.Collections.ArrayList]::new()
    $sysmonIds   = [System.Collections.ArrayList]::new()
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
# Stage Executor - 3단계 필터링
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

    Start-Sleep -Seconds 10
    $end = Get-Date

    $events    = Collect-ObservedEvents $start $end.AddSeconds(60)
    $stageMeta = $Scenario.scenario_flow | Where-Object { $_.stage_id -eq $StageId }

    if ($stageMeta -and $stageMeta.expected_logs) {
        $expectedSec = @()
        $expectedSys = @()
        if ($stageMeta.expected_logs.security) { $expectedSec = @($stageMeta.expected_logs.security | ForEach-Object { [int]$_ }) }
        if ($stageMeta.expected_logs.sysmon)   { $expectedSys = @($stageMeta.expected_logs.sysmon   | ForEach-Object { [int]$_ }) }

        $fSec = [System.Collections.ArrayList]::new()
        $fSys = [System.Collections.ArrayList]::new()
        Add-ToList $fSec ($events.security | Where-Object { [int]$_ -in $expectedSec } | Sort-Object -Unique)
        Add-ToList $fSys ($events.sysmon   | Where-Object { [int]$_ -in $expectedSys } | Sort-Object -Unique)
        $events.security = $fSec
        $events.sysmon   = $fSys
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


Get-Process diaghost -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# ===================================================
# ================= STAGE FLOW ======================
# ===================================================

# Stage 1
Invoke-Stage 1 "authorized_logon" "user_logon" $null {
    Start-Sleep -Seconds 5
} $false "Logon Event"

# Stage 2
Invoke-Stage 2 "system_recon" "system_recon" "systeminfo.exe" {
    systeminfo | Out-Null
    hostname   | Out-Null
} $true "Process Create: systeminfo.exe"

# Stage 3
Invoke-Stage 3 "network_configuration_discovery" "network_recon" "ipconfig/netstat" {
    ipconfig /all | Out-Null
    netstat -an   | Out-Null
} $true "Process Create: ipconfig.exe"

# Stage 4
Invoke-Stage 4 "initial_rdp_login_attempt" "remote_login_attempt" "\\127.0.0.1\IPC$" {
    cmd /c "net use \\127.0.0.1\IPC$ /delete" 2>$null
    cmd /c "net use \\127.0.0.1\IPC$ /user:test wrongpass"
} $true "Network Connection: RDP Failed"

# Stage 5
Invoke-Stage 5 "sniffing_tool_execution" "tool_execution" $Sniffer {
    Start-Process $Sniffer -WindowStyle Hidden -ErrorAction SilentlyContinue
} $true "Process Create: diaghost.exe"

# Stage 6
Invoke-Stage 6 "packet_capture_phase_1" "packet_capture" $Pcap1 {
    Start-Process cmd -ArgumentList "/c echo pcapdata > `"$Pcap1`"" -Wait
} $true "File Create: cacheA.dat"

# Stage 7
Invoke-Stage 7 "pcap_analysis" "analysis" $Analysis {
    Start-Process cmd -ArgumentList "/c echo analysis result > `"$Analysis`"" -Wait
    Start-Process cmd -ArgumentList "/c echo more data >> `"$Analysis`"" -Wait
} $true "File Create: diet.log"

# Stage 8
Invoke-Stage 8 "credential_extraction_phase_1" "credential_search" $CredOut {
    Select-String -Path $Analysis -Pattern "password" | Out-File $CredOut -Force
} $true  "File Access: credential_output"

# Stage 9
Invoke-Stage 9 "packet_capture_phase_2" "packet_capture" $Pcap2 {
    Start-Process cmd -ArgumentList "/c copy /Y `"$Pcap1`" `"$Pcap2`"" -Wait
} $true "File Create: sys_idx.bin"

# Stage 10
Invoke-Stage 10 "credential_extraction_phase_2" "credential_search" $CredOut {
    "user=root password=qwerty" | Out-File $CredOut -Append
} $true "File Write: user.dat"

# Stage 11
Invoke-Stage 11 "rdp_login_retry_failed" "remote_login_attempt" "\\127.0.0.1\IPC$" {
    cmd /c "net use \\127.0.0.1\IPC$ /user:admin wrongpass"
} $true "Network Connection: RDP Failed"


# Stage 12 사전 준비
net user intruder /delete 2>$null
net user intruder P@ssw0rd! /add 2>$null
net localgroup Administrators intruder /add 2>$null

# Stage 12
Invoke-Stage 12 "rdp_login_success" "remote_login_success" "\\127.0.0.1\IPC$" {
    cmd /c "net use \\127.0.0.1\IPC$ /user:intruder P@ssw0rd!"
} $true "Logon Success: RDP"

net user intruder /delete 2>$null

# Stage 13
Invoke-Stage 13 "local_account_creation" "account_creation" "intruder" {
    net user intruder P@ssw0rd! /add
    net localgroup Administrators intruder /add
} $true "Account Create: intruder"

# Stage 14
Invoke-Stage 14 "privilege_check" "privilege_enumeration" "whoami" {
    whoami /groups | Out-Null
} $true "Process Create: whoami.exe"

# Stage 15
Invoke-Stage 15 "temporary_cleanup_1" "file_deletion" $Pcap1 {
    cmd /c "del /f `"$Pcap1`""
} $true "File Delete: cacheA.dat"

# Stage 16
Invoke-Stage 16 "temporary_cleanup_2" "file_deletion" $Analysis {
    cmd /c "del /f `"$Analysis`""
} $true "File Delete: diet.log"
 
# Stage 17
Invoke-Stage 17 "tool_removal_attempt" "tool_cleanup" $Sniffer {
    Start-Process cmd -ArgumentList "/c del /f `"$Sniffer`"" -Wait
} $true "Process Create: cmd.exe del"

# Stage 18
Invoke-Stage 18 "session_termination" "process_exit" $null {
    Write-Host "Session Ended"
} $false "Process Exit"




# ==============================
# Save GT
# ==============================
Show-Summary
$Global:GT.total_stages = $Global:GT.records.Count
$Global:GT | ConvertTo-Json -Depth 6 | Out-File $GTPath -Encoding UTF8
Write-Host "GT saved to $GTPath" -ForegroundColor Yello