param(
    [string]$ScenarioPath = ".\scenario10.json"
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
# {0CCE9215} Logon            (4624)
# {0CCE9216} Logoff           (4634, 4647)
# {0CCE922B} Process Creation (4688)
# {0CCE921D} File System      (4663)
# {0CCE9223} Handle Manip.    (4656)
# {0CCE921C} Special Logon    (4672)
# ==============================
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# {0CCE921B} = Special Logon (4672)

# ==============================
# Load Scenario JSON
# ==============================
if (-not (Test-Path $ScenarioPath)) {
    Write-Error "Scenario file not found: $ScenarioPath"
    exit
}

$Scenario  = (Get-Content $ScenarioPath -Raw -Encoding UTF8) | ConvertFrom-Json
$Artifacts = $Scenario.artifacts_definition

if (-not $Artifacts -or -not $Artifacts.base_directory) {
    Write-Error "artifacts_definition 파싱 실패. JSON 구조를 확인하세요."
    exit
}

# Artifact 경로 정의
$MuseumCacheDir  = "C:\ProgramData\MuseumCache"
$BaseDir         = $Artifacts.base_directory
$ReconScript     = $Artifacts.recon_script
$SecurityMapDat  = $Artifacts.security_map_log
$DomainLayoutTmp = $Artifacts.domain_recon_log
$ShareReconLog   = $Artifacts.share_recon_log
$MonitoringLog   = $Artifacts.monitoring_log

# ==============================
# 공유 데이터 (stage 간 공유)
# ==============================
$Global:DomainInfo = @{ domain = ""; status = ""; workstation = ""; dclist = ""; dsgetdc = "" }
$Global:GroupInfo  = @{ domain_admins = ""; local_admins = ""; groups = ""; priv = ""; is_admin = $false }
$Global:SecInfo    = @{ found = @(); windefend = ""; sysmon64 = ""; defender_rt = "" }
$Global:ShareInfo  = @{ local = ""; view = ""; ipc = ""; admin = ""; c_share = "" }
$Global:PolicyInfo = @{ log_count = 0; security = ""; sysmon = ""; gli = ""; auditpol = "" }

# 디렉터리 생성
@($MuseumCacheDir, "C:\GT") | ForEach-Object {
    if ($_ -and -not (Test-Path $_)) {
        New-Item $_ -ItemType Directory -Force | Out-Null
    }
}

# 기존 artifact 사전 정리
@($ReconScript, $SecurityMapDat, $DomainLayoutTmp, $ShareReconLog, $MonitoringLog) |
    ForEach-Object { Remove-Item $_ -Force -ErrorAction SilentlyContinue }

# ==============================
# SACL - 파일 시스템
# ==============================
function Set-DirSacl {
    param([string]$Path)
    try {
        $acl   = Get-Acl $Path
        $audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",
            "Write,Delete,ReadAndExecute,CreateFiles,AppendData",
            "ContainerInherit,ObjectInherit",
            "None",
            "Success,Failure"
        )
        $acl.AddAuditRule($audit)
        Set-Acl $Path $acl
        Write-Host "[SACL] 감사 규칙 설정 완료: $Path" -ForegroundColor Green
    } catch {
        Write-Host "[SACL] 감사 규칙 설정 실패 ($Path): $_" -ForegroundColor Yellow
    }
}

Set-DirSacl $MuseumCacheDir
Start-Sleep -Seconds 2

# ==============================
# GT Structure
# ==============================
$GTDir  = "C:\GT"
$GTPath = "$GTDir\ground_truth_scenario10.json"

$Global:GT = @{
    schema_version = "2.0"
    scenario_name  = $Scenario.scenario_name
    scenario_id    = $Scenario.scenario_id
    user           = $env:USERNAME
    host           = $env:COMPUTERNAME
    generated_at   = (Get-Date).ToString("o")
    records        = [System.Collections.ArrayList]::new()
}

# AllowedID 집합 구성
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

        $fSec = [System.Collections.ArrayList]::new()
        Add-ToList $fSec ($events.security | Where-Object { [int]$_ -in $expectedSec } | Sort-Object -Unique)
        $events.security = $fSec

        $fSys = [System.Collections.ArrayList]::new()
        Add-ToList $fSys ($events.sysmon | Where-Object { [int]$_ -in $expectedSys } | Sort-Object -Unique)
        $events.sysmon = $fSys
    }

    [void]$Global:GT.records.Add([ordered]@{
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
    })

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
# audit_update.ps1 스크립트 내용
# ==============================
$ReconScriptContent = @'
# audit_update.ps1
# Internal compliance audit - do not modify
param([string]$Mode = "scan", [string]$Target = "")

$ErrorActionPreference = "SilentlyContinue"
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Output "[*] Museum audit scan started: $ts"
Write-Output "[*] Host: $env:COMPUTERNAME | User: $env:USERNAME | Mode: $Mode"

if ($Mode -eq "scan") {
    Get-Process | Select-Object -First 3 | Out-Null
    Get-Service | Where-Object { $_.Status -eq "Running" } | Measure-Object | Out-Null
    Write-Output "[*] Baseline scan complete."
}
Write-Output "[*] Audit finished: $(Get-Date -Format 'HH:mm:ss')"
'@

# ===================================================
# STAGE FLOW
# ===================================================

# --------------------------------------------------
# Stage 1: authorized_logon (attack: false)
# 4624 - 스크립트 실행 시작 전 세션 기록
# --------------------------------------------------
Invoke-Stage 1 "authorized_logon" "user_logon" `
    $null {

    Write-Host "  [INFO] 정상 세션 기준점 생성 (4624 이미 기록됨)" -ForegroundColor Gray
    Write-Host "  [INFO] User: $env:USERDOMAIN\$env:USERNAME | Host: $env:COMPUTERNAME" -ForegroundColor Gray

    $logonSession = Get-WmiObject Win32_LogonSession -ErrorAction SilentlyContinue |
        Where-Object { $_.LogonType -in 2, 3, 10, 11 } |
        Sort-Object StartTime -Descending |
        Select-Object -First 1
    $lid = if ($logonSession) { $logonSession.LogonId } else { "N/A" }
    Write-Host "  [INFO] LogonId: $lid" -ForegroundColor Gray

    Start-Sleep -Seconds 5

} $false "Logon: Security 4624 (already recorded at session start)"


# --------------------------------------------------
# Stage 2: recon_script_deployment
# T1059.001 - PowerShell
# audit_update.ps1 생성 → Sysmon 11
# powershell.exe 실행 → 4688 + Sysmon 1
# --------------------------------------------------
Invoke-Stage 2 "recon_script_deployment" "script_deployment" `
    $ReconScript {

    if (-not (Test-Path $MuseumCacheDir)) {
        New-Item $MuseumCacheDir -ItemType Directory -Force | Out-Null
    }

    # audit_update.ps1 생성 → Sysmon 11
    Set-Content -Path $ReconScript -Value $ReconScriptContent -Encoding UTF8
    Write-Host "  [DEPLOY] audit_update.ps1 생성: $ReconScript" -ForegroundColor Gray

    # powershell.exe 실행 → 4688 + Sysmon 1
    $execProc = Start-Process powershell.exe `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ReconScript`"" `
        -PassThru -Wait -WindowStyle Hidden
    Write-Host "  [EXEC] powershell.exe -File audit_update.ps1 PID=$($execProc.Id) Exit=$($execProc.ExitCode)" -ForegroundColor Gray

} $true "File Create (Sysmon 11): audit_update.ps1 + Process Create (4688 / Sysmon 1): powershell.exe"


# --------------------------------------------------
# Stage 3: hidden_operational_directory_creation
# T1564.001 - Hide Artifacts
# BaseDir({A92D1F}) 생성 + Hidden/System 속성
# MuseumCacheDir SACL 적용 → 4663
# Sysmon 11
# --------------------------------------------------
Invoke-Stage 3 "hidden_operational_directory_creation" "hidden_directory_creation" `
    $BaseDir {

    if (-not (Test-Path $BaseDir)) {
        New-Item $BaseDir -ItemType Directory -Force | Out-Null
        Write-Host "  [CREATE] 숨김 디렉터리 생성: $BaseDir" -ForegroundColor Gray
    } else {
        Write-Host "  [EXIST] 숨김 디렉터리 이미 존재: $BaseDir" -ForegroundColor Yellow
    }

    # Hidden + System 속성 설정 (T1564.001)
    $dirItem = Get-Item $BaseDir -Force
    $dirItem.Attributes = $dirItem.Attributes `
        -bor [System.IO.FileAttributes]::Hidden `
        -bor [System.IO.FileAttributes]::System
    Write-Host "  [ATTR] Hidden + System 속성 설정 완료. Attributes=$($dirItem.Attributes)" -ForegroundColor Gray

    $parentItem = Get-Item $MuseumCacheDir -Force
    $parentItem.Attributes = $parentItem.Attributes `
        -bor [System.IO.FileAttributes]::Hidden `
        -bor [System.IO.FileAttributes]::System
    Write-Host "  [ATTR] 상위 디렉터리 Hidden + System 설정. Attributes=$($parentItem.Attributes)" -ForegroundColor Gray

    # BaseDir SACL 추가 적용 (Stage 9 파일 생성 시 4663 유발)
    Set-DirSacl $BaseDir

    # 디렉터리 Write 접근으로 4663 유발 확인용 임시 파일
    [System.IO.File]::WriteAllText("$BaseDir\.dirmark", "") | Out-Null
    Start-Sleep -Milliseconds 300
    Remove-Item "$BaseDir\.dirmark" -Force -ErrorAction SilentlyContinue

} $true "File Create (Sysmon 11) + Object Access (4663 via SACL): Hidden dir creation"


# --------------------------------------------------
# Stage 4: domain_structure_reconnaissance
# T1482 - Domain Trust Discovery
# nltest.exe /dclist: /dsgetdc: → 4688 + Sysmon 1
# Resolve-DnsName → Sysmon 22
# --------------------------------------------------
Invoke-Stage 4 "domain_structure_reconnaissance" "domain_reconnaissance" `
    $null {

    # DNS 캐시 초기화 (EID 22 발생 보장)
    ipconfig /flushdns 2>&1 | Out-Null
    Write-Host "  [*] DNS 캐시 초기화 완료" -ForegroundColor Gray
    Start-Sleep -Milliseconds 500


    Write-Host "  [RECON] nltest.exe /dclist: → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:DomainInfo["dclist"] = (& nltest.exe /dclist: 2>&1 | Out-String).Trim()
    Write-Host "  [RECON] nltest result: $($Global:DomainInfo['dclist'].Substring(0,[Math]::Min(80,$Global:DomainInfo['dclist'].Length)))" -ForegroundColor Gray

    Start-Sleep -Milliseconds 500

    Write-Host "  [RECON] nltest.exe /dsgetdc: → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:DomainInfo["dsgetdc"] = (& nltest.exe /dsgetdc: 2>&1 | Out-String).Trim()

    Write-Host "  [RECON] net.exe config workstation → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:DomainInfo["workstation"] = (& net.exe config workstation 2>&1 | Out-String).Trim()

    # DNS 쿼리 대상 구성
    $dnsTargets = @()
    if ($env:USERDNSDOMAIN) {
        $dnsTargets += $env:USERDNSDOMAIN
        $dnsTargets += "dc.$env:USERDNSDOMAIN"
        $dnsTargets += "ldap.$env:USERDNSDOMAIN"
    }
    # 독립 VM 환경: FQDN으로 DNS 강제 쿼리
    if ($dnsTargets.Count -eq 0) {
        $dnsTargets += @("cloudflare.com", "github.com", "google.com")
    }

    foreach ($t in $dnsTargets) {
        Resolve-DnsName -Name $t -Type A -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  [DNS] Resolve-DnsName: $t (Sysmon 22)" -ForegroundColor Gray
    }

    $Global:DomainInfo["domain"] = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { "WORKGROUP" }
    $Global:DomainInfo["status"] = if ($env:USERDNSDOMAIN) { "DOMAIN_JOINED" } else { "STANDALONE" }
    Write-Host "  [RECON] Domain status: $($Global:DomainInfo['status'])" -ForegroundColor Gray


} $true "Process Create (4688 / Sysmon 1): nltest.exe x2 + net.exe + Dns Query (Sysmon 22): Resolve-DnsName"


# --------------------------------------------------
# Stage 5: privileged_group_mapping
# T1087.002 - Account Discovery
# net.exe group/localgroup/whoami → 4688 + Sysmon 1
# --------------------------------------------------
Invoke-Stage 5 "privileged_group_mapping" "account_discovery" `
    $null {
    Write-Host "  [RECON] net.exe group 'Domain Admins' /domain → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:GroupInfo["domain_admins"] = (& net.exe group "Domain Admins" /domain 2>&1 | Out-String).Trim()
    Write-Host "  [RECON] net.exe localgroup Administrators → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:GroupInfo["local_admins"] = (& net.exe localgroup Administrators 2>&1 | Out-String).Trim()
    Write-Host "  [RECON] whoami.exe /groups → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:GroupInfo["groups"] = (& whoami.exe /groups 2>&1 | Out-String).Trim()
    Write-Host "  [RECON] whoami.exe /priv → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:GroupInfo["priv"] = (& whoami.exe /priv 2>&1 | Out-String).Trim()

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    $Global:GroupInfo["is_admin"] = $isAdmin
    Write-Host "  [INFO] IsAdministrator: $isAdmin" -ForegroundColor Gray

    # ── EID 4672 트리거 ──
    # SYSTEM 계정으로 Scheduled Task 실행 → 새 로그온 세션 생성
    # SYSTEM = SeDebugPrivilege 등 특권 보유 → 4624(Type5) + 4672 확실 발생
    $taskName = "ReconAudit_Priv_$(Get-Random -Maximum 9999)"
    Write-Host "  [*] EID 4672 트리거 목적 SYSTEM 로그온 생성..." -ForegroundColor Gray

    schtasks /create /tn $taskName `
             /tr "cmd.exe /c whoami" `
             /sc once /st 00:00 `
             /ru SYSTEM /f 2>$null | Out-Null

    schtasks /run /tn $taskName 2>$null | Out-Null
    Start-Sleep -Seconds 3

    schtasks /delete /tn $taskName /f 2>$null | Out-Null
    Write-Host "  [+] SYSTEM 로그온 실행 완료 → Security EID 4624(Type5) + 4672 발생" -ForegroundColor Green

} $true "Process Create (4688 / Sysmon 1): net.exe x2 + whoami.exe x2 / Security EID 4672: SYSTEM Special Logon"


# --------------------------------------------------
# Stage 6: security_monitoring_recon
# T1518.001 - Software Discovery
# tasklist.exe / sc.exe query → 4688 + Sysmon 1
# --------------------------------------------------
Invoke-Stage 6 "security_monitoring_recon" "security_software_discovery" `
    $null {

    Write-Host "  [RECON] tasklist.exe /svc → 4688 + Sysmon 1" -ForegroundColor Gray
    & tasklist.exe /svc 2>&1 | Out-Null

    $secProcNames = @(
        "MsMpEng", "NisSrv", "MsSense", "SenseNdr",
        "csagent", "csfalcon", "SentinelAgent", "SentinelServiceHost",
        "cylancesvc", "cb", "bdagent", "ekrn", "avgnt",
        "Sysmon", "Sysmon64", "taniumclient", "elastic-agent"
    )
    $found = @()
    foreach ($pn in $secProcNames) {
        $p = Get-Process -Name $pn -ErrorAction SilentlyContinue
        if ($p) {
            $found += "$pn(PID:$($p.Id))"
            Write-Host "  [FOUND] 보안 프로세스 탐지: $pn (PID=$($p.Id))" -ForegroundColor Yellow
        }
    }
    $Global:SecInfo["found"] = $found

    Write-Host "  [RECON] sc.exe query WinDefend → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:SecInfo["windefend"] = (& sc.exe query WinDefend 2>&1 | Out-String).Trim()

    Write-Host "  [RECON] sc.exe query Sysmon64 → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:SecInfo["sysmon64"] = (& sc.exe query Sysmon64 2>&1 | Out-String).Trim()

    try {
        $mp = Get-MpPreference -ErrorAction SilentlyContinue
        $Global:SecInfo["defender_rt"] = if ($mp) { "DisableRealtime=$($mp.DisableRealtimeMonitoring)" } else { "N/A" }
    } catch { $Global:SecInfo["defender_rt"] = "query_failed" }

    Write-Host "  [INFO] Defender RT: $($Global:SecInfo['defender_rt'])" -ForegroundColor Gray
    Write-Host "  [INFO] Found security processes: $(if($found){$found -join ', '}else{'none'})" -ForegroundColor Gray

} $true "Process Create (4688 / Sysmon 1): tasklist.exe + sc.exe x2"


# --------------------------------------------------
# Stage 7: administrative_share_recon
# T1135 - Network Share Discovery
# net.exe share/view → 4688 + Sysmon 1
# net use IPC$ / New-PSDrive ADMIN$ → Sysmon 3 (TCP/445)
# --------------------------------------------------
Invoke-Stage 7 "administrative_share_recon" "network_share_discovery" `
    $null {

    Write-Host "  [RECON] net.exe share → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:ShareInfo["local"] = (& net.exe share 2>&1 | Out-String).Trim()

    Write-Host "  [RECON] net.exe view \\$env:COMPUTERNAME → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:ShareInfo["view"] = (& net.exe view "\\$env:COMPUTERNAME" 2>&1 | Out-String).Trim()

    Write-Host "  [SMB]   net.exe use IPC$ → Sysmon 3 (TCP/445)" -ForegroundColor Gray
    $Global:ShareInfo["ipc"] = (& net.exe use "\\$env:COMPUTERNAME\IPC$" 2>&1 | Out-String).Trim()
    Write-Host "  [SMB]   IPC$ result: $($Global:ShareInfo['ipc'])" -ForegroundColor Gray
    Start-Sleep -Milliseconds 500

    Write-Host "  [SMB]   ADMIN$ PSDrive 접근 시도 → Sysmon 3 (TCP/445)" -ForegroundColor Gray
    try {
        $drv = New-PSDrive -Name "TmpAdm" -PSProvider FileSystem `
            -Root "\\$env:COMPUTERNAME\ADMIN$" -ErrorAction Stop
        $Global:ShareInfo["admin"] = "SUCCESS"
        Write-Host "  [SMB]   ADMIN$ 접근 성공" -ForegroundColor Gray
        Get-ChildItem -Path "TmpAdm:" -ErrorAction SilentlyContinue | Select-Object -First 3 | Out-Null
        Remove-PSDrive -Name "TmpAdm" -Force -ErrorAction SilentlyContinue
    } catch {
        $Global:ShareInfo["admin"] = "ACCESS_DENIED"
        Write-Host "  [SMB]   ADMIN$ 접근 실패 (ACCESS_DENIED) - Sysmon 3 기록됨" -ForegroundColor Yellow
    }

    try {
        $drv2 = New-PSDrive -Name "TmpC" -PSProvider FileSystem `
            -Root "\\$env:COMPUTERNAME\C$" -ErrorAction Stop
        $Global:ShareInfo["c_share"] = "SUCCESS"
        Remove-PSDrive -Name "TmpC" -Force -ErrorAction SilentlyContinue
    } catch { $Global:ShareInfo["c_share"] = "FAILED" }
    Write-Host "  [SMB]   C$ result: $($Global:ShareInfo['c_share'])" -ForegroundColor Gray

    & net.exe use "\\$env:COMPUTERNAME\IPC$" /delete 2>&1 | Out-Null

} $true "Process Create (4688 / Sysmon 1): net.exe x2 + NetworkConnect (Sysmon 3): IPC ADMIN C TCP445"


# --------------------------------------------------
# Stage 8: eventlog_policy_inspection
# T1082 - System Information Discovery
# wevtutil.exe / auditpol.exe → 4688 + Sysmon 1
# --------------------------------------------------
Invoke-Stage 8 "eventlog_policy_inspection" "policy_discovery" `
    $null {

    Write-Host "  [RECON] wevtutil.exe el → 4688 + Sysmon 1" -ForegroundColor Gray
    $wevtList = & wevtutil.exe el 2>&1
    $Global:PolicyInfo["log_count"] = ($wevtList | Measure-Object -Line).Lines
    Write-Host "  [RECON] 전체 이벤트 로그 수: $($Global:PolicyInfo['log_count'])" -ForegroundColor Gray

    Write-Host "  [RECON] wevtutil.exe gl Security → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:PolicyInfo["security"] = (& wevtutil.exe gl Security 2>&1 | Out-String).Trim()

    Write-Host "  [RECON] wevtutil.exe gl Sysmon/Operational → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:PolicyInfo["sysmon"] = (& wevtutil.exe gl "Microsoft-Windows-Sysmon/Operational" 2>&1 | Out-String).Trim()

    Write-Host "  [RECON] wevtutil.exe gli Security → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:PolicyInfo["gli"] = (& wevtutil.exe gli Security 2>&1 | Out-String).Trim()

    Write-Host "  [RECON] auditpol.exe /get /category:* → 4688 + Sysmon 1" -ForegroundColor Gray
    $Global:PolicyInfo["auditpol"] = (& auditpol.exe /get /category:"*" 2>&1 | Out-String).Trim()

} $true "Process Create (4688 / Sysmon 1): wevtutil.exe x3 + auditpol.exe"


# --------------------------------------------------
# Stage 9: operational_recon_result_staging
# T1074 - Data Staged
# 4개 파일 생성 → Sysmon 11 (FileCreate x4)
# BaseDir SACL → 4663 (Write/Object Access)
# --------------------------------------------------
Invoke-Stage 9 "operational_recon_result_staging" "data_staging" `
    @($SecurityMapDat, $DomainLayoutTmp, $ShareReconLog, $MonitoringLog) {

    $ts9 = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $secMap = @"
[SECURITY_MAP]
Generated  : $ts9
Host       : $env:COMPUTERNAME
User       : $env:USERDOMAIN\$env:USERNAME

[SECURITY_PRODUCTS_FOUND]
$(if($Global:SecInfo.found.Count -gt 0){($Global:SecInfo.found | ForEach-Object{"  - $_"}) -join "`n"}else{"  (none detected)"})

[SERVICE_STATE]
WinDefend  : $($Global:SecInfo.windefend.Substring(0,[Math]::Min(120,$Global:SecInfo.windefend.Length)))
Sysmon64   : $($Global:SecInfo.sysmon64.Substring(0,[Math]::Min(120,$Global:SecInfo.sysmon64.Length)))
DefenderRT : $($Global:SecInfo.defender_rt)
"@
    Set-Content -Path $SecurityMapDat -Value $secMap -Encoding UTF8
    Write-Host "  [STAGE] security_map.dat → $SecurityMapDat (Sysmon 11 + 4663)" -ForegroundColor Gray

    $domLayout = @"
[DOMAIN_LAYOUT]
Generated  : $ts9
Domain     : $($Global:DomainInfo.domain)
Status     : $($Global:DomainInfo.status)

[WORKSTATION_CONFIG]
$($Global:DomainInfo.workstation.Substring(0,[Math]::Min(400,$Global:DomainInfo.workstation.Length)))

[DC_LIST]
$($Global:DomainInfo.dclist.Substring(0,[Math]::Min(300,$Global:DomainInfo.dclist.Length)))
"@
    Set-Content -Path $DomainLayoutTmp -Value $domLayout -Encoding UTF8
    Write-Host "  [STAGE] domain_layout.tmp → $DomainLayoutTmp (Sysmon 11 + 4663)" -ForegroundColor Gray

    $shareCache = @"
[SHARE_ACCESS]
Generated  : $ts9
ADMIN`$     : $($Global:ShareInfo.admin)
C`$         : $($Global:ShareInfo.c_share)
IPC`$       : $($Global:ShareInfo.ipc.Substring(0,[Math]::Min(100,$Global:ShareInfo.ipc.Length)))

[LOCAL_SHARES]
$($Global:ShareInfo.local.Substring(0,[Math]::Min(400,$Global:ShareInfo.local.Length)))
"@
    Set-Content -Path $ShareReconLog -Value $shareCache -Encoding UTF8
    Write-Host "  [STAGE] share_access.cache → $ShareReconLog (Sysmon 11 + 4663)" -ForegroundColor Gray

    $monLog = @"
[MONITORING_STRUCTURE]
Generated  : $ts9

[EVENT_LOG_POLICY]
$($Global:PolicyInfo.security.Substring(0,[Math]::Min(400,$Global:PolicyInfo.security.Length)))

[AUDIT_POLICY_SUMMARY]
$($Global:PolicyInfo.auditpol.Substring(0,[Math]::Min(500,$Global:PolicyInfo.auditpol.Length)))

[PRIVILEGED_GROUP_SUMMARY]
$($Global:GroupInfo.local_admins.Substring(0,[Math]::Min(300,$Global:GroupInfo.local_admins.Length)))
"@
    Set-Content -Path $MonitoringLog -Value $monLog -Encoding UTF8
    Write-Host "  [STAGE] monitoring_structure.log → $MonitoringLog (Sysmon 11 + 4663)" -ForegroundColor Gray

    foreach ($f in @($SecurityMapDat, $DomainLayoutTmp, $ShareReconLog, $MonitoringLog)) {
        [System.IO.File]::ReadAllBytes($f) | Out-Null
    }

} $true "File Create (Sysmon 11 x4) + Object Access (4663 via BaseDir SACL): staging to hidden dir"


# --------------------------------------------------
# Stage 10: selective_artifact_cleanup
# T1070.004 - Indicator Removal: File Deletion
# audit_update.ps1 / share_access.cache 삭제
# cmd.exe 사용 → 4688 + Sysmon 1 + Sysmon 26
# security_map.dat / domain_layout.tmp / monitoring_structure.log 잔존
# --------------------------------------------------
Invoke-Stage 10 "selective_artifact_cleanup" "artifact_cleanup" `
    @($ReconScript, $ShareReconLog) {

    if (Test-Path $ReconScript) {
        cmd /c "del /f /q `"$ReconScript`""
        Start-Sleep -Milliseconds 400
        if (-not (Test-Path $ReconScript)) {
            Write-Host "  [DEL]  audit_update.ps1 삭제 완료 → Sysmon 26" -ForegroundColor Gray
        } else {
            Remove-Item $ReconScript -Force -ErrorAction SilentlyContinue
            Write-Host "  [DEL]  audit_update.ps1 삭제 (fallback)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [WARN] audit_update.ps1 not found (already absent)" -ForegroundColor Yellow
    }

    Start-Sleep -Milliseconds 500

    if (Test-Path $ShareReconLog) {
        cmd /c "del /f /q `"$ShareReconLog`""
        Start-Sleep -Milliseconds 400
        if (-not (Test-Path $ShareReconLog)) {
            Write-Host "  [DEL]  share_access.cache 삭제 완료 → Sysmon 26" -ForegroundColor Gray
        } else {
            Remove-Item $ShareReconLog -Force -ErrorAction SilentlyContinue
            Write-Host "  [DEL]  share_access.cache 삭제 (fallback)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [WARN] share_access.cache not found (already absent)" -ForegroundColor Yellow
    }

    Write-Host "  [RESIDUAL] security_map.dat   : $(if(Test-Path $SecurityMapDat){'EXISTS (잔존)'}else{'GONE'})" -ForegroundColor Yellow
    Write-Host "  [RESIDUAL] domain_layout.tmp  : $(if(Test-Path $DomainLayoutTmp){'EXISTS (잔존)'}else{'GONE'})" -ForegroundColor Yellow
    Write-Host "  [RESIDUAL] monitoring_structure: $(if(Test-Path $MonitoringLog){'EXISTS (잔존)'}else{'GONE'})" -ForegroundColor Yellow
    Write-Host "  [RESIDUAL] {A92D1F} dir        : $(if(Test-Path $BaseDir){'EXISTS (잔존)'}else{'GONE'})" -ForegroundColor Yellow

} $true "File Delete (Sysmon 26 x2) + Process Create (4688 / Sysmon 1): cmd.exe del"


# --------------------------------------------------
# Stage 11: residual_operational_artifacts (attack: false)
# 잔존 artifact 상태 검증
# --------------------------------------------------
Invoke-Stage 11 "residual_operational_artifacts" "residual_artifact" `
    @($SecurityMapDat, $DomainLayoutTmp, $MonitoringLog) {

    Write-Host "  [RESIDUAL] 잔존 artifact 검증" -ForegroundColor Gray
    $checkMap = [ordered]@{
        "security_map.dat         (잔존 예상)" = $SecurityMapDat
        "domain_layout.tmp        (잔존 예상)" = $DomainLayoutTmp
        "monitoring_structure.log (잔존 예상)" = $MonitoringLog
        "hidden dir {A92D1F}      (잔존 예상)" = $BaseDir
        "audit_update.ps1         (삭제 예상)" = $ReconScript
        "share_access.cache       (삭제 예상)" = $ShareReconLog
    }
    foreach ($entry in $checkMap.GetEnumerator()) {
        $exists = Test-Path $entry.Value
        $state  = if ($exists) { "EXISTS" } else { "ABSENT" }
        $color  = if ($exists) { "Green" } else { "DarkGray" }
        Write-Host ("    {0,-50} {1}" -f $entry.Key, $state) -ForegroundColor $color
    }

} $false "Residual: security_map.dat + domain_layout.tmp + monitoring_structure.log + {A92D1F} dir 잔존"


# --------------------------------------------------
# Stage 12: session_termination (attack: false)
# 4634/4647은 실제 로그오프 시 발생
# --------------------------------------------------
Invoke-Stage 12 "session_termination" "session_logoff" `
    $null {

    Write-Host "  [INFO] Scenario complete." -ForegroundColor Gray
    Write-Host "  [INFO] EID 4634/4647: 실제 로그오프 시 자동 기록됨" -ForegroundColor Gray
    Write-Host "  [INFO] 잔존 artifact는 DFIR 분석 목적으로 보존됨" -ForegroundColor Gray

} $false "Logoff: Security 4634/4647 (recorded on actual session end)"


# ==============================
# Show Summary
# ==============================
Show-Summary


# ==============================
# Save GT
# ==============================
$Global:GT.total_stages = $Global:GT.records.Count
$Global:GT | ConvertTo-Json -Depth 6 | Out-File $GTPath -Encoding UTF8
Write-Host ""
Write-Host "GT saved → $GTPath" -ForegroundColor Yellow