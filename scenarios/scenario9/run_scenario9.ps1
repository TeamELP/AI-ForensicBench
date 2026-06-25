param(
    [string]$ScenarioPath = ".\scenario9.json"
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
# Logon / Logoff (4624, 4634)
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# Process Creation (4688)
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# Security System Extension (4697)
auditpol /set /subcategory:"{0CCE9211-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# Handle Manipulation (4656)
auditpol /set /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
# Kernel Object
auditpol /set /subcategory:"{0CCE9222-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

# ==============================
# Load Scenario JSON
# ==============================
if (-not (Test-Path $ScenarioPath)) {
    Write-Error "Scenario file not found: $ScenarioPath"
    exit
}

$Scenario = Get-Content $ScenarioPath -Raw -Encoding UTF8 | ConvertFrom-Json
$Artifacts = $Scenario.artifacts_definition

if (-not $Artifacts -or -not $Artifacts.driver_directory) {
    Write-Error "artifacts_definition 파싱 실패. JSON 구조를 확인하세요."
    exit
}

$DriverDir    = $Artifacts.driver_directory
$DriverFile   = $Artifacts.driver_file
$HelperLoader = $Artifacts.helper_loader
$MemoryTool   = $Artifacts.memory_tool
$TempLog      = $Artifacts.temporary_log
$CredDumpSim  = $Artifacts.credential_dump_simulation
$ServiceName  = $Artifacts.service_name

# 작업 디렉터리 생성
if (-not (Test-Path $DriverDir)) {
    New-Item $DriverDir -ItemType Directory -Force | Out-Null
}

# ==============================
# SACL - 파일 시스템
# ==============================
try {
    $acl   = Get-Acl $DriverDir
    $audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
        "Everyone", "FullControl",
        "ContainerInherit,ObjectInherit", "None", "Success,Failure"
    )
    $acl.AddAuditRule($audit)
    Set-Acl $DriverDir $acl
    Write-Host "[SACL] 파일 감사 규칙 설정 완료: $DriverDir" -ForegroundColor Green
    Start-Sleep -Seconds 3
} catch {
    Write-Host "[SACL] 파일 감사 규칙 설정 실패: $_" -ForegroundColor Yellow
}

# ==============================
# SACL - 레지스트리
# ==============================
try {
    $regPath  = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $regAcl   = Get-Acl $regPath
    $regAudit = New-Object System.Security.AccessControl.RegistryAuditRule(
        "Everyone", "SetValue,Delete,CreateSubKey",
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
$GTPath = "$GTDir\ground_truth_scenario9.json"

if (-not (Test-Path $GTDir)) { New-Item $GTDir -ItemType Directory -Force | Out-Null }

$Global:GT = @{
    schema_version = "2.0"
    scenario_id    = $Scenario.scenario_id
    scenario_name  = $Scenario.scenario_name
    user           = $env:USERNAME
    host           = $env:COMPUTERNAME
    generated_at   = (Get-Date).ToString("o")
    records        = [System.Collections.ArrayList]::new()   # [FIX] ArrayList 사용
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
# PrivilegeHelper P/Invoke (스크립트 전역)
# ==============================
if (-not ([System.Management.Automation.PSTypeName]'PrivilegeHelper').Type) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;

public class PrivilegeHelper {
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr hProcess, uint access, out IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(
        IntPtr hToken, bool disableAll,
        ref TOKEN_PRIVILEGES newState,
        uint bufLen, IntPtr prevState, IntPtr retLen);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY             = 0x0008;
    const uint SE_PRIVILEGE_ENABLED    = 0x00000002;

    public static bool Enable(string privilegeName) {
        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            return false;

        LUID luid;
        if (!LookupPrivilegeValue(null, privilegeName, out luid))
            return false;

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES {
            PrivilegeCount = 1,
            Luid           = luid,
            Attributes     = SE_PRIVILEGE_ENABLED
        };
        return AdjustTokenPrivileges(hToken, false, ref tp, 0,
                                     IntPtr.Zero, IntPtr.Zero);
    }
}
"@
}

# ==============================
# NtLoadDriver / NtUnloadDriver P/Invoke (스크립트 전역)
# ==============================
if (-not ([System.Management.Automation.PSTypeName]'NtDrvLoader').Type) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;

public class NtDrvLoader {
    [DllImport("ntdll.dll")]
    public static extern uint NtLoadDriver(ref UNICODE_STRING svcName);

    [DllImport("ntdll.dll")]
    public static extern uint NtUnloadDriver(ref UNICODE_STRING svcName);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Buffer;
    }

    public static uint Load(string regPath) {
        UNICODE_STRING us = new UNICODE_STRING {
            Length        = (ushort)(regPath.Length * 2),
            MaximumLength = (ushort)((regPath.Length + 1) * 2),
            Buffer        = regPath
        };
        return NtLoadDriver(ref us);
    }

    public static uint Unload(string regPath) {
        UNICODE_STRING us = new UNICODE_STRING {
            Length        = (ushort)(regPath.Length * 2),
            MaximumLength = (ushort)((regPath.Length + 1) * 2),
            Buffer        = regPath
        };
        return NtUnloadDriver(ref us);
    }
}
"@
}

# ==============================
# ProcAccess P/Invoke (스크립트 전역)
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
            Where-Object { [int]$_.Id -in $AllowedSecurityIDs }
        Add-ToList $securityIds ($sec | Select-Object -ExpandProperty Id -Unique)
    } catch {}

    try {
        $sys = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            StartTime = $Start
            EndTime   = $End
        } -ErrorAction SilentlyContinue |
            Where-Object { [int]$_.Id -in $AllowedSysmonIDs }
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

    Write-Host ""
    Write-Host "===== Stage $StageId : $StageName =====" -ForegroundColor Cyan

    $stageMeta = $Scenario.scenario_flow | Where-Object { $_.stage_id -eq $StageId }

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
        $expSec = @()
        $expSys = @()
        if ($stageMeta.expected_logs.security) {
            $expSec = @($stageMeta.expected_logs.security | ForEach-Object { [int]$_ })
        }
        if ($stageMeta.expected_logs.sysmon) {
            $expSys = @($stageMeta.expected_logs.sysmon | ForEach-Object { [int]$_ })
        }

        $fSec = [System.Collections.ArrayList]::new()
        Add-ToList $fSec ($events.security | Where-Object { [int]$_ -in $expSec } | Sort-Object -Unique)
        $events.security = $fSec

        $fSys = [System.Collections.ArrayList]::new()
        Add-ToList $fSys ($events.sysmon | Where-Object { [int]$_ -in $expSys } | Sort-Object -Unique)
        $events.sysmon = $fSys
    }

    # [FIX] += 대신 ArrayList.Add() 사용
    [void]$Global:GT.records.Add([ordered]@{
        stage_id           = $StageId
        stage_name         = $StageName
        action_type        = if ($stageMeta) { $stageMeta.action_type } else { $ActionType }
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
# Summary
# ==============================
function Show-Summary {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor White
    Write-Host "  STAGE SUMMARY" -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
    foreach ($s in $Global:StageSummary) {
        $icon  = switch ($s.Status) {
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

# ===================================================
# STAGE FLOW
# ===================================================

# --------------------------------------------------
# Stage 1 : authorized_logon
# 공격 시작 전 정상 로그온 세션 생성
# Security EID 4624
# --------------------------------------------------
Invoke-Stage 1 "authorized_logon" "user_logon" `
    @("정상 사용자 세션 생성") {

    Write-Host "  [*] 정상 로그온 세션 baseline 기록" -ForegroundColor Gray
    Start-Sleep -Seconds 2

} $false "Security EID 4624: Logon"

# --------------------------------------------------
# Stage 2 : privilege_validation
# T1033 - System Owner/User Discovery
# Security EID 4688 / Sysmon EID 1
# --------------------------------------------------
Invoke-Stage 2 "privilege_validation" "privilege_validation" `
    @("whoami /priv 실행 흔적", "whoami /groups 실행 흔적") {

    Start-Process -FilePath "whoami.exe" -ArgumentList "/priv" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] whoami /priv 완료" -ForegroundColor Gray

    Start-Process -FilePath "whoami.exe" -ArgumentList "/groups" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] whoami /groups 완료" -ForegroundColor Gray

    Start-Process -FilePath "net.exe" -ArgumentList "session" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] net session 완료" -ForegroundColor Gray

} $true "Security EID 4688 / Sysmon EID 1: whoami.exe privilege enumeration"

# --------------------------------------------------
# Stage 3 : security_product_discovery
# T1518.001 - Security Software Discovery
# Security EID 4688 / Sysmon EID 1
# --------------------------------------------------
Invoke-Stage 3 "security_product_discovery" "security_software_discovery" `
    @("sc query WinDefend", "sc query Sense", "Get-MpComputerStatus") {

    Start-Process -FilePath "sc.exe" -ArgumentList "query WinDefend" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] sc query WinDefend 완료" -ForegroundColor Gray

    Start-Process -FilePath "sc.exe" -ArgumentList "query Sense" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] sc query Sense 완료" -ForegroundColor Gray

    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoProfile -Command `"Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled | Out-Null`"" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] Get-MpComputerStatus 완료" -ForegroundColor Gray

} $true "Security EID 4688 / Sysmon EID 1: sc.exe WinDefend/Sense + powershell.exe Get-MpComputerStatus"

# --------------------------------------------------
# Stage 4 : driver_staging
# T1105 - Ingress Tool Transfer
# Sysmon EID 11 (FileCreate) / Security EID 4688
# --------------------------------------------------
Invoke-Stage 4 "driver_staging" "driver_staging" `
    @($DriverDir, $DriverFile, $HelperLoader, $MemoryTool) {

    # ============================================================
    # 드라이버 선택 전략
    # EID 6 발생 조건:
    #   1) NtLoadDriver 성공 (0x00000000)
    #      → 미실행 + 무종속 드라이버여야 함
    #   2) Sysmon exclude 미해당
    #      → 비 MS/Windows/Intel 서명이어야 함
    # ============================================================

    # Step A: 실행 중인 드라이버 경로 수집
    $runningPaths = @(
        Get-WmiObject Win32_SystemDriver -EA SilentlyContinue |
        Where-Object { $_.State -eq "Running" } |
        ForEach-Object {
            try {
                (Get-Item (
                    ($_.PathName -replace '\\\\?\\.\\','') `
                               -replace '\\SystemRoot\\',"$env:SystemRoot\"
                ) -EA SilentlyContinue).FullName
            } catch { $null }
        } | Where-Object { $_ }
    )
    Write-Host "  [*] 실행 중인 커널 드라이버 수: $($runningPaths.Count)" -ForegroundColor Gray

    # Step B: 알려진 비 MS 서명 드라이버 직접 탐색 (최우선)
    # VirtualBox(Oracle), VMware non-WHCP 등 명시적 경로
    $knownNonMS = @(
        # VirtualBox (Oracle 서명 → Sysmon exclude 미해당)
        "C:\Program Files\Oracle\VirtualBox\drivers\vboxdrv\VBoxDrv.sys",
        "C:\Program Files\Oracle\VirtualBox\drivers\vboxdrv\VBoxDrvU.sys",
        "C:\Program Files\Oracle\VirtualBox\drivers\network\netadp6\VBoxNetAdp6.sys",
        "C:\Program Files\Oracle\VirtualBox\drivers\network\netlwf\VBoxNetLwf.sys",
        # 기타 서드파티 드라이버 후보
        "C:\Program Files\Wireshark\npcap\npf.sys",
        "C:\Program Files\Npcap\npcap.sys"
    )

    $sourceDriver  = $null
    $fallbackDriver = $null  # 무종속이나 MS 서명 (2순위)

    foreach ($candidate in $knownNonMS) {
        if (-not (Test-Path $candidate -EA SilentlyContinue)) { continue }

        $normPath  = (Get-Item $candidate -EA SilentlyContinue).FullName
        $isRunning = $runningPaths -contains $normPath
        if ($isRunning) {
            Write-Host "  [*] 실행 중 스킵: $candidate" -ForegroundColor DarkGray
            continue
        }

        $sig = (Get-AuthenticodeSignature $candidate -EA SilentlyContinue
               ).SignerCertificate.Subject
        Write-Host "  [+] 후보 발견: $([System.IO.Path]::GetFileName($candidate))" -ForegroundColor Green
        Write-Host "      서명: $sig" -ForegroundColor Green
        $sourceDriver = $candidate
        break
    }

    # Step C: 레지스트리 동적 탐색 (Step B 실패 시)
    if (-not $sourceDriver) {
        Write-Host "  [*] 알려진 후보 없음. 레지스트리 동적 탐색 시작..." -ForegroundColor Gray

        Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -EA SilentlyContinue |
        ForEach-Object {
            if ($sourceDriver) { return }
            try {
                $svcProp = Get-ItemProperty $_.PSPath -EA SilentlyContinue

                # Type=1 (커널 드라이버)만 대상
                if ($null -eq $svcProp.Type -or [int]$svcProp.Type -ne 1) { return }

                $imgRaw = $svcProp.ImagePath
                if (-not $imgRaw) { return }

                # 경로 정규화 (따옴표 먼저 제거 → \SystemRoot\ → \??\)
                $imgPath = $imgRaw `
                    -replace '"',              '' `
                    -replace '\\SystemRoot\\', "$env:SystemRoot\" `
                    -replace '^\\\?\?\\',      ''
                $imgPath = $imgPath.Trim()

                if (-not (Test-Path $imgPath -EA SilentlyContinue)) { return }

                $normImg   = (Get-Item $imgPath -EA SilentlyContinue).FullName
                $isRunning = $runningPaths -contains $normImg
                if ($isRunning) { return }

                # ── 종속성 체크 ──
                # DependOnService / DependOnGroup 있으면 0xC0000034 → 제외
                $dep  = $svcProp.DependOnService
                $depG = $svcProp.DependOnGroup
                if (($dep  -and @($dep ).Where({ $_ -ne '' }).Count -gt 0) -or
                    ($depG -and @($depG).Where({ $_ -ne '' }).Count -gt 0)) {
                    return  # 종속 드라이버 제외 (vmhgfs.sys 등)
                }

                # ── 서명 체크 ──
                $sig = (Get-AuthenticodeSignature $imgPath -EA SilentlyContinue
                       ).SignerCertificate.Subject

                if ($sig -and $sig -notmatch '(?i)microsoft|windows|intel') {
                    # 1순위: 비 MS 서명 + 무종속 → EID 6 확실
                    $sourceDriver = $imgPath
                    Write-Host "  [+] 비 MS 서명 무종속 드라이버: $imgPath" -ForegroundColor Green
                    Write-Host "      서명: $sig" -ForegroundColor Green
                } elseif (-not $fallbackDriver) {
                    # 2순위 보존: MS 서명이나 무종속
                    $fallbackDriver = $imgPath
                }
            } catch {}
        }
    }

    # Step D: 2순위 fallback
    if (-not $sourceDriver -and $fallbackDriver) {
        $sourceDriver = $fallbackDriver
        Write-Host "  [!] 비 MS 서명 드라이버 없음. MS 서명 사용: $sourceDriver" -ForegroundColor Yellow
        Write-Host "      → Sysmon EID 6 확보하려면 Sysmon config exclude 룰 수정 필요" -ForegroundColor Yellow
    }

    # Step E: 후보 완전 없음 → Test Signing 상태 확인 후 더미 사용
    if (-not $sourceDriver) {
        Write-Host "  [!] 사용 가능한 드라이버 없음" -ForegroundColor Red

        $tsState = (bcdedit /enum | Select-String "testsigning").ToString()
        if ($tsState -match "Yes") {
            Write-Host "  [*] Test Signing ON 확인 → 더미 MZ 사용 가능 (서명 검증 우회)" -ForegroundColor Yellow
        } else {
            Write-Host "  [!] Test Signing OFF → EID 6 발생 불가" -ForegroundColor Red
            Write-Host "      해결: bcdedit /set testsigning on → 재부팅 → 재실행" -ForegroundColor Gray
            Write-Host "      또는: VirtualBox 설치 후 재실행" -ForegroundColor Gray
        }

        [System.IO.File]::WriteAllBytes($DriverFile,
            [byte[]](0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00))
        Write-Host "  [*] 더미 MZ 헤더 배치 (EID 6 미발생)" -ForegroundColor DarkGray
    }

    # Step F: 선택된 드라이버 복사
    if ($sourceDriver) {
        $srcSig = (Get-AuthenticodeSignature $sourceDriver -EA SilentlyContinue
                  ).SignerCertificate.Subject
        Copy-Item $sourceDriver $DriverFile -Force
        Write-Host "  [*] RTCore64.sys 배치 완료" -ForegroundColor Gray
        Write-Host "      원본: $sourceDriver" -ForegroundColor Gray
        Write-Host "      서명: $srcSig" -ForegroundColor Gray
        Write-Host "  [*] → NtLoadDriver 성공 시 Sysmon EID 6 발생 예상" -ForegroundColor Green
    }

    # 나머지 도구 배치
    Copy-Item "$env:SystemRoot\System32\cmd.exe" $HelperLoader -Force
    Write-Host "  [*] drvloader.exe 배치: $HelperLoader" -ForegroundColor Gray

    Copy-Item "$env:SystemRoot\System32\cmd.exe" $MemoryTool -Force
    Write-Host "  [*] memctl.exe 배치: $MemoryTool" -ForegroundColor Gray

    $p = Start-Process -FilePath $HelperLoader `
        -ArgumentList "/c echo [drvloader] staging complete" `
        -WindowStyle Hidden -PassThru
    $p | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    Write-Host "  [*] drvloader.exe 초기 실행 완료 (Prefetch 생성)" -ForegroundColor Gray

} $true "Sysmon EID 11: FileCreate RTCore64.sys / drvloader.exe / memctl.exe"

# --------------------------------------------------
# Stage 5 : kernel_service_creation
# T1543.003 - Windows Service
# Security EID 4697 / 4688 / Sysmon EID 1
# --------------------------------------------------
Invoke-Stage 5 "kernel_service_creation" "kernel_service_creation" `
    @("HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName") {

    sc.exe delete $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 1

    $r = sc.exe create $ServiceName `
            type= kernel `
            start= demand `
            binPath= $DriverFile `
            DisplayName= "Windows Driver Service" 2>&1
    Write-Host "  [*] sc create 결과: $r" -ForegroundColor Gray

    # NtLoadDriver는 \??\C:\... 형식 필요 → 명시적으로 덮어씀
    $ntImagePath = "\??\" + $DriverFile
    Set-ItemProperty `
        -Path  "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" `
        -Name  "ImagePath" `
        -Value $ntImagePath `
        -Force
    Write-Host "  [*] ImagePath(NT) 설정: $ntImagePath" -ForegroundColor Gray

    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName") {
        Write-Host "  [*] Registry 키 확인 완료" -ForegroundColor Gray
    }

} $true "Security EID 4697: WinDrv Service Installed (type=kernel) / EID 4688: sc.exe"

# --------------------------------------------------
# Stage 6 : driver_load
# T1547.006 - Kernel Modules and Extensions
# NtLoadDriver → Sysmon EID 6
# Security EID 4688 / Sysmon EID 1 · 6
#
# [FIX] 주요 수정 사항:
#   1) P/Invoke 중복 정의 제거 (PrivilegeHelper / NtDrvLoader 는 스크립트 상단에서 로드됨)
#   2) NtLoadDriver 반환값 변수를 $ntStatus 로 명명 (Invoke-Stage 내부 $status 와 혼동 방지)
#   3) 드라이버 교체 로직 정리
# --------------------------------------------------
Invoke-Stage 6 "driver_load" "driver_load" `
    @($DriverFile) {

    # ══════════════════════════════════════════
    # Step 1: 현재 드라이버 서명 확인 및 교체 판단
    # ══════════════════════════════════════════
    $currentSig = ""
    try {
        $currentSig = (Get-AuthenticodeSignature $DriverFile -EA SilentlyContinue
                      ).SignerCertificate.Subject
    } catch {}
    Write-Host "  [*] 현재 드라이버 서명: $currentSig" -ForegroundColor Gray

    # 현재 커널에 로드된 드라이버 경로 수집
    $runningPaths = @(
        Get-WmiObject Win32_SystemDriver -EA SilentlyContinue |
        Where-Object { $_.State -eq "Running" } |
        ForEach-Object {
            ($_.PathName -replace '\\\\?\\.\\', '') `
                -replace '\\SystemRoot\\', "$env:SystemRoot\"
        }
    )

    # 현재 파일이 이미 실행 중인지 확인
    $alreadyLoaded = $runningPaths | Where-Object {
        try {
            (Get-Item $_ -EA SilentlyContinue).FullName -eq
            (Get-Item $DriverFile -EA SilentlyContinue).FullName
        } catch { $false }
    }

    if ($alreadyLoaded) {
        Write-Host "  [!] 현재 드라이버가 이미 실행 중 → 대체 파일 탐색" -ForegroundColor Yellow

        $newSource = $null

        # 1차: 비 MS 서명 미실행 드라이버 탐색
        Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -EA SilentlyContinue |
        ForEach-Object {
            if ($newSource) { return }
            try {
                $p = Get-ItemProperty $_.PSPath -EA SilentlyContinue
                if ($p.Type -ne 1 -or $p.Start -lt 3 -or -not $p.ImagePath) { return }
                $imgPath = $p.ImagePath `
                    -replace '\\SystemRoot\\', "$env:SystemRoot\" `
                    -replace '\\?\?\\', '' `
                    -replace '"', ''
                if (-not (Test-Path $imgPath)) { return }
                $isRunning = $runningPaths | Where-Object {
                    try { (Get-Item $_ -EA SilentlyContinue).FullName -eq
                          (Get-Item $imgPath -EA SilentlyContinue).FullName } catch { $false }
                }
                if ($isRunning) { return }
                $sig = (Get-AuthenticodeSignature $imgPath -EA SilentlyContinue
                       ).SignerCertificate.Subject
                if ($sig -and $sig -notmatch '(?i)microsoft|windows|intel') {
                    $newSource = $imgPath
                    Write-Host "  [+] 비 MS 서명 미실행 드라이버 발견: $imgPath" -ForegroundColor Green
                    Write-Host "      서명: $sig" -ForegroundColor Green
                }
            } catch {}
        }

        # 2차: MS 서명 미실행 드라이버 (Sysmon config AND 규칙 필요)
        if (-not $newSource) {
            Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" -EA SilentlyContinue |
            ForEach-Object {
                if ($newSource) { return }
                try {
                    $p = Get-ItemProperty $_.PSPath -EA SilentlyContinue
                    if ($p.Type -ne 1 -or $p.Start -lt 3 -or -not $p.ImagePath) { return }
                    $imgPath = $p.ImagePath `
                        -replace '\\SystemRoot\\', "$env:SystemRoot\" `
                        -replace '\\?\?\\', '' `
                        -replace '"', ''
                    if (-not (Test-Path $imgPath)) { return }
                    $isRunning = $runningPaths | Where-Object {
                        try { (Get-Item $_ -EA SilentlyContinue).FullName -eq
                              (Get-Item $imgPath -EA SilentlyContinue).FullName } catch { $false }
                    }
                    if (-not $isRunning) { $newSource = $imgPath }
                } catch {}
            }
            if ($newSource) {
                Write-Host "  [*] MS 서명 미실행 드라이버 사용: $newSource" -ForegroundColor Yellow
                Write-Host "  [!] Sysmon config DriverLoad 규칙에 ImagePath AND 조건 확인 필요" -ForegroundColor Yellow
            }
        }

        if ($newSource) {
            Copy-Item $newSource $DriverFile -Force
            Write-Host "  [*] 드라이버 파일 교체 완료: $DriverFile" -ForegroundColor Gray
        } else {
            Write-Host "  [!] 사용 가능한 미실행 드라이버 없음" -ForegroundColor Red
        }
    }

    # ══════════════════════════════════════════
    # Step 2: ImagePath 재설정 (\??\ 형식)
    # ══════════════════════════════════════════
    $ntImagePath = "\??\" + $DriverFile
    try {
        Set-ItemProperty `
            -Path  "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" `
            -Name  "ImagePath" `
            -Value $ntImagePath -Force
        Write-Host "  [*] ImagePath 재설정: $ntImagePath" -ForegroundColor Gray
    } catch {
        Write-Host "  [!] ImagePath 설정 실패 (서비스 키 없음 → Stage 5 실패 여부 확인)" -ForegroundColor Red
    }

    # ══════════════════════════════════════════
    # Step 3: SeLoadDriverPrivilege 활성화
    # ══════════════════════════════════════════
    $privOk = [PrivilegeHelper]::Enable("SeLoadDriverPrivilege")
    Write-Host ("  [{0}] SeLoadDriverPrivilege 활성화" -f $(if ($privOk) {"+"} else {"!"})) `
        -ForegroundColor $(if ($privOk) {"Green"} else {"Red"})

    # ══════════════════════════════════════════
    # Step 4: NtLoadDriver 호출 → Sysmon EID 6
    # [FIX] 반환값 변수를 $ntStatus 로 명명 (Invoke-Stage 의 $status 와 구분)
    # ══════════════════════════════════════════
    $ntRegPath = "\Registry\Machine\SYSTEM\CurrentControlSet\Services\$ServiceName"
    Write-Host "  [*] NtLoadDriver 호출: $ntRegPath" -ForegroundColor Gray

    $ntStatus    = [NtDrvLoader]::Load($ntRegPath)
    $ntStatusHex = "0x{0:X8}" -f $ntStatus
    Write-Host "  [*] NtLoadDriver NTSTATUS: $ntStatusHex" -ForegroundColor Cyan

    switch ($ntStatus) {
        0x00000000 {
            Write-Host "  [+] 드라이버 로드 성공 → Sysmon EID 6 발생" -ForegroundColor Green
            $drvSig = (Get-AuthenticodeSignature $DriverFile -EA SilentlyContinue
                      ).SignerCertificate.Subject
            Write-Host "  [*] 로드된 드라이버 서명: $drvSig" -ForegroundColor Gray
            if ($drvSig -match '(?i)microsoft|windows|intel') {
                Write-Host "  [!] MS/Intel 서명 → Sysmon DriverLoad exclude 규칙 확인 필요" -ForegroundColor Yellow
            }
        }
        0xC000010E {
            Write-Host "  [+] 이미 로드됨 (STATUS_IMAGE_ALREADY_LOADED) → EID 6 부팅 시 기록됨" -ForegroundColor Green
        }
        0xC0000428 {
            Write-Host "  [!] 서명 검증 실패 (STATUS_INVALID_IMAGE_HASH)" -ForegroundColor Yellow
            Write-Host "      → 관리자 CMD에서 실행 후 재부팅:" -ForegroundColor Yellow
            Write-Host "         bcdedit /set testsigning on" -ForegroundColor White
        }
        0xC0000034 {
            Write-Host "  [!] 오브젝트 없음 (STATUS_OBJECT_NAME_NOT_FOUND)" -ForegroundColor Yellow
            Write-Host "      → ImagePath Step 2 결과 및 서비스 키 확인" -ForegroundColor Yellow
        }
        0xC0000061 {
            Write-Host "  [!] 권한 없음 (STATUS_PRIVILEGE_NOT_HELD)" -ForegroundColor Red
            Write-Host "      → 관리자 권한 및 SeLoadDriverPrivilege 확인" -ForegroundColor Red
        }
        default {
            Write-Host "  [!] 기타 NTSTATUS: $ntStatusHex" -ForegroundColor Yellow
        }
    }

    # ── sc start: SCM 경유 흔적 추가 (EID 4688 보조) ──
    $scResult = sc.exe start $ServiceName 2>&1
    Write-Host "  [*] sc start 결과: $scResult" -ForegroundColor Gray

    # ── drvloader.exe 경유 흔적 ──
    $p = Start-Process -FilePath $HelperLoader `
        -ArgumentList "/c sc start $ServiceName" `
        -WindowStyle Hidden -PassThru
    $p | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    Write-Host "  [*] drvloader.exe 경유 완료" -ForegroundColor Gray

} $true "Sysmon EID 6: DriverLoaded RTCore64.sys (NtLoadDriver) / EID 1: sc.exe + drvloader.exe"

# --------------------------------------------------
# Stage 7 : driver_validation
# T1016 - System Network Configuration Discovery
# Security EID 4688 / Sysmon EID 1
# --------------------------------------------------
Invoke-Stage 7 "driver_validation" "driver_validation" `
    @("sc query $ServiceName") {

    $r = sc.exe query $ServiceName 2>&1
    Write-Host "  [*] sc query $ServiceName 결과:" -ForegroundColor Gray
    Write-Host "      $r" -ForegroundColor Gray

    Start-Process -FilePath "sc.exe" -ArgumentList "queryex $ServiceName" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] sc queryex $ServiceName 완료" -ForegroundColor Gray

} $true "Security EID 4688 / Sysmon EID 1: sc.exe query WinDrv"

# --------------------------------------------------
# Stage 8 : memory_tool_execution
# T1068 - Exploitation for Privilege Escalation
# Security EID 4688 / Sysmon EID 1
# --------------------------------------------------
Invoke-Stage 8 "memory_tool_execution" "memory_tool_execution" `
    @($MemoryTool) {

    $p1 = Start-Process -FilePath $MemoryTool `
        -ArgumentList "/c echo [memctl] kernel memory controller initialized" `
        -WindowStyle Hidden -PassThru
    $p1 | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    Write-Host "  [*] memctl.exe 1차 실행 완료 (PID: $($p1.Id))" -ForegroundColor Gray

    $p2 = Start-Process -FilePath $MemoryTool `
        -ArgumentList "/c echo [memctl] ready" `
        -WindowStyle Hidden -PassThru
    $p2 | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    Write-Host "  [*] memctl.exe 2차 실행 완료" -ForegroundColor Gray

} $true "Security EID 4688 / Sysmon EID 1: memctl.exe 실행 / MEMCTL.EXE Prefetch 생성"


# --------------------------------------------------
# Stage 9 : lsass_handle_access
# T1003.001 - LSASS Memory
# memctl.exe → lsass.exe OpenProcess
# Security EID 4656 (Handle Request) / Sysmon EID 10 (ProcessAccess)
# --------------------------------------------------
Invoke-Stage 9 "lsass_handle_access" "lsass_memory_access" `
    @("lsass.exe PROCESS_VM_READ|PROCESS_QUERY_INFORMATION|ACCESS_SYSTEM_SECURITY") {

    # ── SACL 설정용 최소 헬퍼 (EID 4656 트리거에 필요) ──
    if (-not ([System.Management.Automation.PSTypeName]'LsassSacl').Type) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class LsassSacl {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern uint SetSecurityInfo(IntPtr h, uint objType, uint si,
        IntPtr o, IntPtr g, IntPtr dacl, IntPtr sacl);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool InitializeAcl(IntPtr acl, uint sz, uint rev);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AddAuditAccessAce(IntPtr acl, uint rev, uint acc,
        IntPtr sid, bool succ, bool fail);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool CreateWellKnownSid(int t, IntPtr dom, IntPtr sid, ref uint sz);
    public static bool SetSacl(int pid) {
        IntPtr h = OpenProcess(0x01000400, false, pid); // ACCESS_SYSTEM_SECURITY|QUERY_INFO
        if (h == IntPtr.Zero) return false;
        uint sidSz = 256; IntPtr pSid = Marshal.AllocHGlobal(256);
        CreateWellKnownSid(1, IntPtr.Zero, pSid, ref sidSz);
        IntPtr pAcl = Marshal.AllocHGlobal(512);
        InitializeAcl(pAcl, 512, 2);
        AddAuditAccessAce(pAcl, 2, 0x1F0FFF, pSid, true, true);
        uint r = SetSecurityInfo(h, 6, 0x10, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, pAcl);
        Marshal.FreeHGlobal(pSid); Marshal.FreeHGlobal(pAcl); CloseHandle(h);
        return r == 0;
    }
}
"@
    }

    $lsassPid = (Get-Process lsass -ErrorAction SilentlyContinue |
                 Select-Object -First 1).Id
    Write-Host "  [*] lsass.exe PID: $lsassPid" -ForegroundColor Gray

    if (-not $lsassPid) {
        Write-Host "  [!] lsass.exe PID 조회 실패" -ForegroundColor Yellow
        return
    }

    # ── Step 1: SeDebugPrivilege / SeSecurityPrivilege 활성화 ──
    $dbgOk = [PrivilegeHelper]::Enable("SeDebugPrivilege")
    $secOk = [PrivilegeHelper]::Enable("SeSecurityPrivilege")
    Write-Host ("  [{0}] SeDebugPrivilege  [{1}] SeSecurityPrivilege" `
        -f $(if ($dbgOk) {"+"} else {"!"}), $(if ($secOk) {"+"} else {"!"})) `
        -ForegroundColor $(if ($dbgOk -and $secOk) {"Green"} else {"Yellow"})

    # ── Step 2: lsass SACL 설정 → EID 4656 트리거 조건 생성 ──
    $saclOk = [LsassSacl]::SetSacl($lsassPid)
    $saclErr = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host ("  [{0}] lsass SACL 설정 (EID 4656 조건)  Win32Error={1}" `
        -f $(if ($saclOk) {"+"} else {"!"}), $saclErr) `
        -ForegroundColor $(if ($saclOk) {"Green"} else {"Yellow"})

    Start-Sleep -Milliseconds 300

    # ── Step 3: memctl.exe → lsass OpenProcess (Sysmon EID 10 SourceImage=memctl.exe 체인) ──
    # memctl.exe(cmd.exe)가 PowerShell 자식을 띄워 OpenProcess 수행
    # → Sysmon EID 10: SourceImage=powershell.exe(parent=memctl.exe), TargetImage=lsass.exe
    $mask = "0x01000410" # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | ACCESS_SYSTEM_SECURITY
    $psCmd = @"
`$pid = $lsassPid
Add-Type -MemberDefinition '
[DllImport(\"kernel32.dll\")] public static extern IntPtr OpenProcess(uint a,bool i,int p);
[DllImport(\"kernel32.dll\")] public static extern bool CloseHandle(IntPtr h);
' -Name PA -Namespace W
`$h = [W.PA]::OpenProcess($mask, `$false, `$pid)
Write-Host "Handle=`$h"
if (`$h -ne [IntPtr]::Zero) { Start-Sleep 3; [W.PA]::CloseHandle(`$h) | Out-Null }
"@
    Write-Host "  [*] memctl.exe 경유 lsass OpenProcess 시도 (Mask=$mask)" -ForegroundColor Gray
    $p = Start-Process -FilePath $MemoryTool `
        -ArgumentList "/c powershell.exe -NoProfile -WindowStyle Hidden -Command `"$psCmd`"" `
        -WindowStyle Hidden -PassThru
    $p | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue
    Write-Host "  [+] memctl.exe → lsass 접근 완료 → Sysmon EID 10 / Security EID 4656" -ForegroundColor Green

    # ── Step 4: 직접 OpenProcess 병행 (EID 4656 확보 보조) ──
    $maskDirect = [uint32]0x01000410
    Write-Host "  [*] 직접 OpenProcess lsass Mask=0x$($maskDirect.ToString('X8'))" -ForegroundColor Gray
    $handle = [ProcAccess]::OpenProcess($maskDirect, $false, $lsassPid)
    if ($handle -ne [IntPtr]::Zero) {
        Write-Host "  [+] lsass.exe OpenProcess 성공 (Handle:$handle)" -ForegroundColor Green
        Write-Host "      → Security EID 4656 + Sysmon EID 10" -ForegroundColor Gray
        Start-Sleep -Seconds 3
        [ProcAccess]::CloseHandle($handle) | Out-Null
        Write-Host "  [*] Handle 닫기 완료" -ForegroundColor Gray
    } else {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "  [!] 직접 OpenProcess 실패 (Error=$err) → fallback" -ForegroundColor Yellow
        $maskFallback = [uint32]0x00000410
        $handleFallback = [ProcAccess]::OpenProcess($maskFallback, $false, $lsassPid)
        if ($handleFallback -ne [IntPtr]::Zero) {
            Write-Host "  [+] fallback 성공 (Mask:0x$($maskFallback.ToString('X8')))" -ForegroundColor Green
            Start-Sleep -Seconds 3
            [ProcAccess]::CloseHandle($handleFallback) | Out-Null
        } else {
            $err2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "  [!] 모든 시도 실패 (Error=$err2)" -ForegroundColor Red
        }
    }

} $true "Sysmon EID 10: ProcessAccess lsass.exe / Security EID 4656 (RunAsPPL=0 + ACCESS_SYSTEM_SECURITY 조건)"

# --------------------------------------------------
# Stage 10 : credential_dump_simulation
# T1003 - OS Credential Dumping
# Security EID 4688 / Sysmon EID 1 · 11
# --------------------------------------------------
Invoke-Stage 10 "credential_dump_simulation" "credential_dump_simulation" `
    @($CredDumpSim) {

    $dmpHeader = [byte[]](0x4D,0x44,0x4D,0x50)
    $dmpMeta   = [System.Text.Encoding]::UTF8.GetBytes(@"

[dump_simulation]
timestamp    : $(Get-Date -Format 'o')
source       : memctl.exe
target       : lsass.exe (PID simulation)
dump_type    : MiniDumpWithFullMemory (simulated)
note         : forensic artifact only - no real credential data
"@)
    [System.IO.File]::WriteAllBytes($CredDumpSim, ($dmpHeader + $dmpMeta))
    Write-Host "  [*] lsass_sim.dmp 생성: $CredDumpSim" -ForegroundColor Gray

    $p = Start-Process -FilePath $MemoryTool `
        -ArgumentList "/c echo [memctl] dump written to lsass_sim.dmp" `
        -WindowStyle Hidden -PassThru
    $p | Wait-Process -Timeout 10 -ErrorAction SilentlyContinue
    Write-Host "  [*] memctl.exe dump simulation 완료" -ForegroundColor Gray

} $true "Sysmon EID 11: FileCreate lsass_sim.dmp / EID 1: memctl.exe"

# --------------------------------------------------
# Stage 11 : suspicious_memory_activity
# T1055 - Process Injection
# Sysmon EID 10
# --------------------------------------------------
Invoke-Stage 11 "suspicious_memory_activity" "process_injection_simulation" `
    @("svchost.exe PROCESS_ALL_ACCESS (0x1F0FFF)") {

    $svchostPid = (Get-Process svchost -EA SilentlyContinue | Select-Object -First 1).Id

    if ($svchostPid) {
        $mask   = [uint32]0x1F0FFF
        $handle = [ProcAccess]::OpenProcess($mask, $false, $svchostPid)

        if ($handle -ne [IntPtr]::Zero) {
            Write-Host "  [*] svchost.exe OpenProcess 성공 (PID:$svchostPid PROCESS_ALL_ACCESS)" -ForegroundColor Gray
            Start-Sleep -Seconds 2
            [ProcAccess]::CloseHandle($handle) | Out-Null
            Write-Host "  [*] Handle 닫기 완료" -ForegroundColor Gray
        } else {
            Write-Host "  [*] svchost.exe OpenProcess 실패" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [*] svchost.exe PID 조회 실패" -ForegroundColor Yellow
    }

} $true "Sysmon EID 10: ProcessAccess svchost.exe PROCESS_ALL_ACCESS"

# --------------------------------------------------
# Stage 12 : rootkit_behavior_simulation
# T1014 - Rootkit
# Security EID 4688 / Sysmon EID 1 · 11
# --------------------------------------------------
Invoke-Stage 12 "rootkit_behavior" "rootkit_behavior" `
    @($TempLog, "drvloader.exe → cmd.exe 비정상 process tree") {

    # ── 1. Rootkit Artifact 생성 ──
    $kernContent = @"
[kernel_artifact] timestamp=$(Get-Date -Format 'o')
[kernel_artifact] driver=RTCore64.sys
[kernel_artifact] base_address=0xFFFFF80000000000
[kernel_artifact] eprocess_unlink=simulated
[kernel_artifact] pid_spoofing=simulated

[hidden_process_list]
pid=4    name=System     status=unlinked_simulation
pid=768  name=lsass.exe  status=access_attempted
"@

    Set-Content -Path $TempLog -Value $kernContent -Encoding UTF8
    Write-Host "  [*] kern.tmp 생성: $TempLog" -ForegroundColor Gray

    # ── 2. 비정상 Process Lineage 생성 ──
    $p = Start-Process -FilePath $HelperLoader `
        -ArgumentList "/c start /b cmd.exe /c timeout /t 3 /nobreak > nul" `
        -WindowStyle Hidden `
        -PassThru

    $p | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue

    Write-Host "  [*] drvloader → cmd → timeout 비정상 process tree 생성" `
        -ForegroundColor Gray

    # ── 3. 짧은 수명 프로세스 반복 생성 ──
    foreach ($i in 1..3) {

        $sp = Start-Process `
            -FilePath $HelperLoader `
            -ArgumentList "/c exit" `
            -WindowStyle Hidden `
            -PassThru

        $sp | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue
    }

    Write-Host "  [*] 짧은 수명 프로세스 반복 생성 완료" `
        -ForegroundColor Gray

    # ── 4. Driver Trace Artifact 생성 ──
    $extraArtifact = "$env:ProgramData\WinDrv\drv_trace.log"

    @"
[drv_trace] $(Get-Date -Format 'o')
[drv_trace] IRP_MJ_CREATE intercepted: lsass.exe
[drv_trace] IRP_MJ_READ intercepted: lsass.exe offset=0x0
[drv_trace] callback_removed=simulated
"@ | Set-Content `
        -Path $extraArtifact `
        -Encoding UTF8

    Write-Host "  [*] drv_trace.log 생성: $extraArtifact" `
        -ForegroundColor Gray

} $true "Sysmon EID 11: kern.tmp, drv_trace.log / Sysmon EID 1: drvloader→cmd 비정상 process lineage"

# --------------------------------------------------
# Stage 13 : eventlog_cleanup_attempt
# T1070.001 - Clear Windows Event Logs
# Security EID 4688 / Sysmon EID 1
# --------------------------------------------------
Invoke-Stage 13 "eventlog_cleanup_attempt" "eventlog_cleanup_attempt" `
    @("wevtutil el", "wevtutil gli Security", "wevtutil cl (의도적 실패)") {

    Start-Process -FilePath "wevtutil.exe" -ArgumentList "el" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] wevtutil el 완료" -ForegroundColor Gray

    Start-Process -FilePath "wevtutil.exe" -ArgumentList "gli Security" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] wevtutil gli Security 완료" -ForegroundColor Gray

    Start-Process -FilePath "wevtutil.exe" `
        -ArgumentList "cl Microsoft-Windows-Sysmon/Operational /bu:`"C:\NoSuchPath\bk.evtx`"" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] wevtutil cl 시도 (의도적 실패, 로그 보존) 완료" -ForegroundColor Gray

} $true "Security EID 4688 / Sysmon EID 1: wevtutil.exe eventlog cleanup 시도"

# --------------------------------------------------
# Stage 14 : driver_unload_attempt
# T1070.009 - Clear Persistence
# Security EID 4688 / Sysmon EID 1
# --------------------------------------------------
Invoke-Stage 14 "driver_unload_attempt" "driver_unload_attempt" `
    @("sc stop $ServiceName", "sc delete $ServiceName") {

    Write-Host "  [*] sc stop $ServiceName 시도" -ForegroundColor Gray
    $r1 = sc.exe stop $ServiceName 2>&1
    Write-Host "  [*] sc stop 결과: $r1" -ForegroundColor Gray
    Start-Sleep -Seconds 2

    Write-Host "  [*] sc delete $ServiceName 시도" -ForegroundColor Gray
    $r2 = sc.exe delete $ServiceName 2>&1
    Write-Host "  [*] sc delete 결과: $r2" -ForegroundColor Gray

} $true "Security EID 4688 / Sysmon EID 1: sc.exe stop + delete WinDrv"

# --------------------------------------------------
# Stage 15 : registry_cleanup_attempt
# T1112 - Modify Registry
# Security EID 4688 / Sysmon EID 1
# --------------------------------------------------
Invoke-Stage 15 "registry_cleanup_attempt" "registry_cleanup_attempt" `
    @("reg delete HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName") {

    Write-Host "  [*] reg delete Services\$ServiceName 시도" -ForegroundColor Gray
    $r = reg delete "HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName" /f 2>&1
    Write-Host "  [*] reg delete 결과: $r" -ForegroundColor Gray

    Start-Process -FilePath "reg.exe" `
        -ArgumentList "query `"HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName`"" `
        -WindowStyle Hidden -Wait
    Write-Host "  [*] reg query (잔존 확인) 완료" -ForegroundColor Gray

} $true "Security EID 4688 / Sysmon EID 1: reg.exe delete Services\WinDrv"

# --------------------------------------------------
# Stage 16 : kernel_artifact_cleanup
# T1070.004 - File Deletion
# Sysmon EID 26
# --------------------------------------------------
Invoke-Stage 16 "kernel_artifact_cleanup" "artifact_cleanup" `
    @("$TempLog (삭제)", "$HelperLoader (삭제)", "$CredDumpSim (삭제)",
      "$DriverFile (잔존)", "$MemoryTool (잔존)") {

    foreach ($target in @($TempLog, $HelperLoader, $CredDumpSim)) {
        if (Test-Path $target) {
            Remove-Item -Path $target -Force -ErrorAction SilentlyContinue
            Write-Host "  [*] 삭제 완료: $target" -ForegroundColor Gray
        } else {
            Write-Host "  [*] 이미 없음: $target" -ForegroundColor DarkGray
        }
    }

    Write-Host "  [!] 잔존 유지: $DriverFile" -ForegroundColor Yellow
    Write-Host "  [!] 잔존 유지: $MemoryTool" -ForegroundColor Yellow

} $true "Sysmon EID 26: FileDeleteDetected kern.tmp / drvloader.exe / lsass_sim.dmp"

# --------------------------------------------------
# Stage 17 : residual_artifact_state
# DFIR baseline
# --------------------------------------------------
Invoke-Stage 17 "residual_artifact_state" "residual_artifact_state" `
    @($DriverFile, $MemoryTool, "Prefetch 잔존", "DriverLoad 기록 잔존") {

    Write-Host "  [*] 잔존 artifact 최종 상태 점검" -ForegroundColor Gray

    $fileChecks = @(
        [PSCustomObject]@{ Label = "RTCore64.sys";  Path = $DriverFile   }
        [PSCustomObject]@{ Label = "memctl.exe";    Path = $MemoryTool   }
        [PSCustomObject]@{ Label = "kern.tmp";      Path = $TempLog      }
        [PSCustomObject]@{ Label = "drvloader.exe"; Path = $HelperLoader }
        [PSCustomObject]@{ Label = "lsass_sim.dmp"; Path = $CredDumpSim  }
    )
    foreach ($f in $fileChecks) {
        $exists = Test-Path $f.Path
        $tag    = if ($exists) { "[REMAIN ]" } else { "[DELETED]" }
        $col    = if ($exists) { "Yellow"   } else { "Gray"      }
        Write-Host ("  {0} {1,-15}: {2}" -f $tag, $f.Label, $f.Path) -ForegroundColor $col
    }

    $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (Test-Path $svcKey) {
        Write-Host "  [REMAIN ] Registry: HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName" -ForegroundColor Yellow
    } else {
        Write-Host "  [DELETED] Registry: HKLM\SYSTEM\CurrentControlSet\Services\$ServiceName" -ForegroundColor Gray
    }

    foreach ($pattern in $Artifacts.prefetch_targets) {
        $hits = Get-Item $pattern -EA SilentlyContinue
        if ($hits) {
            foreach ($pf in $hits) {
                Write-Host "  [REMAIN ] Prefetch: $($pf.FullName)" -ForegroundColor Yellow
            }
        }
    }

} $false "잔존 artifact 상태 기록 완료 (DFIR 분석 가능 상태 유지)"

# --------------------------------------------------
# Stage 18 : session_termination
# Security EID 4634
# --------------------------------------------------
Invoke-Stage 18 "session_termination" "session_logoff" `
    @("사용자 세션 종료") {

    Write-Host "  [*] 시나리오 종료 및 세션 baseline 기록" -ForegroundColor Gray
    Start-Sleep -Seconds 2

} $false "Security EID 4634: Logoff"

auditpol /remove /resourceSACL:"type=process" 2>&1 | Out-Null
Write-Host "  [*] GOAA 정책 제거 완료" -ForegroundColor Gray

# ==============================
# Show Summary
# ==============================
Show-Summary

# ==============================
# Save GT
# ==============================
$Global:GT.total_stages = $Global:GT.records.Count
$Global:GT | ConvertTo-Json -Depth 8 | Out-File $GTPath -Encoding UTF8
Write-Host ""
Write-Host "GT saved → $GTPath" -ForegroundColor Yellow