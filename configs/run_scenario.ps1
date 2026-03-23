param(
    [string]$ScenarioPath = "C:\ELP\ForensicLab\scenario.json",
    [string]$OutputDir = "C:\ForensicLab\output"
)

$ErrorActionPreference = "Stop"

function Get-IsoTime {
    return (Get-Date).ToString("o")
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# [추가] 실행 환경 준비
function Initialize-Environment {
    Write-Host "[*] Initializing environment..."

    # temp 폴더 생성
    $tempPath = "C:\temp"
    Ensure-Directory -Path $tempPath

    # collector.exe 없으면 생성 (notepad 복사)
    $collectorPath = Join-Path $tempPath "collector.exe"

    if (-not (Test-Path $collectorPath)) {
        Write-Host " -> collector.exe not found, creating dummy executable..."

        Copy-Item "C:\Windows\System32\notepad.exe" $collectorPath -Force
    }

    Write-Host "[*] Environment ready"
    Write-Host ""
}

# 출력 폴더 준비
Ensure-Directory -Path $OutputDir

# 환경 초기화 실행
Initialize-Environment

# 시나리오 로드
if (-not (Test-Path $ScenarioPath)) {
    throw "Scenario file not found: $ScenarioPath"
}

$scenario = Get-Content $ScenarioPath -Raw -Encoding UTF8 | ConvertFrom-Json

# actions 또는 steps 둘 다 대응
if ($scenario.PSObject.Properties.Name -contains "actions") {
    $actionList = $scenario.actions
}
elseif ($scenario.PSObject.Properties.Name -contains "steps") {
    $actionList = $scenario.steps
}
else {
    throw "No 'actions' or 'steps' field found in scenario JSON."
}

# 정렬
$actionList = $actionList | Sort-Object action_id

# GT 저장 배열
$gtActions = [System.Collections.ArrayList]@()

function Add-GroundTruth {
    param (
        [object]$Action,
        [string]$Status,
        [string]$Message,
        [string]$ObservedTarget = $null
    )

     if (-not $ObservedTarget -and $Action.PSObject.Properties.Name -contains "target") {
        $ObservedTarget = $Action.target
    }

    $entry = [PSCustomObject]@{
        action_id = $Action.action_id
        timestamp = Get-IsoTime
        action_type = $Action.action_type
        technique_id = $Action.technique_id
        target = $ObservedTarget
        status = $Status
        message = $Message
        description = $Action.description
    }    

    $gtActions.Add($entry) | Out-Null
}

Write-Host "=== Scenario Execution Start ==="
Write-Host "Scenario ID : $($scenario.scenario_id)"
Write-Host "Scenario Name : $($scenario.scenario_name)"
Write-Host ""

foreach ($action in $actionList) {
    Write-Host "[Action $($action.action_id)] $($action.action_type)"

    try {
        switch ($action.action_type) {

            "powershell_execute" {
                Invoke-Expression $action.command
                Add-GroundTruth -Action $action -Status "success" -Message "PowerShell command executed successfully."
            }
            
            "process_execute" {
                $exePath = $action.command

                if (-not (Test-Path $exePath)) {
                    Add-GroundTruth -Action $action -Status "failed" -Message "Executable not found: $exePath"
                    Write-Host " -> failed: executable not found"
                    continue
                }

                $proc = Start-Process -FilePath $exePath -PassThru
                Start-Sleep -Seconds 2

                Add-GroundTruth -Action $action -Status "success" -Message "Process executed successfully. PID=$($proc.Id)" -ObservedTarget $exePath
            }

            "file_create" {
                $targetPath = $action.target
                $parentDir = Split-Path $targetPath -Parent
                Ensure-Directory -Path $parentDir

                Set-Content -Path $targetPath -Value "secret_data" -Encoding UTF8

                Add-GroundTruth -Action $action -Status "success" -Message "File created successfully."
            }

            "file_compress" {
                $zipPath = $action.target
                $sourcePath = "C:\temp\secret.txt"

                if (-not (Test-Path $sourcePath)) {
                    Add-GroundTruth -Action $action -Status "failed" -Message "source file not found for compression: $sourcePath"
                    Write-Host " -> failed: source file not found"
                    continue
                }

                $zipDir = Split-Path $zipPath -Parent
                Ensure-Directory -Path $zipDir

                if (Test-Path $zipPath) {
                    Remove-Item -Path $zipPath -Force
                }

                Compress-Archive -Path $sourcePath -DestinationPath $zipPath -Force

                Write-Host " -> success: file compressed"

                Add-GroundTruth -Action $action -Status "success" -Message "File compressed successfully."
            }

            "file_delete" {
                $targetPath = $action.target

                if (-not (Test-Path $targetPath)) {
                    Add-GroundTruth -Action $action -Status "failed" -Message "File not found for deletion: $targetPath"
                    Write-Host " -> failed: file not found"
                    continue
                }

                Remove-Item -Path $targetPath -Force

                Add-GroundTruth -Action $action -Status "success" -Message "File deleted successfully."
            }

            default {
                Add-GroundTruth -Action $action -Status "success" -Message "Unsupported action_type: $($action.action_type)"
                Write-Host " -> failed: unsupported action type"
            }
        }
    }
    catch {
        Add-GroundTruth -Action $action -Status "failed" -Message $_.Exception.Message
        Write-Host " -> exception: $($_.Exception.Message)"
    }
    
    Start-Sleep -Seconds 1
}

# 최종 GT JSON 저장
$groundTruth = [PSCustomObject]@{
    scenario_id = $scenario.scenario_id
    scenario_name = $scenario.scenario_name
    run_timestamp = Get-IsoTime
    actions = $gtActions
}

$gtPath = Join-Path $OutputDir "ground_truth.json"
$groundTruth | ConvertTo-Json -Depth 10 | Set-Content -Path $gtPath -Encoding UTF8

Write-Host ""
Write-Host "=== Scenario Execution Complete ==="
Write-Host "Ground truth saved to: $gtPath"