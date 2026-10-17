param(
    [Parameter(Mandatory=$true)][ValidateSet('Start', 'Stop', 'Status', 'Smoke', 'Runtime')][string]$Action,
    [ValidateSet('vulnerable', 'patched')][string]$Variant = 'vulnerable',
    [ValidateRange(1024, 65535)][int]$Port = 18080
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'tools.ps1')
$taskTools = Get-LabToolchain
$taskRuntime = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "$Variant/target/runtime"))
$taskStateRoot = Join-Path $taskTools.RepositoryRoot 'data/output/log4shell-host'
$taskStatePath = Join-Path $taskStateRoot "$Variant.json"

function Get-OwnedLabProcess {
    if (-not (Test-Path -LiteralPath $taskStatePath)) { return $null }
    $taskSaved = Get-Content -LiteralPath $taskStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $taskProcess = Get-Process -Id $taskSaved.pid -ErrorAction SilentlyContinue
    if (-not $taskProcess) { return $null }
    if ($taskProcess.ProcessName -ne 'java' -or
        $taskProcess.StartTime.ToUniversalTime().Ticks -ne $taskSaved.started_ticks -or
        $taskSaved.runtime -ne $taskRuntime -or
        $taskProcess.Path -ne $taskSaved.java_executable) {
        throw 'Saved PID no longer identifies this Lab; refusing to control another process.'
    }
    return $taskProcess
}

if ($Action -eq 'Runtime') {
    if (-not (Test-Path -LiteralPath (Join-Path $taskRuntime 'classes'))) { throw 'Build the Lab first.' }
    Write-Output $taskRuntime
    return
}
if ($Action -eq 'Stop') {
    $taskProcess = Get-OwnedLabProcess
    if ($taskProcess) {
        Stop-Process -Id $taskProcess.Id
        $taskProcess.WaitForExit(5000) | Out-Null
        Write-Output "Stopped owned Lab process: $($taskProcess.Id)"
    }
    else { Write-Output "Lab not running: $Variant" }
    if (Test-Path -LiteralPath $taskStatePath) { Remove-Item -LiteralPath $taskStatePath }
    return
}
if ($Action -eq 'Status') {
    $taskProcess = Get-OwnedLabProcess
    if ($taskProcess) { Get-Content -LiteralPath $taskStatePath -Raw -Encoding UTF8 }
    else { Write-Output "Lab not running: $Variant" }
    return
}
if ($Action -eq 'Smoke') {
    $taskProcess = Get-OwnedLabProcess
    if (-not $taskProcess) { throw "No owned Lab process running: $Variant" }
    $taskSaved = Get-Content -LiteralPath $taskStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $taskAddress = 'http://127.0.0.1:' + $taskSaved.port
    $taskHealth = Invoke-RestMethod -Uri ($taskAddress + '/health') -TimeoutSec 5
    $taskBanking = Invoke-RestMethod -Uri ($taskAddress + '/banking/smoke') -TimeoutSec 5
    $taskInventory = Invoke-RestMethod -Uri ($taskAddress + '/runtime') -TimeoutSec 5
    if ($taskHealth.status -ne 'ok' -or $taskBanking.result -ne 'ok' -or $taskBanking.mode -ne 'synthetic') {
        throw 'Actual HTTP functional contract failed.'
    }
    @{variant=$Variant; pid=$taskProcess.Id; collected_at=[DateTime]::UtcNow.ToString('o');
      health=$taskHealth; banking=$taskBanking; runtime=$taskInventory} | ConvertTo-Json -Depth 6
    return
}

if (Get-OwnedLabProcess) { throw "Lab already running: $Variant. Stop it before replacing the runtime." }
if (-not $taskTools.Java -or -not (Test-Path -LiteralPath $taskTools.Java)) { throw 'JDK not prepared.' }
if (-not (Test-Path -LiteralPath (Join-Path $taskRuntime 'classes')) -or
    -not (Test-Path -LiteralPath (Join-Path $taskRuntime 'lib'))) { throw 'Build the Lab first.' }
New-Item -ItemType Directory -Path $taskStateRoot -Force | Out-Null
$taskStamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$taskStdout = Join-Path $taskStateRoot "$Variant-$taskStamp.stdout.log"
$taskStderr = Join-Path $taskStateRoot "$Variant-$taskStamp.stderr.log"
$taskClasspath = (Join-Path $taskRuntime 'classes') + ';' + (Join-Path $taskRuntime 'lib/*')
# Do not pass platform API keys, database credentials or user-injected Java options to the Lab.
$taskEnvironment = [Environment]::GetEnvironmentVariables('Process')
$taskAllowedEnvironment = @('SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'COMSPEC')
try {
    foreach ($taskName in $taskEnvironment.Keys) {
        if ($taskName -notin $taskAllowedEnvironment) {
            [Environment]::SetEnvironmentVariable($taskName, $null, 'Process')
        }
    }
    $taskProcess = Start-Process -FilePath $taskTools.Java -WindowStyle Hidden -PassThru -WorkingDirectory $taskRuntime `
        -ArgumentList @('-Xms32m', '-Xmx128m', '-cp', ('"' + $taskClasspath + '"'), 'com.example.sbomlab.BankingLab', '--host', '127.0.0.1', '--port', $Port) `
        -RedirectStandardOutput $taskStdout -RedirectStandardError $taskStderr
}
finally {
    foreach ($taskName in $taskEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($taskName, $taskEnvironment[$taskName], 'Process')
    }
}
$taskStarted = $taskProcess.StartTime.ToUniversalTime().Ticks
$taskReady = $false
$taskLastError = 'Startup marker not yet available.'
try {
    $taskDeadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $taskDeadline) {
        $taskProcess.Refresh()
        if ($taskProcess.HasExited) { throw "Lab exited before readiness. See $taskStderr" }
        try {
            $taskMarkerText = Get-Content -LiteralPath $taskStdout -Raw -Encoding UTF8
            if ($taskMarkerText) {
                $taskMarker = $taskMarkerText | ConvertFrom-Json
                if ($taskMarker.host -ne '127.0.0.1' -or $taskMarker.port -ne $Port) { throw 'Startup marker disagrees.' }
                $taskHealth = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 2
                if ($taskHealth.status -eq 'ok') { $taskReady = $true; break }
            }
        }
        catch { $taskLastError = $_.Exception.Message }
        Start-Sleep -Milliseconds 200
    }
    if (-not $taskReady) { throw "Lab readiness failed: $taskLastError; see $taskStderr" }
    $taskSaved = @{pid=$taskProcess.Id; started_ticks=$taskStarted; runtime=$taskRuntime;
                   java_executable=$taskTools.Java; port=$Port; variant=$Variant;
                   started_at=$taskProcess.StartTime.ToUniversalTime().ToString('o');
                   ready_at=[DateTime]::UtcNow.ToString('o'); stdout=$taskStdout; stderr=$taskStderr}
    [IO.File]::WriteAllText($taskStatePath, ($taskSaved | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $taskSaved | ConvertTo-Json
}
catch {
    $taskProcess.Refresh()
    if (-not $taskProcess.HasExited) { Stop-Process -Id $taskProcess.Id }
    throw
}
