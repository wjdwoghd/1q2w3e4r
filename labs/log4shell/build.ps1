param([ValidateSet('vulnerable', 'patched', 'all')][string]$Variant = 'all')

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'tools.ps1')
$taskTools = Get-LabToolchain
if (-not $taskTools.Java -or -not (Test-Path -LiteralPath $taskTools.Java)) {
    throw 'JDK not found. Set LAB_JAVA_HOME or prepare data/output/lab-tooling/toolchain.json.'
}
if (-not $taskTools.Maven -or -not (Test-Path -LiteralPath $taskTools.Maven)) {
    throw 'Maven not found. Set LAB_MAVEN_EXECUTABLE or prepare the local toolchain.'
}
$taskVariants = @($Variant)
if ($Variant -eq 'all') { $taskVariants = @('vulnerable', 'patched') }
$taskPreviousJavaHome = $env:JAVA_HOME
try {
    $env:JAVA_HOME = $taskTools.JavaHome
    foreach ($taskVariant in $taskVariants) {
        $taskState = Join-Path $taskTools.RepositoryRoot "data/output/log4shell-host/$taskVariant.json"
        if (Test-Path -LiteralPath $taskState) {
            $taskSaved = Get-Content -LiteralPath $taskState -Raw -Encoding UTF8 | ConvertFrom-Json
            $taskRunning = Get-Process -Id $taskSaved.pid -ErrorAction SilentlyContinue
            if ($taskRunning -and $taskRunning.StartTime.ToUniversalTime().Ticks -eq $taskSaved.started_ticks) {
                throw "Stop the running $taskVariant Lab before rebuilding its runtime."
            }
        }
        $taskVariantRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $taskVariant))
        $taskTarget = [IO.Path]::GetFullPath((Join-Path $taskVariantRoot 'target'))
        $taskAllowedRoot = [IO.Path]::GetFullPath($PSScriptRoot) + [IO.Path]::DirectorySeparatorChar
        if (-not $taskTarget.StartsWith($taskAllowedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Maven clean target is outside this Lab.'
        }
        $taskPom = Join-Path $taskVariantRoot 'pom.xml'
        & $taskTools.Maven -B -f $taskPom clean package
        if ($LASTEXITCODE -ne 0) { throw "Lab build failed: $taskVariant" }
        $taskRuntime = Join-Path $taskTarget 'runtime'
        $taskClasspath = (Join-Path $taskRuntime 'classes') + ';' + (Join-Path $taskRuntime 'lib/*')
        & $taskTools.Java -cp $taskClasspath com.example.sbomlab.BankingLab --self-test
        if ($LASTEXITCODE -ne 0) { throw "Lab self-test failed: $taskVariant" }
        Write-Output "Runtime ready: $taskRuntime"
    }
}
finally { $env:JAVA_HOME = $taskPreviousJavaHome }
