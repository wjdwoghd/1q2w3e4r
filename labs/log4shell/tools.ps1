function Get-LabToolchain {
    $taskRepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $taskConfigPath = Join-Path $taskRepositoryRoot 'data/output/lab-tooling/toolchain.json'
    $taskConfig = $null
    if (Test-Path -LiteralPath $taskConfigPath) {
        $taskConfig = Get-Content -LiteralPath $taskConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    $taskJavaHome = $env:LAB_JAVA_HOME
    if (-not $taskJavaHome -and $taskConfig) { $taskJavaHome = $taskConfig.java_home }
    if (-not $taskJavaHome) { $taskJavaHome = $env:JAVA_HOME }
    $taskMaven = $env:LAB_MAVEN_EXECUTABLE
    if (-not $taskMaven -and $taskConfig) { $taskMaven = $taskConfig.maven_executable }
    if (-not $taskMaven) {
        $taskCommand = Get-Command mvn -ErrorAction SilentlyContinue
        if ($taskCommand) { $taskMaven = $taskCommand.Source }
    }
    $taskSyft = $env:LAB_SYFT_EXECUTABLE
    if (-not $taskSyft -and $taskConfig) { $taskSyft = $taskConfig.syft_executable }
    if (-not $taskSyft) {
        $taskCommand = Get-Command syft -ErrorAction SilentlyContinue
        if ($taskCommand) { $taskSyft = $taskCommand.Source }
    }
    $taskJava = $null
    if ($taskJavaHome) { $taskJava = Join-Path $taskJavaHome 'bin/java.exe' }
    [pscustomobject]@{
        JavaHome = $taskJavaHome
        Java = $taskJava
        Maven = $taskMaven
        Syft = $taskSyft
        RepositoryRoot = $taskRepositoryRoot
    }
}
