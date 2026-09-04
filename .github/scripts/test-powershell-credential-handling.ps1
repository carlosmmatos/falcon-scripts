$ErrorActionPreference = 'Stop'

$RepositoryRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
$Scripts = @(
    'powershell/install/falcon_windows_install.ps1'
    'powershell/install/falcon_windows_uninstall.ps1'
    'powershell/migrate/falcon_windows_migrate.ps1'
)
$SensitiveLogVariables = '(FalconAccessToken|FalconClientSecret|MaintenanceToken|ProvToken|InstallParams|UninstallParams)'
$Failures = [System.Collections.Generic.List[string]]::new()

foreach ($RelativePath in $Scripts) {
    $Path = Join-Path $RepositoryRoot $RelativePath
    $Tokens = $null
    $ParseErrors = $null
    $Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref] $Tokens,
        [ref] $ParseErrors
    )

    foreach ($ParseError in $ParseErrors) {
        $Failures.Add("${RelativePath}:$($ParseError.Extent.StartLineNumber): parser error: $($ParseError.Message)")
    }

    $LogCommands = $Ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.CommandAst] -and
        $Node.GetCommandName() -in @('Write-FalconLog', 'Write-VerboseLog')
    }, $true)

    foreach ($Command in $LogCommands) {
        $CommandText = $Command.Extent.Text
        if ($CommandText -match "\`$$SensitiveLogVariables") {
            $Failures.Add("${RelativePath}:$($Command.Extent.StartLineNumber): sensitive variable used in log command")
        }
        if ($CommandText -match 'Write-VerboseLog' -and
            $CommandText -match '\$content' -and
            $CommandText -match '(Invoke-FalconAuth|GetToken)') {
            $Failures.Add("${RelativePath}:$($Command.Extent.StartLineNumber): sensitive API response used in verbose log")
        }
    }

    $DebugOffCommands = $Ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.CommandAst] -and
        $Node.GetCommandName() -eq 'Set-PSDebug' -and
        $Node.Extent.Text -match '-Off'
    }, $true)
    if ($DebugOffCommands.Count -eq 0) {
        $Failures.Add("${RelativePath}: PowerShell tracing is not disabled before credentials are processed")
    }
}

if ($Failures.Count -gt 0) {
    $Failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'PASS: PowerShell credential logging and parser checks'
