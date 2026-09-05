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

    $AuthFunctions = $Ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $Node.Name -eq 'Invoke-FalconAuth'
    }, $true)
    if ($AuthFunctions.Count -eq 0) {
        $Failures.Add("${RelativePath}: Invoke-FalconAuth was not found")
    }
    foreach ($Function in $AuthFunctions) {
        $TokenPosts = $Function.FindAll({
            param($Node)
            $Node -is [System.Management.Automation.Language.CommandAst] -and
            $Node.GetCommandName() -eq 'Invoke-WebRequest' -and
            $Node.Extent.Text -match 'oauth2/token'
        }, $true)
        if ($TokenPosts.Count -eq 0) {
            $Failures.Add("${RelativePath}:$($Function.Extent.StartLineNumber): Invoke-FalconAuth has no oauth2/token Invoke-WebRequest")
        }
        foreach ($Command in $TokenPosts) {
            if ($Command.Extent.Text -notmatch '-MaximumRedirection\s+0') {
                $Failures.Add("${RelativePath}:$($Command.Extent.StartLineNumber): Invoke-FalconAuth oauth POST is missing -MaximumRedirection 0")
            }
        }
    }

    # CAND-004 is Medium (A)-only on modern pwsh: Authorization is stripped on
    # redirect follow. Do not require -MaximumRedirection 0 on
    # Invoke-FalconDownload — CDN 302 may be required for installer downloads.
    # Keep the MaxRedirection 0 requirement for Invoke-FalconAuth oauth POSTs only.
}

if ($Failures.Count -gt 0) {
    # -ErrorAction Continue overrides $ErrorActionPreference = 'Stop' for these
    # calls. Without it the first Write-Error throws, and only one of the
    # collected failures is ever reported.
    foreach ($Failure in $Failures) {
        Write-Error $Failure -ErrorAction Continue
    }
    exit 1
}

Write-Output 'PASS: PowerShell credential logging and parser checks'
