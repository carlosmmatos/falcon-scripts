# Live 307 chain for Invoke-FalconAuth and Invoke-FalconDownload.
# High fail is only (B): client_secret or Authorization bearer on hop 2.
# (A) hop-2 contact without the credential is a follow/policy gap, not High.
# Modern PowerShell blocks HTTPS→HTTP, so the leak sink is HTTPS→HTTPS.

[CmdletBinding()]
param(
    [switch] $HopListener,
    [int] $Port,
    [string] $CapturePath,
    [string] $RedirectTo
)

$ErrorActionPreference = 'Stop'

if ($HopListener) {
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("http://127.0.0.1:$Port/")
    $listener.Start()
    [System.IO.File]::WriteAllText("$CapturePath.ready", 'ready')
    try {
        $ctx = $listener.GetContext()
        $req = $ctx.Request
        $reader = [System.IO.StreamReader]::new($req.InputStream, $req.ContentEncoding)
        $body = $reader.ReadToEnd()
        $auth = $req.Headers['Authorization']
        [System.IO.File]::WriteAllText(
            $CapturePath,
            "METHOD=$($req.HttpMethod) AUTH=[$auth] BODY=[$body] PATH=$($req.RawUrl)"
        )
        $resp = $ctx.Response
        if ($RedirectTo) {
            $resp.StatusCode = 307
            $resp.RedirectLocation = $RedirectTo
            $resp.Close()
        }
        else {
            $payload = '{"access_token":"mock","token":"mock"}'
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
            $resp.StatusCode = 200
            $resp.ContentType = 'application/json'
            $resp.OutputStream.Write($bytes, 0, $bytes.Length)
            $resp.Close()
        }
    }
    finally {
        $listener.Stop()
        $listener.Close()
    }
    exit 0
}

$RepositoryRoot = Resolve-Path (Join-Path $PSScriptRoot '../..')
$ServerScript = Join-Path $RepositoryRoot '.github/scripts/redirect-capture-server.py'
if (-not (Test-Path $ServerScript)) {
    throw "missing capture server $ServerScript"
}
$WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("falcon-iwr-redir-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$Failures = [System.Collections.Generic.List[string]]::new()
$ChildProcesses = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

$Cert = Join-Path $WorkDir 'cert.pem'
$Key = Join-Path $WorkDir 'key.pem'
& openssl req -x509 -newkey rsa:2048 -keyout $Key -out $Cert -days 1 -nodes -subj '/CN=127.0.0.1' 2>$null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Cert)) {
    throw 'openssl failed to create a hermetic TLS certificate'
}

$Python = $null
foreach ($candidate in @('python3', 'python')) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source; break }
}
if (-not $Python) { throw 'no python interpreter is available for the HTTPS capture server' }

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    return $port
}

function Wait-Ready {
    param([string] $Path)
    for ($i = 0; $i -lt 50; $i++) {
        if (Test-Path $Path) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "capture server did not start: $Path"
}

function Start-HttpsHop {
    param(
        [string] $CapturePath,
        [string] $RedirectTo
    )
    Remove-Item $CapturePath, "$CapturePath.ready", "$CapturePath.port" -ErrorAction SilentlyContinue
    $redirectArg = if ($RedirectTo) { $RedirectTo } else { '-' }
    $argumentList = @($ServerScript, $CapturePath, $redirectArg, $Cert, $Key)
    $proc = Start-Process -FilePath $Python -ArgumentList $argumentList -PassThru
    $ChildProcesses.Add($proc)
    Wait-Ready "$CapturePath.ready"
    return [int](Get-Content -Raw "$CapturePath.port").Trim()
}

function Start-HttpHop {
    param(
        [int] $Port,
        [string] $CapturePath,
        [string] $RedirectTo
    )
    Remove-Item $CapturePath, "$CapturePath.ready" -ErrorAction SilentlyContinue
    $argumentList = @(
        '-NoProfile'
        '-File', $PSCommandPath
        '-HopListener'
        '-Port', $Port
        '-CapturePath', $CapturePath
    )
    if ($RedirectTo) {
        $argumentList += @('-RedirectTo', $RedirectTo)
    }
    $proc = Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList $argumentList -PassThru
    $ChildProcesses.Add($proc)
    Wait-Ready "$CapturePath.ready"
    return $proc
}

function Read-Capture {
    param([string] $Path)
    if (Test-Path $Path) { return (Get-Content -Raw $Path).Trim() }
    return '<missing>'
}

function Report-AB {
    param(
        [string] $Candidate,
        [string] $Hop2Path,
        [string] $Pattern
    )
    $text = Read-Capture $Hop2Path
    # Write-Host so callers can `if (Report-AB)` on the boolean only.
    if ($text -ne '<missing>') {
        Write-Host "$Candidate (A) hop2_contacted=yes capture=$text"
    }
    else {
        Write-Host "$Candidate (A) hop2_contacted=no"
    }
    if ($text -ne '<missing>' -and $text -match $Pattern) {
        Write-Host "$Candidate (B) credential_on_hop2=yes"
        return $true
    }
    Write-Host "$Candidate (B) credential_on_hop2=no"
    return $false
}

function Get-FunctionText {
    param([string] $Path, [string] $Name)
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $parseErrors)
    $function = $ast.FindAll({
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $Node.Name -eq $Name
    }, $true) | Select-Object -First 1
    if (-not $function) {
        throw "function $Name not found in $Path"
    }
    return $function.Extent.Text
}

function Stop-Children {
    foreach ($proc in $ChildProcesses) {
        if (-not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        }
    }
    $ChildProcesses.Clear()
}

try {
    $FullUserAgent = 'crowdstrike-falcon-scripts/test'
    $FalconAccessToken = $null
    function Write-FalconLog { param($Source, $Message, $stdout) }
    function Write-VerboseLog { param($VerboseInput, $PreMessage) }
    function Get-FalconCloud { param($xCsRegion) return 'https://127.0.0.1' }
    function Format-403Error { param($url, $scope) return "403 $url" }

    $authScripts = @(
        'powershell/install/falcon_windows_install.ps1'
        'powershell/install/falcon_windows_uninstall.ps1'
        'powershell/migrate/falcon_windows_migrate.ps1'
    )

    foreach ($relativePath in $authScripts) {
        $path = Join-Path $RepositoryRoot $relativePath
        $hop1 = Join-Path $WorkDir ("auth-hop1-" + [IO.Path]::GetFileNameWithoutExtension($relativePath) + '.txt')
        $hop2 = Join-Path $WorkDir ("auth-hop2-" + [IO.Path]::GetFileNameWithoutExtension($relativePath) + '.txt')
        $hop2Port = Start-HttpsHop -CapturePath $hop2 -RedirectTo $null
        $hop1Port = Start-HttpsHop -CapturePath $hop1 -RedirectTo "https://127.0.0.1:$hop2Port/oauth2/token"

        Invoke-Expression (Get-FunctionText -Path $path -Name 'Invoke-FalconAuth')
        $body = @{
            client_id     = 'regression-client-id'
            client_secret = 'REGRESSION_SECRET'
        }
        try {
            $null = Invoke-FalconAuth -WebRequestParams @{ SkipCertificateCheck = $true } -BaseUrl "https://127.0.0.1:$hop1Port" -Body $body -FalconCloud 'us-1'
        }
        catch {
            Write-Output "${relativePath}: Invoke-FalconAuth threw $($_.Exception.Message)"
        }

        Start-Sleep -Milliseconds 300
        Write-Output "${relativePath} Invoke-FalconAuth hop1: $(Read-Capture $hop1)"
        Write-Output "${relativePath} Invoke-FalconAuth hop2: $(Read-Capture $hop2)"
        # Hop 2 missing is (B)=no and PASS: -MaximumRedirection 0 is the correct
        # CAND-003 fix and intentionally empties hop 2. Fail only on (B)=yes.
        if (Report-AB -Candidate "CAND-003 $relativePath" -Hop2Path $hop2 -Pattern 'REGRESSION_SECRET') {
            $Failures.Add("${relativePath}: CAND-003 (B) Invoke-FalconAuth leaked client_secret to hop 2 ($(Read-Capture $hop2))")
        }
        Stop-Children
        Remove-Item Function:Invoke-FalconAuth -ErrorAction SilentlyContinue
    }

    $downloadScripts = @(
        @{ Path = 'powershell/install/falcon_windows_install.ps1'; HasHeadersParam = $false }
        @{ Path = 'powershell/migrate/falcon_windows_migrate.ps1'; HasHeadersParam = $true }
    )

    foreach ($entry in $downloadScripts) {
        $relativePath = $entry.Path
        $path = Join-Path $RepositoryRoot $relativePath
        $hop1 = Join-Path $WorkDir ("dl-hop1-" + [IO.Path]::GetFileNameWithoutExtension($relativePath) + '.txt')
        $hop2 = Join-Path $WorkDir ("dl-hop2-" + [IO.Path]::GetFileNameWithoutExtension($relativePath) + '.txt')
        $hop2Port = Start-HttpsHop -CapturePath $hop2 -RedirectTo $null
        $hop1Port = Start-HttpsHop -CapturePath $hop1 -RedirectTo "https://127.0.0.1:$hop2Port/file"

        Invoke-Expression (Get-FunctionText -Path $path -Name 'Invoke-FalconDownload')
        $outFile = Join-Path $WorkDir ("dl-" + [IO.Path]::GetFileNameWithoutExtension($relativePath) + '.bin')
        $headers = @{ Authorization = 'bearer REGRESSION_BEARER' }
        $webParams = @{ SkipCertificateCheck = $true }
        try {
            if ($entry.HasHeadersParam) {
                Invoke-FalconDownload -WebRequestParams $webParams -url "https://127.0.0.1:$hop1Port/file" -Outfile $outFile -Headers $headers
            }
            else {
                $webParams['Headers'] = $headers
                Invoke-FalconDownload -WebRequestParams $webParams -url "https://127.0.0.1:$hop1Port/file" -Outfile $outFile
            }
        }
        catch {
            Write-Output "${relativePath}: Invoke-FalconDownload threw $($_.Exception.Message)"
        }

        Start-Sleep -Milliseconds 300
        Write-Output "${relativePath} Invoke-FalconDownload hop1: $(Read-Capture $hop1)"
        Write-Output "${relativePath} Invoke-FalconDownload hop2: $(Read-Capture $hop2)"
        # Hop 2 missing is (B)=no and PASS. Fail only when the bearer is present
        # on hop 2; (A)-only contact without the credential is not High.
        if (Report-AB -Candidate "CAND-004 $relativePath" -Hop2Path $hop2 -Pattern 'REGRESSION_BEARER') {
            $Failures.Add("${relativePath}: CAND-004 (B) Invoke-FalconDownload leaked Authorization bearer to hop 2 ($(Read-Capture $hop2))")
        }
        Stop-Children
        Remove-Item Function:Invoke-FalconDownload -ErrorAction SilentlyContinue
    }

    # Pin control: -MaximumRedirection 0 must keep the secret off hop 2.
    $ctrl1Port = Get-FreePort
    $ctrl2Port = Get-FreePort
    $ctrl1 = Join-Path $WorkDir 'max0-hop1.txt'
    $ctrl2 = Join-Path $WorkDir 'max0-hop2.txt'
    [void](Start-HttpHop -Port $ctrl2Port -CapturePath $ctrl2 -RedirectTo $null)
    [void](Start-HttpHop -Port $ctrl1Port -CapturePath $ctrl1 -RedirectTo "http://127.0.0.1:$ctrl2Port/oauth2/token")
    try {
        Invoke-WebRequest -Uri "http://127.0.0.1:$ctrl1Port/oauth2/token" -UseBasicParsing -Method POST -Body @{ client_secret = 'REGRESSION_SECRET' } -MaximumRedirection 0 | Out-Null
        $Failures.Add('control: -MaximumRedirection 0 unexpectedly followed the 307')
    }
    catch {
        Write-Output "control: -MaximumRedirection 0 threw as expected ($($_.Exception.Message))"
    }
    Start-Sleep -Milliseconds 300
    $ctrl2Text = Read-Capture $ctrl2
    Write-Output "control MaximumRedirection 0 hop2: $ctrl2Text"
    if ($ctrl2Text -match 'REGRESSION_SECRET') {
        $Failures.Add("control: -MaximumRedirection 0 still leaked to hop 2 ($ctrl2Text)")
    }
    Stop-Children
}
finally {
    Stop-Children
    Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
}

if ($Failures.Count -gt 0) {
    foreach ($failure in $Failures) {
        Write-Error $failure -ErrorAction Continue
    }
    exit 1
}

Write-Output 'PASS: PowerShell redirect credential leak checks'
