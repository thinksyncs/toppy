param(
  [string]$TargetHost = $env:TOPPY_E2E_RDP_HOST
)

$ErrorActionPreference = 'Stop'

function Resolve-IPv4 {
  param(
    [Parameter(Mandatory = $true)][string]$Host
  )

  # If already an IPv4 literal, return it.
  $ipLiteral = $null
  if ([System.Net.IPAddress]::TryParse($Host, [ref]$ipLiteral)) {
    if ($ipLiteral.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
      return $ipLiteral.IPAddressToString
    }
  }

  $addrs = [System.Net.Dns]::GetHostAddresses($Host) | Where-Object {
    $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
  }
  $first = $addrs | Select-Object -First 1
  if (-not $first) {
    throw "failed to resolve IPv4 for host: $Host"
  }
  return $first.IPAddressToString
}

function New-TempDir {
  $root = if (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
  $name = [System.Guid]::NewGuid().ToString('n')
  $path = Join-Path $root "toppy-$name"
  New-Item -ItemType Directory -Path $path | Out-Null
  return $path
}

function Get-FreePort {
  $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
  $listener.Start()
  $port = $listener.LocalEndpoint.Port
  $listener.Stop()
  return $port
}

function Wait-ForPort {
  param(
    [string]$Host,
    [int]$Port,
    [int]$Seconds = 10
  )

  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $result = Test-NetConnection -ComputerName $Host -Port $Port -WarningAction SilentlyContinue
      if ($result.TcpTestSucceeded) {
        return $true
      }
    } catch {
      # ignore transient errors
    }
    Start-Sleep -Milliseconds 200
  }
  return $false
}

if ([string]::IsNullOrWhiteSpace($TargetHost)) {
  Write-Host "TOPPY_E2E_RDP_HOST not set; skipping Windows RDP E2E." 
  Write-Host "Run with: scripts/e2e-rdp.ps1 -TargetHost <your-rdp-host>" 
  exit 0
}

$targetIp = Resolve-IPv4 -Host $TargetHost

$artifactDir = if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_WORKSPACE)) {
  Join-Path $env:GITHUB_WORKSPACE 'artifacts/windows-e2e-rdp'
} else {
  $null
}
if ($artifactDir) {
  New-Item -ItemType Directory -Path $artifactDir -Force | Out-Null
  Write-Host "Artifacts will be written to: $artifactDir"
}

$tmpdir = New-TempDir
$configFile = Join-Path $tmpdir 'config.toml'

# Policy allows only RDP port 3389 to the target host.
@"
gateway = \"127.0.0.1\"
port = 4433
mtu = 1350

[policy]
  [[policy.allow]]
  cidr = \"$targetIp/32\"
  ports = [3389]
"@ | Set-Content -Path $configFile -Encoding UTF8

$listenPort = Get-FreePort
$deniedListenPort = Get-FreePort

Write-Host "TargetHost=$TargetHost TargetIp=$targetIp AllowedListenPort=$listenPort DeniedListenPort=$deniedListenPort"

# Fail fast if the runner can't reach the target at all.
$reachable = Test-NetConnection -ComputerName $targetIp -Port 3389 -WarningAction SilentlyContinue
if (-not $reachable.TcpTestSucceeded) {
  Write-Host "Target $targetIp:3389 is not reachable from this runner. Ensure firewall/NAT allows 3389 from windows-latest."
  exit 1
}

# Pre-build to avoid racing readiness checks against a cold compile.
& cargo build -q -p toppy-cli

# Start allowed proxy in background.
$allowedOut = Join-Path $tmpdir 'allowed.out.log'
$allowedErr = Join-Path $tmpdir 'allowed.err.log'

$allowedArgs = @(
  'run','-q','-p','toppy-cli','--',
  'up',
  '--target',"${targetIp}:3389",
  '--listen',"127.0.0.1:${listenPort}",
  '--once'
)

$proc = Start-Process -FilePath 'cargo' -ArgumentList $allowedArgs -NoNewWindow -PassThru `
  -RedirectStandardOutput $allowedOut -RedirectStandardError $allowedErr `
  -WorkingDirectory (Get-Location) `
  -Environment @{ TOPPY_CONFIG = $configFile }

try {
  if (-not (Wait-ForPort -Host '127.0.0.1' -Port $listenPort -Seconds 15)) {
    Write-Host "Allowed listen port did not open in time."
    Write-Host "--- allowed stdout ---"; Get-Content $allowedOut -ErrorAction SilentlyContinue | ForEach-Object { $_ }
    Write-Host "--- allowed stderr ---"; Get-Content $allowedErr -ErrorAction SilentlyContinue | ForEach-Object { $_ }
    exit 1
  }

  # Connect to the local listener. With --once, the process should then exit.
  $client = [System.Net.Sockets.TcpClient]::new()
  $client.Connect('127.0.0.1', $listenPort)
  Start-Sleep -Milliseconds 200
  $client.Close()

  if (-not $proc.WaitForExit(20000)) {
    Write-Host "Allowed proxy did not exit in time (expected --once behavior)."
    exit 1
  }
  if ($proc.ExitCode -ne 0) {
    Write-Host "Allowed proxy exited with non-zero code: $($proc.ExitCode)"
    exit 1
  }
} finally {
  if ($artifactDir) {
    Copy-Item -Path $allowedOut -Destination (Join-Path $artifactDir 'allowed.out.log') -Force -ErrorAction SilentlyContinue
    Copy-Item -Path $allowedErr -Destination (Join-Path $artifactDir 'allowed.err.log') -Force -ErrorAction SilentlyContinue
    Copy-Item -Path $configFile -Destination (Join-Path $artifactDir 'config.toml') -Force -ErrorAction SilentlyContinue
  }

  if ($proc -and -not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }
}

# Denied case: port 3390 is not allowed by policy.
$deniedArgs = @(
  'run','-q','-p','toppy-cli','--',
  'up',
  '--target',"${targetIp}:3390",
  '--listen',"127.0.0.1:${deniedListenPort}",
  '--once'
)

$deniedOut = Join-Path $tmpdir 'denied.out.log'
$deniedErr = Join-Path $tmpdir 'denied.err.log'
$denied = Start-Process -FilePath 'cargo' -ArgumentList $deniedArgs -NoNewWindow -PassThru -Wait `
  -RedirectStandardOutput $deniedOut -RedirectStandardError $deniedErr `
  -WorkingDirectory (Get-Location) `
  -Environment @{ TOPPY_CONFIG = $configFile }

if ($artifactDir) {
  Copy-Item -Path $deniedOut -Destination (Join-Path $artifactDir 'denied.out.log') -Force -ErrorAction SilentlyContinue
  Copy-Item -Path $deniedErr -Destination (Join-Path $artifactDir 'denied.err.log') -Force -ErrorAction SilentlyContinue
}

if ($denied.ExitCode -eq 0) {
  Write-Host "Expected policy denial exit code, got 0."
  Write-Host "--- denied stdout ---"; Get-Content $deniedOut -ErrorAction SilentlyContinue | ForEach-Object { $_ }
  Write-Host "--- denied stderr ---"; Get-Content $deniedErr -ErrorAction SilentlyContinue | ForEach-Object { $_ }
  exit 1
}

# Ensure denied port isn't listening.
$deniedAccepts = (Test-NetConnection -ComputerName '127.0.0.1' -Port $deniedListenPort -WarningAction SilentlyContinue).TcpTestSucceeded
if ($deniedAccepts) {
  Write-Host "Expected denied listen port to be closed."
  exit 1
}

# Doctor should report policy.denied as fail for the denied target.
$env:TOPPY_CONFIG = $configFile
$env:TOPPY_DOCTOR_NET = 'skip'
$env:TOPPY_DOCTOR_TUN = 'pass'
$env:TOPPY_DOCTOR_TARGET = "${targetIp}:3390"

$doctorJson = & cargo run -q -p toppy-cli -- doctor --json
if ([string]::IsNullOrWhiteSpace($doctorJson)) {
  Write-Host "doctor output was empty"
  exit 1
}

try {
  $data = $doctorJson | ConvertFrom-Json
} catch {
  Write-Host "doctor output was not valid JSON:"
  Write-Host $doctorJson
  exit 1
}

$checks = @{}
foreach ($c in $data.checks) {
  $checks[$c.id] = $c
}

if (-not $checks.ContainsKey('policy.denied')) {
  Write-Host "missing policy.denied check"
  exit 1
}
if ($checks['policy.denied'].status -ne 'fail') {
  Write-Host "expected policy.denied fail, got $($checks['policy.denied'].status)"
  exit 1
}

$summary = [string]$checks['policy.denied'].summary
if ($summary -notmatch 'not allowed') {
  Write-Host "expected denial reason in summary, got: $summary"
  exit 1
}

Write-Host "Windows RDP E2E OK (allowed handshake + denied policy + doctor)."
