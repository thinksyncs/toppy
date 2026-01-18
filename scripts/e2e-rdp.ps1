param(
  [string]$TargetHost = $env:TOPPY_E2E_RDP_HOST
)

$ErrorActionPreference = 'Stop'

function New-TempDir {
  $root = [System.IO.Path]::GetTempPath()
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

$tmpdir = New-TempDir
$configFile = Join-Path $tmpdir 'config.toml'

# Policy allows only RDP port 3389 to the target host.
@"
gateway = \"127.0.0.1\"
port = 4433
mtu = 1350

[policy]
  [[policy.allow]]
  cidr = \"$TargetHost/32\"
  ports = [3389]
"@ | Set-Content -Path $configFile -Encoding UTF8

$listenPort = Get-FreePort
$deniedListenPort = Get-FreePort

Write-Host "TargetHost=$TargetHost AllowedListenPort=$listenPort DeniedListenPort=$deniedListenPort"

# Start allowed proxy in background.
$allowedOut = Join-Path $tmpdir 'allowed.out.log'
$allowedErr = Join-Path $tmpdir 'allowed.err.log'

$allowedArgs = @(
  'run','-q','-p','toppy-cli','--',
  'up',
  '--target',"${TargetHost}:3389",
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

  # Attempt a TCP handshake through the proxy (this triggers the outbound connect).
  $ok = (Test-NetConnection -ComputerName '127.0.0.1' -Port $listenPort -WarningAction SilentlyContinue).TcpTestSucceeded
  if (-not $ok) {
    Write-Host "Expected local proxy port to accept connections (allowed case)."
    exit 1
  }
} finally {
  if ($proc -and -not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }
}

# Denied case: port 3390 is not allowed by policy.
$deniedArgs = @(
  'run','-q','-p','toppy-cli','--',
  'up',
  '--target',"${TargetHost}:3390",
  '--listen',"127.0.0.1:${deniedListenPort}",
  '--once'
)

$deniedOut = Join-Path $tmpdir 'denied.out.log'
$deniedErr = Join-Path $tmpdir 'denied.err.log'
$denied = Start-Process -FilePath 'cargo' -ArgumentList $deniedArgs -NoNewWindow -PassThru -Wait `
  -RedirectStandardOutput $deniedOut -RedirectStandardError $deniedErr `
  -WorkingDirectory (Get-Location) `
  -Environment @{ TOPPY_CONFIG = $configFile }

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
$env:TOPPY_DOCTOR_TARGET = "${TargetHost}:3390"

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

Write-Host "Windows RDP E2E OK (allowed handshake + denied policy + doctor)."
