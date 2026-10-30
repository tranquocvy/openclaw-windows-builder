# Public-source-only builder. Never run on a personal workstation.
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or
    $env:GITHUB_REPOSITORY -ne 'tranquocvy/openclaw-windows-builder') {
  throw 'Dedicated hosted builder required'
}
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:CPA_RUN_ATTEMPT -ne '1') { throw 'Rerun not admitted' }
# Execution stays locked in the workflow pending explicit run approval.
# No personal checkout, secrets, OIDC, cache, or upstream CI workflow.
$pin = 'aedd9f3f56585d92ed14947df8c84ef6354f64cc'
$tree = '4a03e85758ce6e57f50998beb19399100db1cada'
$base = Join-Path $env:RUNNER_TEMP ('cpa-' + $env:CPA_RUN_ID)
if (Test-Path -LiteralPath $base) { throw 'Fresh directory required' }
$src = Join-Path $base 'source'
$tools = Join-Path $base 'tools'
$builderHome = Join-Path $base 'home'
$store = Join-Path $base 'store'
$out = Join-Path $env:RUNNER_TEMP 'cpa-export'
if (Test-Path -LiteralPath $out) { throw 'Export path already exists' }
$null = New-Item -ItemType Directory -Path $src,$tools,$builderHome,$store,$out
$childEnv = @{
  SystemRoot = $env:SystemRoot; WINDIR = $env:WINDIR
  TEMP = $builderHome; TMP = $builderHome; HOME = $builderHome; USERPROFILE = $builderHome
  APPDATA = $builderHome; LOCALAPPDATA = $builderHome; CI = 'true'
  ComSpec = (Join-Path $env:SystemRoot 'System32/cmd.exe')
  PATHEXT = '.COM;.EXE;.BAT;.CMD'
  GIT_CONFIG_NOSYSTEM = '1'; GIT_CONFIG_GLOBAL = 'NUL'
  GIT_TERMINAL_PROMPT = '0'; GIT_CONFIG_COUNT = '0'
  NPM_CONFIG_USERCONFIG = (Join-Path $builderHome 'empty.npmrc')
  NPM_CONFIG_GLOBALCONFIG = (Join-Path $builderHome 'empty-global.npmrc')
  NPM_CONFIG_REGISTRY = 'https://registry.npmjs.org/'
  OPENCLAW_BUILD_ALL_NO_PNPM = '1'; NODE_DISABLE_COMPILE_CACHE = '1'
}
# This removes inheritance for launched children, NOT administrator
# access to the runner agent/token or a network enforcement boundary.
$receipts = [System.Collections.Generic.List[object]]::new()
function Publish-ExportProgress([string]$Text,[bool]$RequireSuccess,[bool]$TimedOut,[int]$ExitCode) {
  # A numeric protocol is reconstructed;never echo child lines or parse errors.
  if ($Text.Length -gt 65536) { throw 'Export progress cap' }
  $records = [System.Collections.Generic.List[string]]::new()
  $lastStatus = ''
  $errorCode = ''
  $originRecord = ''
  $allowed = @('EXPORT_MISSING_ENTRY','EXPORT_WORKSPACE_SURFACE_UNKNOWN','EXPORT_MISSING_DEPENDENCY',
    'EXPORT_CONTENT_BLOCKED','EXPORT_READ_LENGTH_MISMATCH','EXPORT_CONTENT_PATTERN_MATCH',
    'EXPORT_GENERATED_FILE_LIMIT','EXPORT_GENERATED_METADATA_LIMIT','EXPORT_GENERATED_PATTERN_MATCH','EXPORT_FILENAME_BLOCKED','EXPORT_PATH_REJECTED','EXPORT_LINK_REJECTED',
    'EXPORT_IDENTITY_FAILED','EXPORT_SNAPSHOT_CHANGED','EXPORT_INTEGRITY_FAILED','EXPORT_LIMIT_EXCEEDED',
    'EXPORT_METADATA_INVALID','EXPORT_PROGRESS_INVALID','EXPORT_CONFIGURATION_INVALID','EXPORT_UNEXPECTED_FAILURE')
  foreach ($line in $Text.Split("`n")) {
    # Optional one-shot origin diagnosis;EP1/EF1 fields and guards stay unchanged.
    if ($line.StartsWith('EO1|',[StringComparison]::Ordinal)) {
      $origin = $line.TrimEnd("`r").Split('|')
      if ($line.Length -gt 96 -or $origin.Count -ne 3 -or $originRecord -cne '' -or
          $errorCode -cne '' -or $lastStatus -cne 'FAILED' -or
          $origin[1] -cnotin @('COMPILED_RUNTIME','PACKAGE_METADATA','RUNTIME_DEPENDENCY',
            'PLUGIN_OR_EXTENSION','ROOT_RUNTIME','GENERATED_CONTENT','OTHER_OR_UNKNOWN') -or
          $origin[2] -cnotin @('PRIVATE_KEY_LIKE','GITHUB_TOKEN_LIKE','API_KEY_LIKE',
            'AWS_ACCESS_KEY_LIKE','JWT_LIKE','BEARER_TOKEN_LIKE','OTHER_OR_UNKNOWN')) { throw 'Export origin schema' }
      $originRecord = 'EO1|' + $origin[1] + '|' + $origin[2]
      continue
    }
    if ($line.StartsWith('EF1|',[StringComparison]::Ordinal)) {
      $failure = $line.TrimEnd("`r").Split('|')
      if ($line.Length -gt 96 -or $failure.Count -ne 2 -or $errorCode -cne '' -or
          $allowed -cnotcontains $failure[1]) { throw 'Export failure schema' }
      $errorCode = $failure[1]
      continue
    }
    if (-not $line.StartsWith('EP1|',[StringComparison]::Ordinal)) { continue }
    if ($errorCode -cne '' -or $lastStatus -cin @('SUCCEEDED','FAILED')) { throw 'Export failure binding' }
    $parts = $line.TrimEnd("`r").Split('|')
    if ($line.Length -gt 512 -or $parts.Count -ne 17 -or $records.Count -ge 64) { throw 'Export progress schema' }
    if ($parts[1] -cnotin @('METADATA_RESOLUTION','RUNTIME_SELECTION','SNAPSHOT_COPY','MANIFEST_FINALIZATION') -or
        $parts[2] -cnotin @('RUNNING','SUCCEEDED','FAILED')) { throw 'Export progress schema' }
    $safe = [System.Collections.Generic.List[string]]::new()
    $safe.Add('EP1'); $safe.Add($parts[1]); $safe.Add($parts[2])
    for ($index = 3; $index -lt 17; $index++) {
      $number = 0L
      if ($parts[$index] -cnotmatch '^(0|[1-9][0-9]{0,15})$' -or
          -not [long]::TryParse($parts[$index],[ref]$number) -or $number -gt 9007199254740991) { throw 'Export progress schema' }
      $safe.Add($number.ToString([Globalization.CultureInfo]::InvariantCulture))
    }
    $lastStatus = $parts[2]
    $records.Add([string]::Join('|',$safe))
  }
  # An enum is diagnostic data,not authenticated provenance from the child.
  # Contradictory success/timeout/terminal records fail before any relay.
  $startupFailure = $records.Count -eq 0 -and $errorCode -cin @('EXPORT_CONFIGURATION_INVALID','EXPORT_UNEXPECTED_FAILURE')
  if ($errorCode -cne '' -and ($TimedOut -or $ExitCode -eq 0 -or ($lastStatus -cne 'FAILED' -and -not $startupFailure))) {
    throw 'Export failure binding'
  }
  if (-not $TimedOut -and $ExitCode -ne 0 -and $errorCode -ceq '') { throw 'Export failure incomplete' }
  if ($lastStatus -ceq 'FAILED' -and -not $TimedOut -and $ExitCode -eq 0) { throw 'Export failure binding' }
  if ($originRecord -cne '' -and ($TimedOut -or $ExitCode -eq 0 -or
      $errorCode -cnotin @('EXPORT_CONTENT_PATTERN_MATCH','EXPORT_GENERATED_PATTERN_MATCH') -or
      ($errorCode -ceq 'EXPORT_GENERATED_PATTERN_MATCH' -and -not $originRecord.StartsWith('EO1|GENERATED_CONTENT|')) -or
      ($errorCode -ceq 'EXPORT_CONTENT_PATTERN_MATCH' -and $originRecord.StartsWith('EO1|GENERATED_CONTENT|')))) { throw 'Export origin binding' }
  $relayBytes = 0
  if ($originRecord -cne '') { $relayBytes += $originRecord.Length + 1 }
  foreach ($record in $records) { $relayBytes += $record.Length + 1 }
  if ($errorCode -cne '') { $relayBytes += 5 + $errorCode.Length }
  if ($relayBytes -gt 32768) { throw 'Export progress cap' }
  # On timeout a RUNNING snapshot is useful;it cannot become a success receipt.
  foreach ($record in $records) { Write-Host $record }
  if ($originRecord -cne '') { Write-Host $originRecord }
  if ($errorCode -cne '') { Write-Host ('EF1|' + $errorCode) }
  if ($RequireSuccess -and ($records.Count -eq 0 -or $lastStatus -cne 'SUCCEEDED')) { throw 'Export progress incomplete' }
}
function Run-Bounded([string]$Id,[string]$Exe,[string[]]$Arguments,[int]$Seconds) {
  if (-not [IO.Path]::IsPathFullyQualified($Exe) -or -not [IO.File]::Exists($Exe)) { throw ('Executable unavailable: ' + $Id) }
  if (-not [IO.Directory]::Exists($src)) { throw ('Working directory unavailable: ' + $Id) }
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $Exe; $psi.WorkingDirectory = $src
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  $psi.Environment.Clear()
  foreach ($k in $childEnv.Keys) { $psi.Environment[$k] = $childEnv[$k] }
  foreach ($a in $Arguments) { $psi.ArgumentList.Add($a) }
  $p = [System.Diagnostics.Process]::new(); $p.StartInfo = $psi
  $clock = [System.Diagnostics.Stopwatch]::StartNew()
  if (-not $p.Start()) { throw ('Launch failed: ' + $Id) }
  $stdout = $p.StandardOutput.ReadToEndAsync()
  $stderr = $p.StandardError.ReadToEndAsync()
  $timedOut = -not $p.WaitForExit($Seconds * 1000)
  if ($timedOut) {
    $p.Kill($true); $p.WaitForExit()
    if ($Id -cne 'runtime-export') { throw ('Timeout: ' + $Id) }
  }
  # Do not relay arbitrary dependency output or runner environment.
  if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) { throw ('Unsettled stdio: ' + $Id) }
  $null = $stderr.GetAwaiter().GetResult()
  $text = $stdout.GetAwaiter().GetResult()
  if ($Id -ceq 'runtime-export') { Publish-ExportProgress $text (-not $timedOut -and $p.ExitCode -eq 0) $timedOut $p.ExitCode }
  if ($timedOut) { throw ('Timeout: ' + $Id) }
  $receipts.Add(@{step=$Id;exit=$p.ExitCode;elapsedMs=$clock.ElapsedMilliseconds})
  Write-Host ('Step ' + $Id + ': exit=' + $p.ExitCode + '; ms=' + $clock.ElapsedMilliseconds)
  if ($p.ExitCode -ne 0) { throw ('Nonzero exit: ' + $Id) }
  if ($Id -ceq 'runtime-export') { return '' }
  return $text.Trim()
}
function Assert-Hash([string]$Path,[string]$Expected) {
  if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) {
    throw 'Artifact integrity mismatch'
  }
}
function Download([string]$Url,[string]$Path) {
  # Fixed public HTTPS URLs; no credentials or registry auth config.
  Invoke-WebRequest -Uri $Url -OutFile $Path -MaximumRedirection 0 -TimeoutSec 120
}
$git = (Get-Command git.exe -CommandType Application | Select-Object -First 1).Source
$childEnv.PATH = (Split-Path $git) + ';' + $env:SystemRoot + '\System32'
$null = Run-Bounded 'git-init' $git @('init','--quiet','.') 30
$g = @('-c','credential.helper=','-c','core.hooksPath=NUL','-c','core.autocrlf=false',
       '-c','protocol.file.allow=never','-c','submodule.recurse=false')
$null = Run-Bounded 'git-fetch' $git ($g + @('fetch','--depth=1','--no-tags',
  'https://github.com/openclaw/openclaw.git',$pin)) 240
$null = Run-Bounded 'git-checkout' $git ($g + @('checkout','--detach','--force','FETCH_HEAD')) 120
if ((Run-Bounded 'git-pin' $git @('rev-parse','HEAD') 30) -ne $pin) { throw 'Wrong source pin' }
if ((Run-Bounded 'git-tree' $git @('rev-parse','HEAD^{tree}') 30) -ne $tree) { throw 'Wrong source tree' }
$null = Run-Bounded 'git-fsck' $git @('fsck','--strict','--no-reflogs') 120
$sourceHashes = @{
  'package.json'='801cd116568e20a302be83f47b7b96514d9bf89b23e71c5b4e5bab6490acdaef'
  'pnpm-lock.yaml'='c6f523df6d6bbcd2d97e64ab6c01536d47fd02aac35c5d2238937ad4281300e9'
  'pnpm-workspace.yaml'='7f00393940a1afc8d55192083e68b7392ab872b9bf5820626e48de10fc9fa80a'
  'scripts/build-all.mts'='06fcf76854260a8fd28c06ee8231bbf68642515a6426c476eb4a8a65df7f9278'
}
foreach ($f in $sourceHashes.Keys) { Assert-Hash (Join-Path $src $f) $sourceHashes[$f] }
$nodeZip = Join-Path $tools 'node.zip'
Download 'https://nodejs.org/dist/v24.22.1/node-v24.22.1-win-x64.zip' $nodeZip
Assert-Hash $nodeZip 'd2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5'
# Only an exact previously reviewed archive is extracted; size/path
# inventory must be requalified if either pinned archive ever changes.
Expand-Archive -LiteralPath $nodeZip -DestinationPath $tools
$node = Join-Path $tools 'node-v24.22.1-win-x64/node.exe'
Assert-Hash $node 'd702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5'
$pnpmTgz = Join-Path $tools 'pnpm.tgz'
Download 'https://registry.npmjs.org/@pnpm/exe.win32-x64/-/exe.win32-x64-12.15.0.tgz' $pnpmTgz
$sha = [System.Security.Cryptography.SHA512]::HashData([IO.File]::ReadAllBytes($pnpmTgz))
if ([Convert]::ToBase64String($sha) -ne 'nrd+Tp1We1DGj4DGG5Bea9lZNh9y1PjlLBdEwdInS4D0h0UIDtM7JaGGGDJhNzIwcHASyihWI7HLV+dtG+fhYg==') {
  throw 'pnpm archive integrity mismatch'
}
$tar = Join-Path $env:SystemRoot 'System32/tar.exe'
$null = Run-Bounded 'pnpm-extract' $tar @('-xzf',$pnpmTgz,'-C',$tools) 60
$pnpm = Join-Path $tools 'package/pnpm.exe'
Assert-Hash $pnpm '6052300915b4d839772595dc15dd6539333bf2af440839d1f8c1ffe34c86b4fd'
$childEnv.PATH = (Split-Path $node) + ';' + (Split-Path $pnpm) + ';' + $childEnv.PATH
if ((Run-Bounded 'node-version' $node @('--version') 30) -ne 'v24.22.1') { throw 'Wrong Node' }
if ((Run-Bounded 'pnpm-version' $pnpm @('--version') 30) -ne '12.15.0') { throw 'Wrong pnpm' }
$null = Run-Bounded 'fetch' $pnpm @('pm','fetch','--ignore-pnpmfile',
  '--pm-on-fail=error','--runtime-on-fail=error','--store-dir',$store) 600
$null = Run-Bounded 'install' $pnpm @('pm','install','--offline','--frozen-lockfile',
  '--ignore-scripts','--ignore-pnpmfile','--no-runtime','--pm-on-fail=error',
  '--runtime-on-fail=error','--store-dir',$store) 600
foreach ($f in $sourceHashes.Keys) { Assert-Hash (Join-Path $src $f) $sourceHashes[$f] }
$null = Run-Bounded 'cliStartup' $node @('--import','./scripts/tsx.mjs',
  'scripts/build-all.mts','cliStartup') 1800
# No rebuild/allow-builds/postinstall/full-profile automatic fallback.
foreach ($f in $sourceHashes.Keys) { Assert-Hash (Join-Path $src $f) $sourceHashes[$f] }
if ((Run-Bounded 'source-clean' $git @('status','--porcelain','--untracked-files=no') 30)) {
  throw 'Build modified tracked source; review required'
}
foreach ($f in @('dist/entry.js','dist/runtime-dependency-ownership.json')) {
  if (-not (Test-Path -LiteralPath (Join-Path $src $f) -PathType Leaf)) { throw 'Missing build output' }
}
foreach ($f in @('.openclaw-lifecycle-pending','dist/openclaw-install-guard')) {
  if (Test-Path -LiteralPath (Join-Path $src $f)) { throw 'Pending package lifecycle; no repair allowed' }
}
$payload = Join-Path $base 'payload'
$runtime = Join-Path $payload 'runtime'
$null = New-Item -ItemType Directory -Path $runtime
# Select declared runtime packages and built workspace surfaces before copying.
# Package metadata is data only;no package/Node import,installer or lifecycle is run.
# Unknown entries,required denied names and unresolved links fail closed.
$links = [System.Collections.Generic.List[object]]::new()
$files = [System.Collections.Generic.List[object]]::new()
$python = (Get-Command python.exe -CommandType Application | Select-Object -First 1).Source
$exportScript = Join-Path $PSScriptRoot 'test_candidate.py'
$exportPolicy = Join-Path (Split-Path $PSScriptRoot) 'policy/artifact-policy.json'
$fileManifest = Join-Path $payload 'files.json'
$linkManifest = Join-Path $payload 'links.json'
$null = Run-Bounded 'runtime-export' $python @('-I','-B',$exportScript,'--prepare-runtime',
  '--source',$src,'--destination',$runtime,'--policy',$exportPolicy,
  '--files',$fileManifest,'--links',$linkManifest) 120
foreach ($row in @(Get-Content -LiteralPath $fileManifest -Raw | ConvertFrom-Json)) { $files.Add($row) }
foreach ($row in @(Get-Content -LiteralPath $linkManifest -Raw | ConvertFrom-Json)) { $links.Add($row) }
# Original bin target intentionally absent: upstream wrapper has
# automatic runtime/lifecycle recovery paths. CP-B must review an
# exact no-repair invocation before any host execution is authorized.
$null = New-Item -ItemType Directory -Path (Join-Path $payload 'node')
Copy-Item -LiteralPath $node -Destination (Join-Path $payload 'node/node.exe')
$files.Add(@{path='node/node.exe';bytes=(Get-Item $node).Length;sha256='d702daa815eabbff763c7d3808e235cf031cf2ca70211b56847bc72f51e240e5'})
$nodeLicense = Join-Path (Split-Path $node) 'LICENSE'
Copy-Item -LiteralPath $nodeLicense -Destination (Join-Path $payload 'node/LICENSE')
$files.Add(@{path='node/LICENSE';bytes=(Get-Item $nodeLicense).Length;sha256=(Get-FileHash -LiteralPath $nodeLicense -Algorithm SHA256).Hash.ToLowerInvariant()})
$links | ConvertTo-Json -Depth 5 -AsArray | Set-Content (Join-Path $payload 'links.json') -Encoding utf8NoBOM
$files | Sort-Object path | ConvertTo-Json -Depth 5 -AsArray | Set-Content (Join-Path $payload 'files.json') -Encoding utf8NoBOM
# No Gateway/model/worker invocation, schema import, lifecycle repair
# or arbitrary runtime package load is added as a packaging shortcut.
$receipt = @{
  runnerImage=$env:ImageOS;runnerImageVersion=$env:ImageVersion
  gitSha256=(Get-FileHash -LiteralPath $git -Algorithm SHA256).Hash.ToLowerInvariant()
  powershell=$PSVersionTable.PSVersion.ToString()
  source=$pin;tree=$tree;sourceHashes=$sourceHashes;profile='cliStartup'
  node='24.22.1';pnpm='12.15.0';runId=$env:CPA_RUN_ID
  workflowSha=$env:CPA_WORKFLOW_SHA;runAttempt=1;steps=$receipts
  status='QUARANTINED_CANDIDATE';hostExecution=$false
  runtimeQualification='UNRUN';signedProvenance=$false
  lifecycleHooks='SUPPRESSED; NONE ENABLED';links='DATA ONLY'
}
$receipt | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $payload 'receipt.json') -Encoding utf8NoBOM
$inventory = @(Get-ChildItem -LiteralPath $payload -Recurse -Force)
if (@($inventory | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
  throw 'Export contains a reparse point'
}
$regular = @($inventory | Where-Object { -not $_.PSIsContainer })
if ($regular.Count -gt 200000 -or ($regular | Measure-Object -Property Length -Sum).Sum -gt 1GB) {
  throw 'Final payload inventory cap exceeded'
}
# Export gate remains separate from build success. This draft cannot
# prove a same-admin dependency has not read CI credentials or forged
# outputs. Resolve B-CPA-SECURITY before enabling; hashes are integrity.
$zip = Join-Path $out 'openclaw-windows-candidate.zip'
Compress-Archive -LiteralPath (Join-Path $payload 'runtime'),(Join-Path $payload 'node'),(Join-Path $payload 'links.json'),(Join-Path $payload 'files.json'),(Join-Path $payload 'receipt.json') -DestinationPath $zip
if ((Get-Item $zip).Length -gt 250MB) { throw 'Compressed artifact exceeds 250 MiB' }
((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() + '  openclaw-windows-candidate.zip') | Set-Content (Join-Path $out 'SHA256SUMS') -Encoding ascii
