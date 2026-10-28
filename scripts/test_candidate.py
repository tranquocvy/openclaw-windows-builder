"""Non-executing ZIP gate. Never imports/executes candidate code or extracts it.
Developer-only --test-build-preamble separately runs reviewed builder initialization.

Same-runner consistency screening only; a compromised builder can forge this
program, policy, receipt and output. Independent review is required before use.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile


class Rejected(Exception):
    pass


def need(condition, category):
    if not condition:
        raise Rejected(category)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def safe_path(value):
    need(isinstance(value, str) and 0 < len(value) <= 4096, 'PATH')
    need('\\' not in value and not value.startswith('/') and ':' not in value, 'PATH')
    parts = value.rstrip('/').split('/')
    for part in parts:
        need(part not in ('', '.', '..') and part[-1:] not in (' ', '.'), 'PATH')
        need(not re.search(r'[\x00-\x1f<>"|?*]', part), 'PATH')
        need(not re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', part, re.I), 'PATH')
        need(not re.match(r'^(\.env(?:\.|$)|\.npmrc$|auth\.json$|credentials?(?:\.|$)|\.git$)', part, re.I), 'FORBIDDEN_NAME')
    return '/'.join(parts)


def sensitive(data):
    # Pattern screening is intentionally incomplete; never emit matched bytes.
    patterns = [rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----',
                rb'\bgh[pousr]_[A-Za-z0-9]{20,}', rb'\bgithub_pat_[A-Za-z0-9_]{20,}',
                rb'\bsk-[A-Za-z0-9_-]{20,}', rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b',
                rb'\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]+',
                rb'(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/-]{12,}']
    return any(re.search(pattern, data) for pattern in patterns)


def native_owner(path, policy):
    prefix = 'runtime/node_modules/.pnpm/'
    if not path.startswith(prefix):
        return None
    folder = path[len(prefix):].split('/', 1)[0]
    for owner in policy['nativeOwners']:
        key = owner['pnpmPrefix']
        if folder == key or folder.startswith(key + '_'):
            return owner['package']
    return None


def validate_archive(stream, policy, workflow_sha, run_id):
    with zipfile.ZipFile(stream) as archive:
        need(not archive.comment, 'ARCHIVE_COMMENT')
        position = archive.fp.tell()
        archive.fp.seek(0, 2)
        need(archive.fp.tell() <= policy['maxCompressedBytes'], 'COMPRESSED_CAP')
        archive.fp.seek(position)
        entries = archive.infolist()
        need(len(entries) <= policy['maxEntries'], 'ENTRY_CAP')
        need(sum(i.file_size for i in entries) <= policy['maxExpandedBytes'], 'EXPANDED_CAP')
        names, content, hashes, binaries, scripts = {}, {}, {}, [], 0
        for item in entries:
            need(not item.comment, 'ENTRY_COMMENT')
            path = safe_path(item.filename)
            need(not sensitive(path.encode()), 'SENSITIVE_PATTERN')
            key = path.casefold()
            need(key not in names, 'CASE_COLLISION')
            names[key] = path
            mode = (item.external_attr >> 16) & 0xFFFF
            need(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), 'SPECIAL_FILE')
            need(stat.S_IFMT(mode) != stat.S_IFDIR or item.is_dir(), 'DIRECTORY_TYPE')
            need(not item.flag_bits & 1 and not item.external_attr & 0x400, 'ENCRYPTED_OR_REPARSE')
            need(item.file_size <= policy['maxFileBytes'], 'FILE_CAP')
            need(path.split('/')[0] in ('runtime', 'node') or path in ('files.json', 'links.json', 'receipt.json'), 'ROOT_INVENTORY')
            if item.is_dir():
                need(item.file_size == 0, 'DIRECTORY_PAYLOAD')
                continue
            if path.startswith('runtime/'):
                rel = path[len('runtime/'):]
                if '/' not in rel:
                    need(rel in policy['rootFiles'], 'ROOT_HELPER')
                else:
                    need(rel.split('/')[0] in ('dist', 'node_modules', 'packages', 'extensions'), 'ROOT_INVENTORY')
            if path.startswith('node/'):
                need(path in ('node/node.exe', 'node/LICENSE'), 'ROOT_INVENTORY')
            need(path != 'runtime/openclaw.mjs', 'ACTIVE_WRAPPER')
            with archive.open(item) as source:
                digest, count, overlap, head = hashlib.sha256(), 0, b'', b''
                is_metadata = path in ('files.json', 'links.json', 'receipt.json')
                buf = bytearray() if is_metadata else None
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    if not head:
                        head = chunk[:4]
                    count += len(chunk)
                    need(count <= item.file_size and count <= policy['maxFileBytes'], 'FILE_CAP')
                    need(not sensitive(overlap + chunk), 'SENSITIVE_PATTERN')
                    overlap = chunk[-2048:]
                    digest.update(chunk)
                    if buf is not None:
                        need(count <= 32 * 1024 * 1024, 'METADATA_CAP')
                        buf.extend(chunk)
                need(count == item.file_size, 'SIZE_MISMATCH')
                hashes[path] = (count, digest.hexdigest())
                if buf is not None:
                    content[path] = json.loads(buf.decode('utf-8-sig'), object_pairs_hook=strict_object)
            suffix = Path(path).suffix.lower()
            need(head not in (b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf') and suffix not in ('.so', '.dylib'), 'FOREIGN_NATIVE')
            if head[:2] == b'MZ' or suffix in ('.exe', '.dll', '.node'):
                owner = native_owner(path, policy)
                need(path == 'node/node.exe' or owner is not None, 'UNEXPECTED_NATIVE')
                binaries.append({'path': path, 'owner': owner or 'verified-node', 'sha256': hashes[path][1]})
            if suffix in ('.ps1', '.cmd', '.bat', '.sh', '.py', '.vbs'):
                # Extra installer/launcher scripts cannot appear at artifact root.
                need(path.startswith(('runtime/node_modules/', 'runtime/packages/', 'runtime/extensions/')), 'UNEXPECTED_SCRIPT')
                scripts += 1
        for path in hashes:
            parts = path.split('/')
            need(not any('/'.join(parts[:n]) in hashes for n in range(1, len(parts))), 'PATH_SHADOW')
        required = {'files.json', 'links.json', 'receipt.json', 'node/node.exe', 'node/LICENSE',
                    'runtime/package.json', 'runtime/dist/entry.js', 'runtime/dist/runtime-dependency-ownership.json'}
        need(required <= hashes.keys(), 'MISSING_OUTPUT')
        need(hashes['node/node.exe'][1] == policy['nodeExeSha256'], 'NODE_HASH')
        rows = content['files.json']
        need(isinstance(rows, list), 'FILE_MANIFEST')
        expected = {}
        for row in rows:
            need(set(row) == {'path', 'bytes', 'sha256'}, 'FILE_MANIFEST')
            p = safe_path(row['path'])
            need(p not in expected and re.fullmatch(r'[a-f0-9]{64}', row['sha256']), 'FILE_MANIFEST')
            expected[p] = (row['bytes'], row['sha256'])
        actual = {p: v for p, v in hashes.items() if p not in ('files.json', 'links.json', 'receipt.json')}
        need(expected == actual, 'FILE_MANIFEST')
        links = content['links.json']
        need(isinstance(links, list), 'LINK_MANIFEST')
        aliases = {}
        for row in links:
            need(set(row) == {'path', 'target', 'directory'}, 'LINK_MANIFEST')
            p, target = safe_path(row['path']), safe_path(row['target'])
            p, target = 'runtime/' + p, 'runtime/' + target
            need(p.casefold() not in names and p.casefold() not in aliases, 'LINK_ALIAS')
            need(isinstance(row['directory'], bool), 'LINK_TYPE')
            need(p != target and not p.startswith(target + '/'), 'LINK_CYCLE')
            if row['directory']:
                need(target not in actual and (target.casefold() in names or any(q.startswith(target + '/') for q in actual)), 'LINK_TARGET')
            else:
                need(target in actual, 'LINK_TARGET')
            need(not any(q.startswith(p + '/') for q in actual), 'LINK_SHADOW')
            aliases[p.casefold()] = (p, target)
        for p, target in aliases.values():
            need(not any(p.casefold().startswith(a + '/') for a in aliases if a != p.casefold()), 'LINK_NESTING')
            need(not any(target.casefold() == a or target.casefold().startswith(a + '/') for a in aliases), 'LINK_CHAIN')
        r = content['receipt.json']
        need(r['source'] == policy['source'] and r['tree'] == policy['sourceTree'], 'SOURCE_PIN')
        need(r['sourceHashes'] == policy['sourceHashes'], 'SOURCE_HASH')
        need(r['workflowSha'] == workflow_sha and str(r['runId']) == str(run_id) and r['runAttempt'] == 1, 'RUN_BINDING')
        need(r['node'] == '24.22.1' and r['pnpm'] == '12.15.0' and r['profile'] == 'cliStartup', 'TOOLS_PROFILE')
        need(r['status'] == 'QUARANTINED_CANDIDATE' and r['hostExecution'] is False, 'QUALIFICATION')
        need(r['runtimeQualification'] == 'UNRUN' and r['signedProvenance'] is False, 'QUALIFICATION')
        need(r['lifecycleHooks'] == 'SUPPRESSED; NONE ENABLED', 'LIFECYCLE')
        need(all(x['exit'] == 0 for x in r['steps']), 'STEP_EXIT')
        need({'fetch', 'install', 'cliStartup', 'source-clean'} <= {x['step'] for x in r['steps']}, 'STEP_INVENTORY')
        return {'status': 'QUARANTINED_CANDIDATE', 'screening': 'CONSISTENCY_CHECK_PASS',
                'files': len(actual), 'links': len(links), 'scripts': scripts, 'nativeInventory': binaries,
                'independentSecurityBoundary': False, 'runtimeQualification': 'UNRUN',
                'hostExecution': False, 'source': r['source'], 'workflowSha': workflow_sha, 'runId': str(run_id)}


def test_build_preamble(powershell):
    """Developer-only test of reviewed production statements; never loads a payload."""
    import base64
    import os
    import subprocess
    import tempfile
    script = Path(__file__).resolve().with_name('Build.ps1')
    shell = Path(powershell).resolve(strict=True)
    need(shell.name.lower() == 'pwsh.exe', 'POWERSHELL_EXECUTABLE')
    harness = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null; $parseErrors = $null
$sourceText = [IO.File]::ReadAllText($env:PREAMBLE_SOURCE)
$ast = [System.Management.Automation.Language.Parser]::ParseInput($sourceText,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'PRODUCTION_PARSE' }
$boundaries = @($ast.EndBlock.Statements | Where-Object {
  $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$receipts'
})
if ($boundaries.Count -ne 1) { throw 'PREAMBLE_BOUNDARY' }
$prefix = $sourceText.Substring(0,$boundaries[0].Extent.StartOffset)
$prefixAst = [System.Management.Automation.Language.Parser]::ParseInput($prefix,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'PREFIX_PARSE' }
$allowed = @('Join-Path','Test-Path','New-Item','Set-StrictMode')
$commands = @($prefixAst.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true))
foreach ($command in $commands) {
  if ($allowed -cnotcontains $command.GetCommandName() -or
      $command.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown) {
    throw 'UNREVIEWED_PREAMBLE_COMMAND'
  }
}
if (@($prefixAst.FindAll({param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]},$true)).Count) {
  throw 'UNREVIEWED_PREAMBLE_MEMBER_CALL'
}
# Names/options only: never collect automatic variable values.
$protected = @(Get-Variable | Where-Object {
  $_.Options -band ([System.Management.Automation.ScopedItemOptions]::ReadOnly -bor
                    [System.Management.Automation.ScopedItemOptions]::Constant)
} | ForEach-Object Name) + @('HOME','PID','PSVersionTable','PSScriptRoot','PSCommandPath',
                            'args','input','Error','MyInvocation','PSBoundParameters','CODEX_HOME')
$bindings = @($ast.FindAll({param($n)
  $n -is [System.Management.Automation.Language.AssignmentStatementAst] -or
  $n -is [System.Management.Automation.Language.ParameterAst] -or
  $n -is [System.Management.Automation.Language.ForEachStatementAst]
},$true))
$names = foreach ($binding in $bindings) {
  if ($binding -is [System.Management.Automation.Language.AssignmentStatementAst]) {
    if ($binding.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
      $binding.Left.VariablePath.UserPath -replace '^script:',''
    }
  } elseif ($binding -is [System.Management.Automation.Language.ParameterAst]) {
    $binding.Name.VariablePath.UserPath
  } else { $binding.Variable.VariablePath.UserPath }
}
$collisions = @($names | Where-Object { $protected -icontains $_ } | Sort-Object -Unique)
function Invoke-PreambleProbe([string]$Code,[string]$Case) {
  $env:RUNNER_TEMP = Join-Path $env:FIXTURE_ROOT $Case
  $null = New-Item -ItemType Directory -Path $env:RUNNER_TEMP
  try {
    . ([scriptblock]::Create($Code))
    if ($Case -eq 'original') { throw 'OLD_BUG_NOT_DETECTED' }
    $expected = Join-Path (Join-Path $env:RUNNER_TEMP 'cpa-synthetic') 'home'
    if ($builderHome -cne $expected) { throw 'SYNTHETIC_HOME' }
    foreach ($key in @('TEMP','TMP','HOME','USERPROFILE','APPDATA','LOCALAPPDATA')) {
      if ($childEnv[$key] -cne $expected) { throw 'CHILD_ENV_BINDING' }
    }
    foreach ($key in @('NPM_CONFIG_USERCONFIG','NPM_CONFIG_GLOBALCONFIG')) {
      if (-not $childEnv[$key].StartsWith($expected + [IO.Path]::DirectorySeparatorChar)) {
        throw 'SYNTHETIC_CONFIG_PATH'
      }
    }
    foreach ($path in @($src,$tools,$builderHome,$store,$out)) {
      if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw 'FIXTURE_DIRECTORY' }
    }
    return @{case=$Case;result='PASS';initialization='COMPLETE'}
  } catch {
    if ($Case -eq 'original' -and $_.FullyQualifiedErrorId -eq 'VariableNotWritable') {
      if (@(Get-ChildItem -LiteralPath $env:RUNNER_TEMP -Force).Count) { throw 'OLD_BUG_SIDE_EFFECT' }
      return @{case=$Case;result='EXPECTED_FAIL';errorId='VariableNotWritable'}
    }
    if ($_.FullyQualifiedErrorId -eq 'VariableNotWritable') { throw 'PREAMBLE_AUTOMATIC_VARIABLE' }
    throw 'PREAMBLE_REGRESSION_FAILED'
  }
}
$fixed = Invoke-PreambleProbe $prefix 'fixed'
if ($collisions.Count) { throw 'AUTOMATIC_VARIABLE_COLLISION' }
if (-not $prefix.Contains('$builderHome = ') -or $prefix.Contains('$home = ')) { throw 'REPAIR_BINDING' }
# Recreate the former production spelling in memory, not a duplicate preamble.
$original = Invoke-PreambleProbe ($prefix.Replace('$builderHome','$home')) 'original'
@{status='PASS';powershell=$PSVersionTable.PSVersion.ToString();fixed=$fixed;original=$original;
  preambleEndOffset=$boundaries[0].Extent.StartOffset;productionBindingsReviewed=@($names).Count;
  automaticVariableCollisions=$collisions;networkOrBuildInvoked=$false} | ConvertTo-Json -Depth 5 -Compress
"""
    # A fresh synthetic HOME and a small allowlist, never inherited auth/config.
    with tempfile.TemporaryDirectory(prefix='.preamble-', dir=script.parent.parent) as fixture:
        system = Path(os.environ['SystemRoot'])
        environment = {'SystemRoot': str(system), 'WINDIR': str(system),
                       'ComSpec': str(system / 'System32/cmd.exe'),
                       'HOME': fixture, 'USERPROFILE': fixture, 'APPDATA': fixture,
                       'LOCALAPPDATA': fixture, 'TEMP': fixture, 'TMP': fixture,
                       'PREAMBLE_SOURCE': str(script), 'FIXTURE_ROOT': fixture,
                       'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Windows',
                       'GITHUB_REPOSITORY': 'tranquocvy/openclaw-windows-builder',
                       'CPA_RUN_ATTEMPT': '1', 'CPA_RUN_ID': 'synthetic'}
        encoded = base64.b64encode(harness.encode('utf-16le')).decode()
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive',
                                 '-EncodedCommand', encoded], cwd=fixture, env=environment,
                                capture_output=True, timeout=30)
        if result.returncode and b'PREAMBLE_AUTOMATIC_VARIABLE' in result.stderr:
            raise Rejected('AUTOMATIC_VARIABLE_RUNTIME')
        need(result.returncode == 0, 'PREAMBLE_RUNTIME_REGRESSION')
        report = json.loads(result.stdout.decode('utf-8-sig').strip())
        need(report['status'] == 'PASS' and report['original']['result'] == 'EXPECTED_FAIL',
             'REGRESSION_RECEIPT')
        report['productionSha256'] = hashlib.sha256(script.read_bytes()).hexdigest()
    report['fixtureCleanup'] = not Path(fixture).exists()
    need(report['fixtureCleanup'], 'FIXTURE_CLEANUP')
    return report


def main():
    parser = argparse.ArgumentParser()
    for key in ('archive', 'checksums', 'policy', 'report', 'workflow-sha', 'run-id'):
        parser.add_argument('--' + key, required=True)
    args = parser.parse_args()
    try:
        policy = json.loads(Path(args.policy).read_text(encoding='utf-8'))
        path = Path(args.archive)
        need(path.stat().st_size <= policy['maxCompressedBytes'], 'COMPRESSED_CAP')
        checksum = Path(args.checksums).read_text(encoding='utf-8').strip().split('  ')
        need(len(checksum) == 2 and checksum[1] == path.name, 'OUTER_CHECKSUM')
        digest = hashlib.sha256()
        with path.open('rb') as src:
            for part in iter(lambda: src.read(1024 * 1024), b''):
                digest.update(part)
        need(digest.hexdigest() == checksum[0], 'OUTER_CHECKSUM')
        report = validate_archive(path, policy, args.workflow_sha, args.run_id)
        report['archiveSha256'] = digest.hexdigest()
        dest = Path(args.report)
        need(not dest.exists(), 'REPORT_EXISTS')
        encoded = (json.dumps(report, indent=2) + '\n').encode()
        need(len(encoded) <= 1024 * 1024, 'REPORT_CAP')
        with dest.open('xb') as target:
            target.write(encoded)
        print('CONSISTENCY_CHECK_PASS; QUARANTINED_CANDIDATE; hostExecution=false')
    except Rejected as exc:
        print('CANDIDATE_REJECTED: ' + str(exc))
        return 1
    except Exception:
        # Malformed/untrusted values, file names and exception text stay private.
        print('CANDIDATE_REJECTED: MALFORMED_OR_IO')
        return 1
    return 0


if __name__ == '__main__':
    import sys
    if sys.argv[1:2] == ['--test-build-preamble']:
        parser = argparse.ArgumentParser()
        parser.add_argument('--test-build-preamble', action='store_true')
        parser.add_argument('--powershell', required=True)
        args = parser.parse_args()
        try:
            print(json.dumps(test_build_preamble(args.powershell), indent=2))
        except Rejected as exc:
            print('PREAMBLE_TEST_FAILED: ' + str(exc))
            raise SystemExit(1)
        except Exception:
            print('PREAMBLE_TEST_FAILED; no raw exception output')
            raise SystemExit(1)
    else:
        raise SystemExit(main())
