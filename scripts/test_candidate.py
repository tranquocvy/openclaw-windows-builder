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


def prepare_runtime(source, destination, policy):
    """Project declared runtime package units; never import/execute candidate code."""
    import contextlib
    import ctypes
    from ctypes import wintypes
    import os
    import msvcrt
    need(os.name == 'nt', 'WINDOWS_EXPORT_REQUIRED')
    root = Path(os.path.abspath(source))
    output = Path(os.path.abspath(destination))
    need(bool(re.fullmatch(r'[a-zA-Z]:', root.drive)) and
         bool(re.fullmatch(r'[a-zA-Z]:', output.drive)), 'EXPORT_LOCAL_VOLUME_REQUIRED')
    need(root.is_dir() and output.is_dir(), 'EXPORT_ROOTS')
    need(not output.is_relative_to(root) and not root.is_relative_to(output), 'EXPORT_ROOTS')
    deny = re.compile(r'^(\.env($|\.)|\.npmrc$|auth\.json$|credentials?\.)', re.I)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    class Info(ctypes.Structure):
        _fields_ = [('attrs', wintypes.DWORD), ('created', wintypes.FILETIME),
                    ('access', wintypes.FILETIME), ('written', wintypes.FILETIME),
                    ('volume', wintypes.DWORD), ('sizeHigh', wintypes.DWORD),
                    ('sizeLow', wintypes.DWORD), ('links', wintypes.DWORD),
                    ('indexHigh', wintypes.DWORD), ('indexLow', wintypes.DWORD)]
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(Info)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                               wintypes.DWORD, wintypes.DWORD]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    invalid = ctypes.c_void_p(-1).value
    current = kernel.GetCurrentProcess
    current.restype = wintypes.HANDLE
    files, aliases, packages, identities, deferred = {}, {}, set(), {}, {}
    total = 0

    def relative(path):
        try:
            rel = Path(os.path.abspath(path)).relative_to(root).as_posix()
        except ValueError:
            raise Rejected('EXPORT_PATH_ESCAPE') from None
        need(rel != '.', 'EXPORT_ROOT_ALIAS')
        need(not any(deny.search(part) for part in rel.split('/')), 'Forbidden export filename')
        safe_path(rel)
        need(not sensitive(rel.encode('utf-8')), 'EXPORT_PATH_CONTENT_BLOCKED')
        return rel

    @contextlib.contextmanager
    def locked(path, directory=False, destination_parent=False, new_file=False):
        path = Path(os.path.abspath(path))
        # No reparse ancestor,including ancestors outside the source root.
        handles = []
        try:
            chain = [*reversed(path.parents), path]
            for index, item in enumerate(chain):
                last = index == len(chain) - 1
                is_dir = not last or directory
                access = 0x80 if is_dir else (0xC0000000 if last and new_file else 0x80000000)
                disposition = 1 if last and new_file else 3
                handle = kernel.CreateFileW(str(item), access, 1, None, disposition, 0x02200000, None)
                need(handle not in (None, invalid), 'EXPORT_LOCK_FAILED')
                handles.append(handle)
                info = Info()
                need(kernel.GetFileInformationByHandle(handle, ctypes.byref(info)), 'EXPORT_IDENTITY')
                need(not info.attrs & 0x400, 'EXPORT_REPARSE_ANCESTOR')
                need(bool(info.attrs & 0x10) == is_dir, 'EXPORT_OBJECT_TYPE')
                if last:
                    need(is_dir or info.links == 1, 'EXPORT_HARDLINK')
                    buf = ctypes.create_unicode_buffer(32768)
                    size = kernel.GetFinalPathNameByHandleW(handle, buf, len(buf), 0)
                    need(0 < size < len(buf), 'EXPORT_CANONICAL_PATH')
                    final = buf.value
                    if final.startswith('\\\\?\\UNC\\'):
                        final = '\\\\' + final[8:]
                    elif final.startswith('\\\\?\\'):
                        final = final[4:]
                    need(os.path.normcase(os.path.abspath(final)) ==
                         os.path.normcase(str(path)), 'EXPORT_CANONICAL_PATH')
                    token = (info.volume, info.indexHigh, info.indexLow, info.sizeHigh,
                             info.sizeLow, info.written.dwHighDateTime, info.written.dwLowDateTime)
            yield handles[-1], token
        finally:
            for handle in reversed(handles):
                kernel.CloseHandle(handle)

    def read(path):
        rel = relative(path)
        with locked(path) as (handle, identity):
            if rel in identities:
                need(identities[rel] == identity, 'EXPORT_CHANGED_SNAPSHOT')
            identities[rel] = identity
            size = (identity[3] << 32) | identity[4]
            need(size <= policy['maxFileBytes'], 'FILE_CAP')
            # Duplicate handle ownership for a standard-library read;locks remain held.
            current = kernel.GetCurrentProcess
            current.restype = wintypes.HANDLE
            duplicate = wintypes.HANDLE()
            kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                wintypes.BOOL, wintypes.DWORD]
            need(kernel.DuplicateHandle(current(), handle, current(), ctypes.byref(duplicate),
                                        0, False, 2), 'EXPORT_READ_HANDLE')
            fd = msvcrt.open_osfhandle(duplicate.value, os.O_RDONLY | os.O_BINARY)
            with os.fdopen(fd, 'rb') as stream:
                data = stream.read(size + 1)
            need(len(data) == size and not sensitive(data), 'EXPORT_CONTENT_BLOCKED')
            return data

    def metadata(directory):
        data = read(directory / 'package.json')
        need(len(data) <= 32 * 1024 * 1024, 'METADATA_CAP')
        try:
            obj = json.loads(data, object_pairs_hook=strict_object)
        except (ValueError, UnicodeError):
            raise Rejected('EXPORT_PACKAGE_METADATA') from None
        need(isinstance(obj, dict), 'EXPORT_PACKAGE_METADATA')
        return obj

    def select(path):
        nonlocal total
        rel = relative(path)
        key = rel.casefold()
        need(key not in aliases, 'EXPORT_LINK_SHADOW')
        if key in files:
            need(files[key]['rel'] == rel, 'EXPORT_CASE_COLLISION')
            return
        data = read(path)
        total += len(data)
        need(total <= policy['maxExpandedBytes'] and (len(files) + len(aliases)) < policy['maxEntries'], 'EXPORT_CAP')
        files[key] = {'rel': rel, 'path': path, 'bytes': len(data),
                      'sha256': hashlib.sha256(data).hexdigest()}

    def resolve_link(path):
        rel = relative(path)
        target_text = os.readlink(path)
        if target_text.startswith('\\\\?\\'):
            need(bool(re.match(r'^[a-zA-Z]:[\\\\/]', target_text[4:])), 'EXPORT_LINK_DEVICE_UNKNOWN')
            target_text = target_text[4:]
        target = Path(os.path.abspath(path.parent / target_text))
        tr = relative(target)
        with locked(target, directory=True):
            pass
        key = rel.casefold()
        need(key not in files and tr.casefold() != key, 'EXPORT_LINK_ALIAS')
        row = {'path': rel, 'target': tr, 'directory': True}
        need(key not in aliases or aliases[key] == row, 'EXPORT_LINK_ALIAS')
        need(key in aliases or len(files) + len(aliases) < policy['maxEntries'], 'EXPORT_CAP')
        aliases[key] = row
        return target

    def tree(directory, depth=0):
        need(depth <= 100, 'EXPORT_DEPTH')
        relative(directory)
        with locked(directory, directory=True):
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
            for item in entries:
                path = Path(item.path)
                relative(path)  # Names checked before contents or reparse handling.
                if item.stat(follow_symlinks=False).st_file_attributes & 0x400:
                    # Links are admitted later only if a declared dependency resolves through them.
                    deferred[relative(path).casefold()] = path
                    continue
                if item.is_dir(follow_symlinks=False):
                    if item.name == 'node_modules':
                        continue  # Dependencies are selected below,not copied en masse.
                    tree(path, depth + 1)
                elif item.is_file(follow_symlinks=False):
                    select(path)
                else:
                    raise Rejected('EXPORT_OBJECT_TYPE')

    def dependency(from_dir, name, optional=False):
        need(isinstance(name, str) and bool(re.fullmatch(
            r'(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*', name)), 'EXPORT_DEPENDENCY_NAME')
        directory = from_dir
        while directory == root or directory.is_relative_to(root):
            location = directory / 'node_modules' / name
            relative(location)
            if os.path.lexists(location):
                with locked(location.parent, directory=True):
                    pass
                if location.lstat().st_file_attributes & 0x400:
                    target = resolve_link(location)
                else:
                    target = location
                obj = metadata(target)
                need(obj.get('name') == name, 'EXPORT_PACKAGE_IDENTITY_UNKNOWN')
                package(target)
                bins = obj.get('bin', {})
                if isinstance(bins, str):
                    bins = {obj.get('name', '').split('/')[-1]: bins}
                need(isinstance(bins, dict), 'EXPORT_BIN_METADATA')
                base_modules = location.parent.parent if name.startswith('@') else location.parent
                for bin_name in bins:
                    need(bool(re.fullmatch(r'[a-zA-Z0-9._-]+', bin_name)), 'EXPORT_BIN_NAME')
                    for suffix in ('', '.cmd', '.ps1'):
                        shim = base_modules / '.bin' / (bin_name + suffix)
                        if os.path.lexists(shim):
                            select(shim)
                return
            if directory == root:
                break
            directory = directory.parent
        need(optional, 'EXPORT_MISSING_DEPENDENCY')

    def declared_dependencies(directory, obj):
        required = obj.get('dependencies', {})
        optional = obj.get('optionalDependencies', {})
        peers = obj.get('peerDependencies', {})
        need(all(isinstance(x, dict) for x in (required, optional, peers)), 'EXPORT_DEPENDENCIES')
        for name in sorted(set(required) | set(optional) | set(peers)):
            peer_optional = obj.get('peerDependenciesMeta', {}).get(name, {}).get('optional') is True
            is_optional = name in optional or (name not in required and peer_optional)
            dependency(directory, name, is_optional)

    def entries(directory, obj):
        # Validate declared runtime entry paths;types are not Node runtime conditions.
        def walk(value, condition=None):
            if condition == 'types':
                return
            if isinstance(value, str):
                if value.startswith('./'):
                    need('?' not in value and not any(c in value for c in '[]{}'), 'EXPORT_DYNAMIC_ENTRY_UNKNOWN')
                    marker = '_export_wildcard_'
                    need(marker not in value, 'EXPORT_DYNAMIC_ENTRY_UNKNOWN')
                    safe_path(value[2:].replace('*', marker))
                    target = directory / value[2:].replace('*', marker)
                    pattern = relative(target).replace(marker, '*').casefold() if '*' in value else relative(target).casefold()
                    if '*' in value:
                        import fnmatch
                        need(any(fnmatch.fnmatchcase(k, pattern) for k in files), 'EXPORT_MISSING_ENTRY')
                    else:
                        need(pattern in files, 'EXPORT_MISSING_ENTRY')
                else:
                    raise Rejected('EXPORT_ENTRY_UNKNOWN')
            elif isinstance(value, dict):
                for key, item in value.items():
                    walk(item, key)
            elif isinstance(value, list):
                raise Rejected('EXPORT_ENTRY_ALTERNATIVES_UNKNOWN')
            else:
                need(value is None, 'EXPORT_ENTRY_UNKNOWN')
        for field in ('main', 'module', 'exports', 'imports'):
            if field in obj:
                value = obj[field]
                if field != 'exports' and isinstance(value, str) and not value.startswith('./'):
                    value = './' + value
                walk(value)
        plugin = obj.get('openclaw')
        if plugin is not None:
            need(isinstance(plugin, dict), 'EXPORT_PLUGIN_METADATA')
            if 'extensions' in plugin:
                need(isinstance(plugin['extensions'], list), 'EXPORT_PLUGIN_METADATA')
                for entry in plugin['extensions']:
                    need(isinstance(entry, str), 'EXPORT_PLUGIN_METADATA')
                    walk(entry)
            if 'setupEntry' in plugin:
                need(isinstance(plugin['setupEntry'], str), 'EXPORT_PLUGIN_METADATA')
                walk(plugin['setupEntry'])

    def package(directory):
        rel = relative(directory)
        if rel.casefold() in packages:
            return
        with locked(directory, directory=True):
            pass
        packages.add(rel.casefold())
        obj = metadata(directory)
        select(directory / 'package.json')
        # Workspace source must declare its supported packaged surface explicitly.
        if rel.startswith(('packages/', 'extensions/')):
            shipped = obj.get('files')
            need(isinstance(shipped, list) and shipped, 'EXPORT_WORKSPACE_SURFACE_UNKNOWN')
            for part in shipped:
                need(isinstance(part, str) and part and not any(x in part for x in '*?![]{}'),
                     'EXPORT_WORKSPACE_GLOB_UNKNOWN')
                safe_path(part.removeprefix('./').rstrip('/'))
                target = directory / part.removeprefix('./').rstrip('/')
                relative(target)
                if not target.exists():
                    need(part.upper() in ('LICENSE', 'README.MD', 'CHANGELOG.MD'), 'EXPORT_MISSING_PACKAGE_FILE')
                    continue
                if target.is_dir():
                    tree(target)
                else:
                    select(target)
        else:
            need(rel.startswith('node_modules/'), 'EXPORT_PACKAGE_ROOT_UNKNOWN')
            # Registry packages are installed distribution units;preserve their native/assets/source.
            tree(directory)
        entries(directory, obj)
        declared_dependencies(directory, obj)
        bins = obj.get('bin', {})
        if isinstance(bins, str):
            bins = {obj.get('name', '').split('/')[-1]: bins}
        need(isinstance(bins, dict), 'EXPORT_BIN_METADATA')
        for name, entry in bins.items():
            need(isinstance(entry, str), 'EXPORT_BIN_METADATA')
            safe_path(entry.removeprefix('./'))
            target = directory / entry.removeprefix('./')
            need(relative(target).casefold() in files, 'EXPORT_MISSING_BIN')
            need(bool(re.fullmatch(r'[a-zA-Z0-9._-]+', name)), 'EXPORT_BIN_NAME')
            # Preserve existing Windows shims when present;never execute or generate them.
            for suffix in ('', '.cmd', '.ps1'):
                shim = directory.parent / '.bin' / (name + suffix)
                if os.path.lexists(shim):
                    select(shim)

    def write_new(dst, data, expected_hash):
        with locked(dst, new_file=True) as (handle, identity):
            duplicate = wintypes.HANDLE()
            need(kernel.DuplicateHandle(current(), handle, current(), ctypes.byref(duplicate),
                                        0, False, 2), 'EXPORT_WRITE_HANDLE')
            fd = msvcrt.open_osfhandle(duplicate.value, os.O_RDWR | os.O_BINARY)
            with os.fdopen(fd, 'w+b') as stream:
                stream.write(data)
                stream.flush()
                stream.seek(0)
                need(hashlib.sha256(stream.read()).hexdigest() == expected_hash, 'EXPORT_WRITE_HASH')

    with locked(root, directory=True), locked(output, directory=True, destination_parent=True):
        need(not any(output.iterdir()), 'EXPORT_ROOTS')
        need(not any(os.path.lexists(output.parent / n) for n in ('files.json', 'links.json')),
             'EXPORT_MANIFEST_COLLISION')
        root_obj = metadata(root)
        select(root / 'package.json')
        for name in policy['rootFiles']:
            safe_path(name)
            if name == 'package.json':
                continue
            target = root / name
            if target.exists():
                select(target)
        need((root / 'dist').is_dir(), 'EXPORT_MISSING_DIST')
        tree(root / 'dist')
        for needed in ('dist/entry.js', 'dist/runtime-dependency-ownership.json'):
            need(needed.casefold() in files, 'EXPORT_MISSING_ENTRY')
        entries(root, root_obj)
        declared_dependencies(root, root_obj)
        # Generated built plugin manifests own their dependencies,not source plugin manifests.
        for item in list(files.values()):
            rel = item['rel']
            if rel.startswith('dist/extensions/') and rel.endswith('/package.json'):
                directory = item['path'].parent
                obj = metadata(directory)
                entries(directory, obj)
                declared_dependencies(directory, obj)
        need(set(deferred) <= set(aliases), 'EXPORT_UNDECLARED_REPARSE')
        for alias in aliases.values():
            target = alias['target'].casefold()
            need(any(k.startswith(target + '/') for k in files), 'EXPORT_LINK_TARGET')
            need(not any(target == a or target.startswith(a + '/') for a in aliases), 'EXPORT_LINK_CHAIN')
        # No payload writes until selection,required edges and content checks all pass.
        for item in files.values():
            data = read(item['path'])
            need(hashlib.sha256(data).hexdigest() == item['sha256'], 'EXPORT_CHANGED_SNAPSHOT')
            dst = output / item['rel']
            parent = output
            for part in item['rel'].split('/')[:-1]:
                with locked(parent, directory=True, destination_parent=True):
                    child = parent / part
                    if not os.path.lexists(child):
                        child.mkdir()
                    with locked(child, directory=True, destination_parent=True):
                        pass
                parent = child
            write_new(dst, data, item['sha256'])
        rows = [{'path': 'runtime/' + x['rel'], 'bytes': x['bytes'], 'sha256': x['sha256']}
                for x in sorted(files.values(), key=lambda x: x['rel'])]
        link_rows = sorted(aliases.values(), key=lambda x: x['path'])
        for filename, values in [('files.json', rows), ('links.json', link_rows)]:
            data = (json.dumps(values, separators=(',', ':')) + '\n').encode('utf-8')
            need(len(data) <= 32 * 1024 * 1024, 'METADATA_CAP')
            write_new(output.parent / filename, data, hashlib.sha256(data).hexdigest())
        return rows, link_rows



def test_runtime_export():
    """Bounded Windows production-function tests;all payloads/canaries are synthetic."""
    import contextlib
    import copy
    import ctypes
    import inspect
    import io
    import os
    import subprocess
    import tempfile
    import time
    from unittest import mock
    public = Path(__file__).resolve().parents[1]
    base_policy = json.loads((public / 'policy/artifact-policy.json').read_text(encoding='utf-8'))
    reports = []
    deadline = time.monotonic() + 90
    # Generated,declared FAKE test input. Never log/store it in test receipts.
    fake_canary = (b'ghp_' + b'Q' * 36)
    real_sha = hashlib.sha256

    @contextlib.contextmanager
    def fixture(source_name='source'):
        temporary = tempfile.TemporaryDirectory(prefix='.export-', dir=public)
        owned = Path(temporary.name)
        try:
            need(owned.resolve().parent == public.resolve() and not owned.is_symlink(), 'FIXTURE_BOUNDARY')
            source = owned / source_name
            destination = owned / 'payload/runtime'
            source.mkdir();destination.mkdir(parents=True)
            def put(rel, value):
                path = source / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(value if isinstance(value, bytes) else
                                 json.dumps(value).encode() if isinstance(value, dict) else value.encode())
                return path
            put('package.json', {'name':'synthetic-root','dependencies':{'runtime-dep':'1'},
                                 'devDependencies':{'dev-only':'1'}})
            put('dist/entry.js', '// synthetic compiled entry')
            put('dist/runtime-dependency-ownership.json', {'chunks':{}})
            put('node_modules/runtime-dep/package.json', {'name':'runtime-dep','main':'./index.js'})
            put('node_modules/runtime-dep/index.js', '// synthetic runtime module')
            put('node_modules/dev-only/credentials.ts', '// excluded synthetic development source')
            put('extensions/unselected/src/credentials.ts', '// excluded synthetic source')
            yield owned, source, destination, put
        finally:
            need(owned.resolve().parent == public.resolve() and not owned.is_symlink(), 'FIXTURE_BOUNDARY')
            temporary.cleanup()
            need(not owned.exists(), 'FIXTURE_CLEANUP')

    def junction(link, target, owned):
        link.parent.mkdir(parents=True, exist_ok=True)
        system = Path(os.environ['SystemRoot'])
        env = {'SystemRoot':str(system),'WINDIR':str(system),'PATH':str(system/'System32'),
               'TEMP':str(owned),'TMP':str(owned)}
        p = subprocess.run([str(system/'System32/cmd.exe'),'/d','/c','mklink','/J',
                            str(link),str(target)],cwd=owned,env=env,capture_output=True,timeout=5)
        need(p.returncode == 0, 'SYNTHETIC_JUNCTION_UNAVAILABLE')

    def run(name, change=None, rejection=None, exporter=None, policy_change=None):
        need(time.monotonic() < deadline, 'TEST_DEADLINE')
        with fixture() as (owned, source, destination, put):
            policy = copy.deepcopy(base_policy)
            if change:
                change(owned, source, destination, put)
            if policy_change:
                policy_change(policy)
            stdout = io.StringIO()
            try:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
                    rows, links = (exporter or prepare_runtime)(source,destination,policy)
            except Rejected as exc:
                need(rejection is not None and str(exc) == rejection, 'UNEXPECTED_EXPORT_REJECTION')
                need(not any(destination.iterdir()), 'REJECTED_BEFORE_PAYLOAD_COPY')
                rows, links = [], []
            else:
                need(rejection is None, 'MISSING_REQUIRED_REJECTION')
                names = {x['path'] for x in rows}
                need('runtime/dist/entry.js' in names and
                     'runtime/node_modules/runtime-dep/index.js' in names, 'VALID_RUNTIME_MISSING')
                need(not any('dev-only' in x or 'unselected' in x for x in names), 'DEVELOPMENT_EXPORTED')
                for row in rows:
                    data = (destination.parent / row['path']).read_bytes()
                    need(len(data) == row['bytes'] and real_sha(data).hexdigest() == row['sha256'], 'MANIFEST_HASH')
                need(json.loads((destination.parent/'files.json').read_text()) == rows, 'MANIFEST_BYTES')
                need(json.loads((destination.parent/'links.json').read_text()) == links, 'MANIFEST_BYTES')
            need(fake_canary.decode() not in stdout.getvalue(), 'TEST_OUTPUT_CANARY')
            return {'case':name,'status':'LOCAL_RUNTIME_VERIFIED','expectedRejection':rejection,
                    'files':len(rows),'links':len(links),'cleanup':True}

    reports.append(run('valid-runtime-and-development-omission'))
    for filename in ['.env','.env.example','.npmrc','auth.json','credentials.ts','credentials.test.ts','Credentials.JSON']:
        reports.append(run('deny-name-'+filename,
            lambda o,s,d,p,n=filename:p('dist/'+n,'// synthetic benign body'),
            'Forbidden export filename'))
    reports.append(run('credential-like-content',
        lambda o,s,d,p:p('dist/canary.txt',fake_canary),'EXPORT_CONTENT_BLOCKED'))
    reports.append(run('credential-like-path',
        lambda o,s,d,p:p('dist/'+fake_canary.decode(),'// synthetic'),
        'EXPORT_PATH_CONTENT_BLOCKED'))
    reports.append(run('missing-declared-dependency',
        lambda o,s,d,p:p('package.json',{'dependencies':{'missing-runtime':'1'}}),
        'EXPORT_MISSING_DEPENDENCY'))
    reports.append(run('missing-declared-entry',
        lambda o,s,d,p:p('node_modules/runtime-dep/package.json',
                        {'name':'runtime-dep','main':'./absent.js'}),'EXPORT_MISSING_ENTRY'))
    for value in ['./../other.js','./dist/../other.js','C:/synthetic-outside','//synthetic-server/share']:
        reports.append(run('entry-path-normalization',
            lambda o,s,d,p,v=value:p('node_modules/runtime-dep/package.json',{'name':'runtime-dep','main':v}),
            'PATH' if value.startswith('./') else 'PATH'))
    reports.append(run('trailing-dot-name',
        lambda o,s,d,p:p('package.json',{'dependencies':{'runtime-dep':'1'}}),
        'PATH',policy_change=lambda p:p['rootFiles'].append('synthetic.')))
    reports.append(run('case-insensitive-selection-collision',
        lambda o,s,d,p:p('Case.js','// synthetic'),
        'EXPORT_CASE_COLLISION',policy_change=lambda p:p['rootFiles'].extend(['Case.js','case.js'])))
    def hardlink(o,s,d,p):
        original=p('dist/entry.js','// synthetic compiled entry')
        os.link(original,o/'hardlink-synthetic.txt')
    reports.append(run('source-hardlink',hardlink,'EXPORT_HARDLINK'))
    def external_link(o,s,d,p):
        target=o/'protected-synthetic';target.mkdir()
        junction(s/'dist/escape',target,o)
    reports.append(run('unresolved-external-junction',external_link,'EXPORT_UNDECLARED_REPARSE'))
    def dependency_escape(o,s,d,p):
        target=o/'protected-synthetic';target.mkdir()
        junction(s/'node_modules/escape',target,o)
        p('package.json',{'dependencies':{'escape':'1'}})
    reports.append(run('declared-junction-escape',dependency_escape,'EXPORT_PATH_ESCAPE'))
    def reparse_ancestor(o,s,d,p):
        target=o/'protected-synthetic';target.mkdir()
        junction(s/'node_modules/scope',target,o)
        p('package.json',{'dependencies':{'scope':'1'}})
    reports.append(run('dependency-target-outside',reparse_ancestor,'EXPORT_PATH_ESCAPE'))
    def workspace(o,s,d,p):
        target=s/'packages/synthetic-workspace'
        p('packages/synthetic-workspace/package.json',
          {'name':'synthetic-workspace','files':['dist'],'main':'./dist/index.js'})
        p('packages/synthetic-workspace/dist/index.js','// synthetic compiled workspace')
        p('packages/synthetic-workspace/src/credentials.ts','// excluded source')
        junction(s/'node_modules/synthetic-workspace',target,o)
        p('package.json',{'dependencies':{'runtime-dep':'1','synthetic-workspace':'1'}})
    reports.append(run('workspace-dist-selection-and-internal-link',workspace))
    def no_surface(o,s,d,p):
        workspace(o,s,d,p)
        p('packages/synthetic-workspace/package.json',{'name':'synthetic-workspace','main':'./src/index.ts'})
    reports.append(run('unknown-workspace-surface',no_surface,'EXPORT_WORKSPACE_SURFACE_UNKNOWN'))
    def ancestor_link(o,s,d,p):
        workspace(o,s,d,p)
        directory=s/'packages/synthetic-workspace/dist'
        need(directory.is_relative_to(o) and not directory.is_symlink(), 'FIXTURE_BOUNDARY')
        (directory/'index.js').unlink();directory.rmdir()
        target=o/'protected-synthetic';target.mkdir()
        junction(directory,target,o)
    reports.append(run('selected-reparse-ancestor',ancestor_link,'EXPORT_REPARSE_ANCESTOR'))
    with fixture() as (owned,source,destination,put):
        target=owned/'protected-synthetic.txt';target.write_text('synthetic only')
        alias=source/'dist/synthetic-link'
        try:
            os.symlink(target,alias)
        except OSError:
            reports.append({'case':'native-symbolic-link','status':'BLOCKED',
                            'reason':'HOST_SYMLINK_PRIVILEGE_OR_FEATURE_UNAVAILABLE','cleanup':True})
        else:
            try:prepare_runtime(source,destination,copy.deepcopy(base_policy))
            except Rejected as exc:need(str(exc)=='EXPORT_UNDECLARED_REPARSE','SYMLINK_NOT_REJECTED')
            else:raise Rejected('SYMLINK_NOT_REJECTED')
            reports.append({'case':'native-symbolic-link','status':'LOCAL_RUNTIME_VERIFIED','cleanup':True})
    # Exercise the same CLI production Build.ps1 calls,with an explicit synthetic-only child environment.
    for failure in (False,True):
        with fixture('source with spaces' if not failure else 'source') as (owned,source,destination,put):
            if failure:
                put('dist/credentials.ts','synthetic benign name-policy fixture')
            import sys
            system=Path(os.environ['SystemRoot'])
            env={'SystemRoot':str(system),'WINDIR':str(system),'PATH':str(system/'System32'),
                 'TEMP':str(owned),'TMP':str(owned)}
            process=subprocess.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),
                '--prepare-runtime','--source',str(source),'--destination',str(destination),
                '--policy',str(public/'policy/artifact-policy.json'),
                '--files',str(destination.parent/'files.json'),'--links',str(destination.parent/'links.json')],
                env=env,cwd=owned,capture_output=True,timeout=15)
            output=process.stdout+process.stderr
            need(fake_canary not in output and b'Traceback' not in output,'CLI_OUTPUT')
            need(process.returncode==(1 if failure else 0),'CLI_STATUS')
            if failure:need(not any(destination.iterdir()),'CLI_DENY_BEFORE_COPY')
            reports.append({'case':'production-cli-reject' if failure else 'production-cli-valid',
                            'status':'LOCAL_RUNTIME_VERIFIED','cleanup':True})

    reports.append(run('unpacked-size-boundary',None,'EXPORT_CAP',
                       policy_change=lambda p:p.update(maxExpandedBytes=1)))

    def manifest_hardlink(o,s,d,p):
        protected=o/'protected-synthetic.txt';protected.write_text('synthetic protected metadata')
        os.link(protected,d.parent/'files.json')
    reports.append(run('manifest-hardlink-collision',manifest_hardlink,'EXPORT_MANIFEST_COLLISION'))
    def link_chain(o,s,d,p):
        junction(s/'node_modules/chain-a',s/'node_modules/runtime-dep',o)
        junction(s/'node_modules/chain-b',s/'node_modules/chain-a',o)
        p('package.json',{'dependencies':{'chain-b':'1'}})
    reports.append(run('dependency-link-chain',link_chain,'EXPORT_REPARSE_ANCESTOR'))
    with fixture() as (owned,source,destination,put):
        original_entry=(source/'dist/entry.js').read_bytes()
        changed=[False]
        def inject(data=b'',*args,**kwargs):
            result=real_sha(data,*args,**kwargs)
            if data==original_entry and not changed[0]:
                changed[0]=True
                put('dist/entry.js','// changed synthetic snapshot with different size')
            return result
        with mock.patch.object(hashlib,'sha256',side_effect=inject):
            try:prepare_runtime(source,destination,copy.deepcopy(base_policy))
            except Rejected as exc:need(str(exc)=='EXPORT_CHANGED_SNAPSHOT','SNAPSHOT_NOT_REJECTED')
            else:raise Rejected('SNAPSHOT_NOT_REJECTED')
        need(changed[0] and not (destination.parent/'files.json').exists(),'FAILED_SNAPSHOT_PUBLISHED')
        reports.append({'case':'changed-source-snapshot','status':'LOCAL_RUNTIME_VERIFIED','cleanup':True})
    def built_plugin(o,s,d,p):
        p('dist/extensions/synthetic-plugin/package.json',
          {'name':'synthetic-plugin','openclaw':{'extensions':['./index.js'],'setupEntry':'./setup.js'}})
        p('dist/extensions/synthetic-plugin/index.js','// synthetic compiled plugin')
        p('dist/extensions/synthetic-plugin/setup.js','// synthetic compiled setup')
    reports.append(run('compiled-plugin-metadata-entries',built_plugin))
    def missing_plugin(o,s,d,p):
        built_plugin(o,s,d,p)
        p('dist/extensions/synthetic-plugin/package.json',
          {'openclaw':{'extensions':['./missing.js']}})
    reports.append(run('missing-openclaw-plugin-entry',missing_plugin,'EXPORT_MISSING_ENTRY'))
    def missing_setup(o,s,d,p):
        built_plugin(o,s,d,p)
        p('dist/extensions/synthetic-plugin/package.json',
          {'openclaw':{'extensions':['./index.js'],'setupEntry':'./missing-setup.js'}})
    reports.append(run('missing-openclaw-setup-entry',missing_setup,'EXPORT_MISSING_ENTRY'))
    # Native payload/link topology plus actual ZIP validator;no real native executable is run.
    with fixture() as (owned,source,destination,put):
        native = base_policy['nativeOwners'][1]
        name = native['package'].rsplit('@',1)[0]
        folder = 'node_modules/.pnpm/'+native['pnpmPrefix']+'/node_modules/'+name
        put(folder+'/package.json',{'name':name,'main':'./index.js'})
        put(folder+'/index.js','// synthetic native loader')
        put(folder+'/native.node',b'MZsynthetic-native')
        junction(source/'node_modules'/name,source/folder,owned)
        put('package.json',{'dependencies':{'runtime-dep':'1',name:'1'}})
        policy=copy.deepcopy(base_policy)
        rows,links=prepare_runtime(source,destination,policy)
        need(any(x['path'].endswith('/native.node') for x in rows) and len(links)==1,'NATIVE_OR_LINK_LOST')
        payload=destination.parent
        (payload/'node').mkdir()
        node=b'MZsynthetic-node';policy['nodeExeSha256']=real_sha(node).hexdigest()
        for rel,data in [('node/node.exe',node),('node/LICENSE',b'synthetic-license')]:
            (payload/rel).write_bytes(data)
            rows.append({'path':rel,'bytes':len(data),'sha256':real_sha(data).hexdigest()})
        (payload/'files.json').write_text(json.dumps(rows))
        receipt={'source':policy['source'],'tree':policy['sourceTree'],'sourceHashes':policy['sourceHashes'],
                 'workflowSha':'synthetic-workflow','runId':'synthetic-run','runAttempt':1,
                 'node':'24.22.1','pnpm':'12.15.0','profile':'cliStartup','status':'QUARANTINED_CANDIDATE',
                 'hostExecution':False,'runtimeQualification':'UNRUN','signedProvenance':False,
                 'lifecycleHooks':'SUPPRESSED; NONE ENABLED',
                 'steps':[{'step':x,'exit':0} for x in ['fetch','install','cliStartup','source-clean']]}
        (payload/'receipt.json').write_text(json.dumps(receipt))
        archive=io.BytesIO()
        with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED) as z:
            for path in payload.rglob('*'):
                need(not path.is_symlink() and not path.lstat().st_file_attributes & 0x400,'EXPORTED_REPARSE')
                if path.is_file():
                    z.writestr(path.relative_to(payload).as_posix(),path.read_bytes())
        data=archive.getvalue()
        result=validate_archive(io.BytesIO(data),policy,'synthetic-workflow','synthetic-run')
        need(result['status']=='QUARANTINED_CANDIDATE','ZIP_QUALIFICATION')
        reports.append({'case':'native-link-manifest-zip','status':'LOCAL_RUNTIME_VERIFIED',
                        'files':len(rows),'links':len(links),'cleanup':True})
        for key,boundary,category in [('maxCompressedBytes',len(data)-1,'COMPRESSED_CAP'),
                                      ('maxEntries',1,'ENTRY_CAP')]:
            bad=copy.deepcopy(policy);bad[key]=boundary
            try:validate_archive(io.BytesIO(data),bad,'synthetic-workflow','synthetic-run')
            except Rejected as exc:need(str(exc)==category,'WRONG_ZIP_CAP')
            else:raise Rejected('ZIP_CAP_NOT_ENFORCED')
        try:validate_archive(io.BytesIO(data),policy,'synthetic-other','synthetic-run')
        except Rejected as exc:need(str(exc)=='RUN_BINDING','WRONG_BINDING_REJECTION')
        else:raise Rejected('BINDING_NOT_ENFORCED')
        need(fake_canary not in data,'CANARY_IN_ZIP')
        reports.append({'case':'zip-size-entry-binding-negative','status':'LOCAL_RUNTIME_VERIFIED','cleanup':True})
    # Mutate the actual production function in an isolated namespace,never the file on disk.
    original=inspect.getsource(prepare_runtime)
    mutant=original.replace("        need(not any(deny.search(part) for part in rel.split('/')), 'Forbidden export filename')\n",'')
    mutant=mutant.replace('        safe_path(rel)\n','')  # Bypass redundant filename defence too.
    need(mutant!=original,'MUTATION_NOT_APPLIED')
    namespace={k:globals()[k] for k in ['Path','need','Rejected','strict_object','safe_path','sensitive','hashlib','re','json']}
    exec(compile(mutant,'<synthetic-production-deny-mutant>','exec'),namespace)
    try:
        run('mutated-production-name-guard',
            lambda o,s,d,p:p('dist/credentials.ts','// synthetic benign body'),
            'Forbidden export filename',namespace['prepare_runtime'])
    except Rejected as exc:
        need(str(exc)=='MISSING_REQUIRED_REJECTION','MUTATION_WRONG_FAILURE')
    else:
        raise Rejected('DENY_MUTATION_SURVIVED')
    reports.append({'case':'production-deny-mutation-killed','status':'LOCAL_RUNTIME_VERIFIED',
                    'mutation':'Primary and redundant filename checks bypassed in actual function fixture',
                    'cleanup':True})

    # Primary regex-only mutation is also detected before relying on the redundant name gate.
    primary=re.sub(r"deny = re\.compile\(r'[^']+', re\.I\)", "deny = re.compile(r'(?!)', re.I)", original, count=1)
    need(primary!=original,'MUTATION_NOT_APPLIED')
    namespace={k:globals()[k] for k in ['Path','need','Rejected','strict_object','safe_path','sensitive','hashlib','re','json']}
    exec(compile(primary,'<synthetic-primary-rule-mutant>','exec'),namespace)
    try:
        run('mutated-primary-deny-predicate',
            lambda o,s,d,p:p('dist/credentials.ts','// synthetic benign body'),
            'Forbidden export filename',namespace['prepare_runtime'])
    except Rejected as exc:
        need(str(exc)=='UNEXPECTED_EXPORT_REJECTION','MUTATION_WRONG_FAILURE')
    else:raise Rejected('PRIMARY_DENY_MUTATION_SURVIVED')
    reports.append({'case':'primary-production-deny-mutation-killed','status':'LOCAL_RUNTIME_VERIFIED',
                    'note':'Expected primary pre-copy rejection absent;redundant gate still rejected',
                    'cleanup':True})
    need(not list(public.glob('.export-*')),'FIXTURE_CLEANUP')
    return {'status':'PASS','cases':reports,'count':len(reports),'fixtureCleanup':True,
            'proof':'LOCAL_RUNTIME_VERIFIED synthetic production exporter and actual ZIP gate only',
            'realOpenClawClosure':'CI_RUNTIME_VERIFY','historicalD047Offender':'UNKNOWN',
            'nativePayloads':'SYNTHETIC_NOT_EXECUTED','policyOverrides':'IN_MEMORY_SYNTHETIC_HASH_AND_LOWERED_CAP_ONLY',
            'sourceToolchainActionWorkflowPolicyFilesChanged':False}


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



def test_build_launches(powershell, git, git_alternative, node):
    """Run only reviewed production bootstrap slices against synthetic resources."""
    import base64
    import os
    import shutil
    import subprocess
    import sys
    import tempfile
    script = Path(__file__).resolve().with_name('Build.ps1')
    root = script.parent.parent
    shell, git, git_alternative, node = (Path(x).resolve(strict=True) for x in
                                       (powershell, git, git_alternative, node))
    need(shell.name.lower() == 'pwsh.exe' and git.name.lower() == 'git.exe'
         and git_alternative.name.lower() == 'git.exe' and node.name.lower() == 'node.exe',
         'BOOTSTRAP_EXECUTABLE_NAMES')
    need(git.parent != git_alternative.parent, 'DISTINCT_DISCOVERY_DIRECTORIES')
    harness = r"""
$ErrorActionPreference='Stop'
$tokens=$null;$parseErrors=$null
$code=[IO.File]::ReadAllText($env:LAUNCH_SOURCE)
$ast=[System.Management.Automation.Language.Parser]::ParseInput($code,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'PRODUCTION_PARSE' }
$boundary=@($ast.EndBlock.Statements | Where-Object {
 $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -ceq '$receipts'
})
$function=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Run-Bounded'},$false))
$lookup=@($ast.EndBlock.Statements | Where-Object {$_.Extent.Text.StartsWith('$git = (Get-Command git.exe -CommandType Application')})
$pathSetup=@($ast.EndBlock.Statements | Where-Object {$_.Extent.Text.StartsWith('$childEnv.PATH = ')} | Select-Object -First 1)
$init=@($ast.EndBlock.Statements | Where-Object {$_.Extent.Text -ceq '$null = Run-Bounded ''git-init'' $git @(''init'',''--quiet'',''.'') 30'})
if ($boundary.Count -ne 1 -or $function.Count -ne 1 -or $lookup.Count -ne 1 -or $pathSetup.Count -ne 1 -or $init.Count -ne 1) { throw 'SOURCE_BOUNDARY' }
$prefix=$code.Substring(0,$boundary[0].Extent.StartOffset)
$prefixAst=[System.Management.Automation.Language.Parser]::ParseInput($prefix,[ref]$tokens,[ref]$parseErrors)
$allowed=@('Join-Path','Test-Path','New-Item','Set-StrictMode')
foreach ($command in $prefixAst.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true)) {
 if ($allowed -cnotcontains $command.GetCommandName() -or $command.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown) { throw 'UNREVIEWED_PREFIX' }
}
if (@($prefixAst.FindAll({param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst]},$true)).Count) { throw 'UNREVIEWED_PREFIX' }
. ([scriptblock]::Create($prefix))
$receipts=[System.Collections.Generic.List[object]]::new()
. ([scriptblock]::Create($function[0].Extent.Text))
$gitCandidates=@(Get-Command git.exe -CommandType Application)
. ([scriptblock]::Create($lookup[0].Extent.Text))
. ([scriptblock]::Create($pathSetup[0].Extent.Text))
$report=@{status='FAIL';powershell=$PSVersionTable.PSVersion.ToString();gitDiscoveryCandidates=$gitCandidates.Count;
 boundExecutableExists=[IO.File]::Exists([string]$git);workingDirectoryExists=[IO.Directory]::Exists($src);
 useShellExecute=$false;environmentKeys=@($childEnv.Keys|Sort-Object);cases=@()}
$startTime=Get-Date
$timeoutChild=$null
try {
 # Exact first production call, not a copy of its argument-binding logic.
 . ([scriptblock]::Create($init[0].Extent.Text))
 if (-not (Test-Path -LiteralPath (Join-Path $src '.git/HEAD'))) { throw 'SYNTHETIC_GIT_MISSING' }
 $top=Run-Bounded 'synthetic-root' $git @('rev-parse','--show-toplevel') 5
 if ([IO.Path]::GetFullPath($top) -ne [IO.Path]::GetFullPath($src)) { throw 'WRONG_REPOSITORY' }
 $report.cases+=@{id='production-git-init';result='PASS'}
 if (@($git).Count -ne 1 -or $git -ne $env:LAUNCH_GIT) { throw 'GIT_SELECTION' }
 $version=Run-Bounded 'synthetic-node-version' $env:LAUNCH_NODE @('--version') 5
 if ($version -ne 'v24.22.1') { throw 'NODE_VERSION' }
 $report.cases+=@{id='node-version';result='PASS'}
 $js='console.error("SYNTHETIC_STDERR");console.log(JSON.stringify({arg:process.argv[1],parentPresent:"SYNTHETIC_PARENT_ONLY" in process.env}))'
 $result=Run-Bounded 'synthetic-stdio' $env:LAUNCH_NODE @('-e',$js,'argument with spaces') 5
 $parsed=$result|ConvertFrom-Json
 if ($parsed.arg -ne 'argument with spaces' -or $parsed.parentPresent -ne $false -or $result.Contains('SYNTHETIC_STDERR')) { throw 'STDIO_OR_ENVIRONMENT' }
 $report.cases+=@{id='stdio-arguments-parent-env-filter';result='PASS'}
 $rejected=$false
 try { $null=Run-Bounded 'synthetic-exit' $env:LAUNCH_NODE @('-e','process.exit(7)') 5 }
 catch { if ($_.Exception.Message -eq 'Nonzero exit: synthetic-exit') { $rejected=$true } else { throw } }
 if (-not $rejected -or $receipts[$receipts.Count-1].exit -ne 7) { throw 'NONZERO_NOT_REJECTED' }
 $report.cases+=@{id='nonzero-exit';result='EXPECTED_REJECTION'}
 $rejected=$false
 $js='require("fs").writeFileSync("timeout-child.pid",String(process.pid));setInterval(()=>{},1000)'
 try { $null=Run-Bounded 'synthetic-timeout' $env:LAUNCH_NODE @('-e',$js) 1 }
 catch { if ($_.Exception.Message -eq 'Timeout: synthetic-timeout') { $rejected=$true } else { throw } }
 $pidFile=Join-Path $src 'timeout-child.pid'
 if (-not $rejected -or -not (Test-Path -LiteralPath $pidFile)) { throw 'TIMEOUT_NOT_EXERCISED' }
 $ownedId=[int][IO.File]::ReadAllText($pidFile)
 $timeoutChild=Get-Process -Id $ownedId -ErrorAction SilentlyContinue
 if ($null -ne $timeoutChild) { throw 'TIMEOUT_CHILD_ALIVE' }
 $report.cases+=@{id='timeout-kills-owned-child';result='EXPECTED_REJECTION';childAlive=$false}
 $rejected=$false
 try { $null=Run-Bounded 'synthetic-missing-exe' (Join-Path $tools 'missing.exe') @() 1 }
 catch { if ($_.Exception.Message -eq 'Executable unavailable: synthetic-missing-exe') { $rejected=$true } else { throw } }
 if (-not $rejected) { throw 'MISSING_EXE_NOT_REJECTED' }
 $report.cases+=@{id='missing-executable';result='EXPECTED_REJECTION'}
 $originalSrc=$src;$src=Join-Path $base 'missing-directory';$rejected=$false
 try { $null=Run-Bounded 'synthetic-missing-cwd' $git @('--version') 1 }
 catch { if ($_.Exception.Message -eq 'Working directory unavailable: synthetic-missing-cwd') { $rejected=$true } else { throw } }
 finally { $src=$originalSrc }
 if (-not $rejected) { throw 'MISSING_CWD_NOT_REJECTED' }
 $report.cases+=@{id='missing-working-directory';result='EXPECTED_REJECTION'}
 # Load only the real workflow's Python lookup; never execute any gate/upload.
 $pythonLines=@([IO.File]::ReadAllLines($env:LAUNCH_WORKFLOW) | Where-Object {$_.Trim().StartsWith('$python = (Get-Command python.exe -CommandType Application')})
 if ($pythonLines.Count -ne 1) { throw 'WORKFLOW_LOOKUP_BOUNDARY' }
 $report.pythonDiscoveryCandidates=@(Get-Command python.exe -CommandType Application).Count
 . ([scriptblock]::Create($pythonLines[0].Trim()))
 $pythonOutput=@(& $python -I -S -c 'print("SYNTHETIC_PYTHON")')
 if ($LASTEXITCODE -ne 0 -or $pythonOutput.Count -ne 1 -or $pythonOutput[0] -ne 'SYNTHETIC_PYTHON') { throw 'PYTHON_BOOTSTRAP' }
 if (@($python).Count -ne 1 -or $python -ne $env:LAUNCH_PYTHON) { throw 'PYTHON_SELECTION' }
 $report.cases+=@{id='production-workflow-python-lookup';result='PASS'}
 $report.status='PASS'
} catch {
 $report.failureType=$_.Exception.GetType().FullName
 $report.failureClassifiers=@(@('NativeCommandFailed','CommandNotFoundException','ProgramFailedToRun','InvalidOperation','PropertyNotFoundStrict','CantActivateDocumentInPipeline') | Where-Object {$Error[0].FullyQualifiedErrorId.Contains($_)})
 $report.messageCategories=@(@('Access is denied','cannot find','working directory','read-only','not recognized','could not be run','permission','NativeCommand') | Where-Object {$Error[0].Exception.Message.Contains($_)})
 $errorObject=$_.Exception;$nativeCodes=@()
 while ($null -ne $errorObject) {
  if ($errorObject -is [System.ComponentModel.Win32Exception]) { $nativeCodes+=$errorObject.NativeErrorCode }
  $errorObject=$errorObject.InnerException
 }
 $report.nativeErrorCodes=$nativeCodes
 $known=@('GIT_SELECTION','NODE_VERSION','PYTHON_SELECTION','PYTHON_BOOTSTRAP','SYNTHETIC_GIT_MISSING','WRONG_REPOSITORY','STDIO_OR_ENVIRONMENT','NONZERO_NOT_REJECTED','TIMEOUT_NOT_EXERCISED','TIMEOUT_CHILD_ALIVE','MISSING_EXE_NOT_REJECTED','MISSING_CWD_NOT_REJECTED','WORKFLOW_LOOKUP_BOUNDARY')
 $report.failureCategory=if ($known -contains $_.Exception.Message) { $_.Exception.Message } else { 'PRODUCTION_RUNTIME_EXCEPTION' }
} finally {
 # Recovery touches only the PID written by this synthetic Node fixture.
 $pidFile=Join-Path $src 'timeout-child.pid'
 if (Test-Path -LiteralPath $pidFile) {
  $ownedId=[int][IO.File]::ReadAllText($pidFile)
  $owned=Get-Process -Id $ownedId -ErrorAction SilentlyContinue
  if ($null -ne $owned) {
   if ($owned.Path -ne $env:LAUNCH_NODE -or $owned.StartTime -lt $startTime) { throw 'OWNED_CHILD_IDENTITY_UNCERTAIN' }
   $owned.Kill($true);$owned.WaitForExit()
  }
  $report.timeoutChildSettled=$null -eq (Get-Process -Id $ownedId -ErrorAction SilentlyContinue)
 }
}
$report.receipts=@($receipts.ToArray())
$report | ConvertTo-Json -Depth 7 -Compress
"""
    with tempfile.TemporaryDirectory(prefix='.launch-', dir=root) as fixture:
        directory = Path(fixture).resolve()
        need(directory.parent == root.resolve(), 'FIXTURE_SCOPE')
        alternative = directory / 'python-alternative'
        alternative.mkdir()
        shutil.copyfile(sys.executable, alternative / 'python.exe')
        system = Path(os.environ['SystemRoot'])
        environment = {'SystemRoot': str(system), 'WINDIR': str(system),
                       'ComSpec': str(system / 'System32/cmd.exe'),
                       'PATHEXT': '.COM;.EXE;.BAT;.CMD',
                       'PATH': ';'.join(map(str, [git.parent, git_alternative.parent,
                                                Path(sys.executable).parent, alternative])),
                       'HOME': fixture, 'USERPROFILE': fixture, 'APPDATA': fixture,
                       'LOCALAPPDATA': fixture, 'TEMP': fixture, 'TMP': fixture,
                       'RUNNER_TEMP': fixture, 'LAUNCH_SOURCE': str(script),
                       'LAUNCH_WORKFLOW': str(root / '.github/workflows/build-windows.yml'),
                       'LAUNCH_GIT': str(git), 'LAUNCH_NODE': str(node),
                       'LAUNCH_PYTHON': sys.executable,
                       'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Windows',
                       'GITHUB_REPOSITORY': 'tranquocvy/openclaw-windows-builder',
                       'CPA_RUN_ATTEMPT': '1', 'CPA_RUN_ID': 'synthetic',
                       'SYNTHETIC_PARENT_ONLY': 'synthetic-fixture'}
        encoded = base64.b64encode(harness.encode('utf-16le')).decode()
        process = subprocess.Popen([str(shell), '-NoProfile', '-NonInteractive',
                                    '-EncodedCommand', encoded], cwd=directory,
                                   env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            # Only this still-owned live process tree; never a global name kill.
            if process.poll() is None:
                subprocess.run([str(system / 'System32/taskkill.exe'), '/PID', str(process.pid),
                                '/T', '/F'], env=environment, capture_output=True, timeout=10)
            process.communicate(timeout=10)
            raise Rejected('BOOTSTRAP_OUTER_TIMEOUT')
        need(process.returncode == 0, 'BOOTSTRAP_HARNESS_RUNTIME')
        lines = stdout.decode('utf-8-sig').splitlines()
        report = json.loads(lines[-1])
        report['productionSha256'] = hashlib.sha256(script.read_bytes()).hexdigest()
        report['workflowSha256'] = hashlib.sha256((root / '.github/workflows/build-windows.yml').read_bytes()).hexdigest()
    report['fixtureCleanup'] = not directory.exists()
    need(report['fixtureCleanup'], 'BOOTSTRAP_FIXTURE_CLEANUP')
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
    elif sys.argv[1:2] == ['--test-build-launches']:
        parser = argparse.ArgumentParser()
        parser.add_argument('--test-build-launches', action='store_true')
        for key in ('powershell', 'git', 'git-alternative', 'node'):
            parser.add_argument('--' + key, required=True)
        args = parser.parse_args()
        try:
            report = test_build_launches(args.powershell, args.git, args.git_alternative, args.node)
            print(json.dumps(report, indent=2))
            raise SystemExit(0 if report['status'] == 'PASS' else 1)
        except Rejected as exc:
            print('BOOTSTRAP_TEST_FAILED: ' + str(exc))
            raise SystemExit(1)
        except Exception:
            print('BOOTSTRAP_TEST_FAILED; no raw exception output')
            raise SystemExit(1)
    elif sys.argv[1:2] == ['--test-runtime-export']:
        try:
            print(json.dumps(test_runtime_export(), indent=2))
        except Rejected as exc:
            print('RUNTIME_EXPORT_TEST_FAILED: ' + str(exc))
            raise SystemExit(1)
        except Exception:
            print('RUNTIME_EXPORT_TEST_FAILED; no raw exception output')
            raise SystemExit(1)
    elif sys.argv[1:2] == ['--prepare-runtime']:
        parser = argparse.ArgumentParser()
        parser.add_argument('--prepare-runtime', action='store_true')
        for key in ('source', 'destination', 'policy', 'files', 'links'):
            parser.add_argument('--' + key, required=True)
        args = parser.parse_args()
        try:
            policy = json.loads(Path(args.policy).read_text(encoding='utf-8'))
            base = Path(args.destination).absolute().parent
            need(Path(args.files).absolute() == base / 'files.json' and
                 Path(args.links).absolute() == base / 'links.json', 'EXPORT_MANIFEST_PATH')
            rows, links = prepare_runtime(args.source, args.destination, policy)
            print('Runtime export selected; qualification remains required')
        except Rejected as exc:
            print('RUNTIME_EXPORT_REJECTED: ' + str(exc))
            raise SystemExit(1)
        except Exception:
            print('RUNTIME_EXPORT_REJECTED; no raw exception output')
            raise SystemExit(1)
    else:
        raise SystemExit(main())
