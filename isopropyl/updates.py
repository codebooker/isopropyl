"""Official GitHub release discovery and verified, cancellable update staging."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from dataclasses import dataclass
import hashlib
import hmac
import importlib.metadata
import json
import os
import platform
from pathlib import Path
import re
import shutil
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

REPOSITORY = 'https://github.com/codebooker/isopropyl'
LATEST_URL = 'https://api.github.com/repos/codebooker/isopropyl/releases/latest'
MANIFEST_NAME = 'isopropyl-update.json'
MAX_ASSET_SIZE = 8 * 1024**3
MAX_METADATA_SIZE = 2 * 1024**2
KINDS = {'wheel', 'deb', 'portable-zip', 'offline-wheelhouse'}


class UpdateError(RuntimeError):
    pass


class UpdateCancelled(UpdateError):
    pass


@dataclass(frozen=True)
class UpdateAsset:
    os: str
    arch: str
    kind: str
    name: str
    size: int
    sha256: str
    url: str


@dataclass(frozen=True)
class Release:
    version: str
    title: str
    notes: str
    page_url: str
    asset: UpdateAsset


def current_version():
    try:
        return importlib.metadata.version('isopropyl')
    except importlib.metadata.PackageNotFoundError:
        from . import __version__
        return __version__


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})', value):
        raise UpdateError('Update version must be a stable major.minor.patch version')
    return tuple(map(int, value.split('.')))


def _target(host=None, arch=None, kind=None):
    host = host or sys.platform
    host = {'darwin': 'macos', 'win32': 'windows'}.get(host, host)
    arch = (arch or platform.machine()).lower()
    arch = {'amd64': 'x86_64', 'x86-64': 'x86_64', 'aarch64': 'arm64'}.get(arch, arch)
    if host not in {'linux', 'windows', 'macos'} or arch not in {'x86_64', 'arm64'} or (host == 'macos' and arch != 'arm64'):
        raise UpdateError('This operating system or architecture has no supported update package')
    if kind is None:
        if host == 'windows': kind = 'portable-zip'
        elif host == 'macos': kind = 'offline-wheelhouse'
        else: kind = 'deb' if Path('/var/lib/dpkg/info/isopropyl.list').exists() and sys.prefix == sys.base_prefix else 'wheel'
    if kind not in KINDS:
        raise UpdateError('Unsupported update package kind')
    return host, arch, kind


def _name(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,199}', name) or '..' in name:
        raise UpdateError('Unsafe release asset filename')
    return name


def _asset_url(tag, name):
    return REPOSITORY + '/releases/download/' + tag + '/' + _name(name)


def _catalog(payload):
    assets = payload.get('assets')
    if not isinstance(assets, list) or len(assets) > 128:
        raise UpdateError('Invalid release asset catalog')
    result = {}
    tag = payload.get('tag_name')
    for asset in assets:
        if not isinstance(asset, dict): raise UpdateError('Invalid release asset')
        name = _name(asset.get('name'))
        if name in result: raise UpdateError('Duplicate release asset filename')
        if asset.get('browser_download_url') != _asset_url(tag, name):
            raise UpdateError('Release asset URL is outside the official release')
        size = asset.get('size')
        if type(size) is not int or not 0 < size <= MAX_ASSET_SIZE:
            raise UpdateError('Release asset size is invalid')
        result[name] = asset
    return result


def parse_release(payload, manifest, *, version=None, host=None, arch=None, kind=None):
    """Validate metadata and select exactly one newer package for this installation."""
    if not isinstance(payload, dict): raise UpdateError('Invalid GitHub release response')
    if payload.get('draft') is not False or payload.get('prerelease') is not False:
        return None
    tag = payload.get('tag_name')
    if not isinstance(tag, str) or not tag.startswith('v'): raise UpdateError('Release tag must be vMAJOR.MINOR.PATCH')
    new = _version(tag[1:]); old = _version(version or current_version())
    if new <= old: return None
    if payload.get('html_url') != REPOSITORY + '/releases/tag/' + tag:
        raise UpdateError('Release page is outside the official repository')
    catalog = _catalog(payload)
    if not isinstance(manifest, dict) or type(manifest.get('schema')) is not int or manifest['schema'] != 1 or manifest.get('version') != tag[1:]:
        raise UpdateError('Update manifest schema or version does not match the release')
    entries = manifest.get('assets')
    if not isinstance(entries, list) or not 1 <= len(entries) <= 64:
        raise UpdateError('Invalid update manifest asset list')
    target = _target(host, arch, kind); matches = []; seen = set()
    for entry in entries:
        if not isinstance(entry, dict): raise UpdateError('Invalid update manifest entry')
        key = entry.get('os'), entry.get('arch'), entry.get('kind')
        if key[0] not in {'linux', 'macos', 'windows'} or key[1] not in {'x86_64', 'arm64'} or key[2] not in KINDS or key in seen:
            raise UpdateError('Unsupported or duplicate update manifest target')
        seen.add(key)
        name = _name(entry.get('name')); row = catalog.get(name)
        digest = entry.get('sha256')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise UpdateError('Every update package requires a SHA-256 checksum')
        if row is None or type(entry.get('size')) is not int or entry['size'] != row['size']:
            raise UpdateError('Update manifest asset does not match the GitHub release catalog')
        if row.get('digest') not in (None, 'sha256:' + digest):
            raise UpdateError('GitHub and manifest SHA-256 checksums disagree')
        expected_suffix = {'wheel': '.whl', 'deb': '.deb', 'portable-zip': '.zip', 'offline-wheelhouse': '.zip'}[key[2]]
        if not name.endswith(expected_suffix): raise UpdateError('Update package extension does not match its kind')
        if key == target: matches.append(UpdateAsset(*key, name, row['size'], digest, row['browser_download_url']))
    if not matches: raise UpdateError('This release has no update package for this installation')
    title, notes = payload.get('name') or tag, payload.get('body') or ''
    if not isinstance(title, str) or not isinstance(notes, str) or len(title) > 1000 or len(notes) > MAX_METADATA_SIZE:
        raise UpdateError('Invalid release notes')
    return Release(tag[1:], title, notes, payload['html_url'], matches[0])


def _check(cancel_check, deadline):
    if cancel_check and cancel_check(): raise UpdateCancelled('Update cancelled')
    if time.monotonic() > deadline: raise UpdateError('Update network operation timed out')


def _https(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (ValueError, TypeError) as error:
        raise UpdateError('Invalid update URL') from error
    if parsed.scheme != 'https' or parsed.username or parsed.password or port not in (None, 443) or parsed.fragment:
        raise UpdateError('Update requests require HTTPS official URLs')
    if parsed.hostname not in {'api.github.com', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}:
        raise UpdateError('Update redirect left the official GitHub asset hosts')


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _https(newurl)
        count = getattr(req, '_update_redirects', 0) + 1
        if count > 5: raise UpdateError('Too many update redirects')
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        if result is not None: result._update_redirects = count
        return result


def _open(url, opener):
    _https(url)
    request = urllib.request.Request(url, headers={'User-Agent': 'ISOpropyl-updater', 'Accept': 'application/vnd.github+json' if url == LATEST_URL else 'application/octet-stream', 'X-GitHub-Api-Version': '2022-11-28'})
    response = (opener or urllib.request.build_opener(_Redirect()).open)(request, timeout=15)
    try:
        _https(response.geturl())
        if response.getcode() != 200: raise UpdateError('Update server did not return HTTP 200')
        if response.headers.get('Content-Encoding', 'identity') != 'identity': raise UpdateError('Encoded update responses are not accepted')
    except BaseException:
        response.close(); raise
    return response


def _read(url, limit, opener, cancel_check, deadline):
    _check(cancel_check, deadline)
    with _open(url, opener) as response:
        result = bytearray()
        while True:
            _check(cancel_check, deadline)
            chunk = response.read(min(65536, limit + 1 - len(result)))
            if not chunk: return bytes(result)
            result.extend(chunk)
            if len(result) > limit: raise UpdateError('Update metadata exceeds its size limit')


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise UpdateError('Duplicate update metadata key')
            result[key] = value
        return result
    try: return json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as error: raise UpdateError('Invalid update JSON') from error


def check_for_update(*, version=None, host=None, arch=None, kind=None, cancel_check=None, opener=None):
    deadline = time.monotonic() + 60
    try:
        try: payload = _json(_read(LATEST_URL, MAX_METADATA_SIZE, opener, cancel_check, deadline))
        except urllib.error.HTTPError as error:
            if error.code == 404: return None
            raise
        if not isinstance(payload, dict): raise UpdateError('Invalid GitHub release response')
        if payload.get('draft') is not False or payload.get('prerelease') is not False: return None
        tag = payload.get('tag_name', '')
        if not isinstance(tag, str) or not tag.startswith('v'): raise UpdateError('Invalid release tag')
        if _version(tag[1:]) <= _version(version or current_version()): return None
        catalog = _catalog(payload)
        row = catalog.get(MANIFEST_NAME)
        if row is None or row['size'] > MAX_METADATA_SIZE: raise UpdateError('Release has no bounded update manifest')
        data = _read(row['browser_download_url'], row['size'], opener, cancel_check, deadline)
        if len(data) != row['size']: raise UpdateError('Truncated update manifest')
        if row.get('digest') not in (None, 'sha256:' + hashlib.sha256(data).hexdigest()): raise UpdateError('Update manifest digest mismatch')
        return parse_release(payload, _json(data), version=version, host=host, arch=arch, kind=kind)
    except (OSError, ValueError) as error:
        from .verified_download import safe_error_detail
        raise UpdateError('Could not check for updates: ' + safe_error_detail(error)) from error


def download_update(release, stagingdir, progress=None, cancel_check=None, *, opener=None):
    """Return a verified private staged file; delete all partial data on failure."""
    from .portable_fs import os as private_os
    if type(release) is not Release or type(release.asset) is not UpdateAsset: raise UpdateError('Invalid selected release')
    asset = release.asset
    _version(release.version)
    if asset.url != _asset_url('v' + release.version, asset.name) or not re.fullmatch('[0-9a-f]{64}', asset.sha256) or type(asset.size) is not int or not 0 < asset.size <= MAX_ASSET_SIZE:
        raise UpdateError('Invalid update artifact authority')
    parent = Path(stagingdir).resolve(strict=True)
    root = parent / ('isopropyl-update-' + uuid.uuid4().hex)
    private_os.mkdir(root, 0o700)
    path = root / asset.name
    deadline = time.monotonic() + 1800
    try:
        info = private_os.lstat(root)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != private_os.geteuid(): raise UpdateError('Update workspace is not private')
        if shutil.disk_usage(root).free < asset.size + 16 * 1024**2: raise UpdateError('Not enough free space for the update')
        digest = hashlib.sha256(); total = 0
        _check(cancel_check, deadline)
        with _open(asset.url, opener) as response, path.open('xb', buffering=0) as output:
            advertised = response.headers.get('Content-Length')
            if advertised is not None and advertised != str(asset.size): raise UpdateError('Update response size differs from the manifest')
            while True:
                _check(cancel_check, deadline)
                chunk = response.read(min(1024**2, asset.size + 1 - total))
                if not chunk: break
                total += len(chunk)
                if total > asset.size: raise UpdateError('Update exceeds its declared size')
                output.write(chunk); digest.update(chunk)
                if progress: progress(total, asset.size)
            output.flush(); os.fsync(output.fileno())
        if total != asset.size or not hmac.compare_digest(digest.hexdigest(), asset.sha256): raise UpdateError('Update failed its SHA-256 or size verification')
        # Read the staged bytes independently before handing them to installation.
        verify = hashlib.sha256()
        with path.open('rb') as source:
            while True:
                _check(cancel_check, deadline)
                chunk = source.read(1024**2)
                if not chunk: break
                verify.update(chunk)
        if not hmac.compare_digest(verify.hexdigest(), asset.sha256): raise UpdateError('Staged update changed during verification')
        return path
    except BaseException as error:
        shutil.rmtree(root, ignore_errors=True)
        if isinstance(error, OSError):
            from .verified_download import safe_error_detail
            raise UpdateError('Could not download the update: ' + safe_error_detail(error)) from error
        raise
