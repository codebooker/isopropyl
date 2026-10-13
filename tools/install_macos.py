"""Install a non-editable macOS runtime outside privacy-protected project folders."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import argparse
import os
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME = Path.home()/'Library/Application Support/ISOpropyl/runtime'


def install_app():
    bundle = Path.home()/'Applications/ISOpropyl.app'
    contents = bundle/'Contents'
    (contents/'MacOS').mkdir(parents=True, exist_ok=True)
    (contents/'Resources').mkdir(exist_ok=True)
    executable = contents/'MacOS/ISOpropyl'
    subprocess.run(['/usr/bin/clang', '-arch', 'arm64', '-mmacosx-version-min=13.0', '-O2', '-Wall', '-Wextra',
                    str(ROOT/'tools/macos_launcher.c'), '-o', str(executable)], check=True)
    (contents/'Resources/runtime.txt').write_text(str(DEFAULT_RUNTIME)+'\n')
    shutil.copyfile(ROOT/'data/io.github.codebooker.isopropyl.icns', contents/'Resources/ISOpropyl.icns')
    with (contents/'Info.plist').open('wb') as stream:
        plistlib.dump({'CFBundleExecutable':'ISOpropyl', 'CFBundleIdentifier':'io.github.codebooker.isopropyl',
                      'CFBundleName':'ISOpropyl', 'CFBundleDisplayName':'ISOpropyl', 'CFBundlePackageType':'APPL',
                      'CFBundleVersion':'1', 'CFBundleShortVersionString':'0.1.0', 'LSMinimumSystemVersion':'13.0',
                      'CFBundleIconFile':'ISOpropyl.icns',
                      'NSHighResolutionCapable':True,
                      'NSRemovableVolumesUsageDescription':'ISOpropyl reads and writes the USB drive you explicitly select and confirm.'}, stream)
    subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--identifier',
                    'io.github.codebooker.isopropyl', str(bundle)], check=True)
    return bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel', type=Path, help='install an already built ISOpropyl wheel')
    parser.add_argument('--launch', action='store_true')
    args = parser.parse_args()
    if sys.platform != 'darwin' or platform.machine().lower() != 'arm64' or os.geteuid() == 0:
        parser.error('Run as a regular user with native Apple silicon Python')
    python = DEFAULT_RUNTIME/'bin/python'
    if not (DEFAULT_RUNTIME/'pyvenv.cfg').is_file():
        venv.EnvBuilder(with_pip=True, symlinks=True).create(DEFAULT_RUNTIME)
    else:
        subprocess.run([str(python), '-m', 'ensurepip', '--upgrade'], check=True)
    with tempfile.TemporaryDirectory(prefix='isopropyl-wheel-') as directory:
        wheel = args.wheel.resolve() if args.wheel else None
        if wheel is None:
            subprocess.run([str(python), '-m', 'pip', 'wheel', '--no-deps', '--wheel-dir', directory, str(ROOT)], check=True)
            wheels = list(Path(directory).glob('isopropyl-*.whl'))
            if len(wheels) != 1:
                raise RuntimeError('Build did not produce one ISOpropyl wheel')
            wheel = wheels[0]
        subprocess.run([str(python), '-m', 'pip', 'install', '--force-reinstall', '--no-deps', str(wheel)], check=True)
        subprocess.run([str(python), '-m', 'pip', 'install', str(wheel)], check=True)
    launcher = DEFAULT_RUNTIME/'bin/isopropyl'
    print(f'Installed: {launcher}')
    bundle = install_app()
    print(f'App: {bundle}')
    if args.launch:
        subprocess.run(['/usr/bin/open', str(bundle)], check=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
