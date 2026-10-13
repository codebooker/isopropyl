"""Wrap the Windows native test runtime in a user-level, self-extracting EXE."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import argparse
import hashlib
import subprocess
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture',choices=('x86-64','arm64'),default='x86-64')
    parser.add_argument('--bundle',type=Path)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    args.bundle=args.bundle or ROOT/('dist/ISOpropyl-Windows-'+args.architecture+'-test.zip')
    args.output=args.output or ROOT/('dist/ISOpropyl-Windows-'+args.architecture+'-portable.exe')
    version=hashlib.sha256(args.bundle.read_bytes()).hexdigest()[:16]
    with tempfile.TemporaryDirectory(prefix='isopropyl-exe-') as directory:
        work=Path(directory)
        with zipfile.ZipFile(args.bundle) as archive:archive.extractall(work)
        payload=work/('ISOpropyl-Windows-'+args.architecture)
        if not (payload/'runtime/pythonw.exe').is_file():raise ValueError('Missing native Windows runtime')
        script=work/'portable.nsi'
        script.write_text('''Unicode true
!include "x64.nsh"
!include "FileFunc.nsh"
Name "ISOpropyl"
OutFile "/work/ISOpropyl.exe"
Icon "/work/ISOpropyl.ico"
RequestExecutionLevel user
SilentInstall silent
AutoCloseWindow true
SetCompressor /SOLID lzma
SetCompressorDictSize 32
VIProductVersion "0.1.0.0"
VIAddVersionKey /LANG=1033 "ProductName" "ISOpropyl"
VIAddVersionKey /LANG=1033 "FileDescription" "ISOpropyl portable Windows x86-64 test app"
VIAddVersionKey /LANG=1033 "FileVersion" "0.1.0"
Section
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "This package requires 64-bit Windows."
    Quit
  ${EndIf}
  StrCpy $INSTDIR "$LOCALAPPDATA\\ISOpropyl\\portable\\VERSION"
  IfFileExists "$INSTDIR\\ready.txt" start
  SetOutPath "$INSTDIR"
  File /r "/work/ISOpropyl-Windows-x86-64/*"
  FileOpen $0 "$INSTDIR\\ready.txt" w
  FileWrite $0 "VERSION"
  FileClose $0
start:
  ${GetParameters} $R0
  StrCmp $R0 "/tests" tests
  Exec '\"$INSTDIR\\runtime\\pythonw.exe\" \"$INSTDIR\\launch.py\" $R0'
  IfErrors failed
  Quit
tests:
  ExecWait '\"$INSTDIR\\runtime\\python.exe\" \"$INSTDIR\\test_windows.py\"'
  ExecShell "open" "$INSTDIR\\windows-test-results.txt"
  Quit
failed:
  MessageBox MB_OK|MB_ICONSTOP "ISOpropyl could not launch. The extracted runtime is at $INSTDIR."
SectionEnd
'''.replace('VERSION',version).replace('ISOpropyl-Windows-x86-64','ISOpropyl-Windows-'+args.architecture).replace('Windows x86-64 test app','Windows '+args.architecture+' test app'))
        (work/'ISOpropyl.ico').write_bytes((ROOT/'data/io.github.codebooker.isopropyl.ico').read_bytes())
        subprocess.run(['docker','run','--rm','--platform','linux/amd64','-v',f'{work}:/work',
            'debian:trixie-slim','sh','-c','apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nsis > /tmp/apt.log && makensis -V2 /work/portable.nsi'],check=True)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_bytes((work/'ISOpropyl.exe').read_bytes())
    print(args.output)
    print('SHA-256:',hashlib.sha256(args.output.read_bytes()).hexdigest())


if __name__=='__main__':main()
