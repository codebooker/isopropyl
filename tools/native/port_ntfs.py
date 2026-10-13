#!/usr/bin/env python3
"""Preserve GNU/Clang NTFS on-disk packing on Windows.

Upstream's legacy MSVC compatibility header erases __attribute__ on WINDOWS.
LLVM MinGW supports those attributes; erasing them only in library include
orders changes the MFT ABI relative to the formatter and corrupts images.
"""
# SPDX-License-Identifier: GPL-2.0-or-later
import sys
from pathlib import Path
root=Path(sys.argv[1])
path=root/'include/ntfs-3g/compat.h'
source=path.read_text()
old='#define __attribute__(X)\t/*nothing*/'
new='#if !defined(__GNUC__) && !defined(__clang__)\n'+old+'\n#endif'
if source.count(old)!=1:raise SystemExit('Unexpected pinned NTFS compatibility header')
path.write_text(source.replace(old,new))
