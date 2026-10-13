#!/usr/bin/env python3
"""Patch pinned e2fsprogs' MinGW scandir to copy complete directory entries."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
import sys
root=Path(sys.argv[1]);path=root/'misc/create_inode.c';source=path.read_text()
# MinGW documents d_reclen as always zero; the POSIX variable-size idiom
# allocates and copies zero bytes, then lstat receives an empty filename.
old='malloc((dent->d_reclen + 3) & ~3)'
new='malloc(sizeof(*dent))'
if old not in source:raise ValueError('Pinned Windows scandir allocation changed')
source=source.replace(old,new).replace('memcpy(temp_list[num_dent], dent, dent->d_reclen);','memcpy(temp_list[num_dent], dent, sizeof(*dent));')
path.write_text(source)
