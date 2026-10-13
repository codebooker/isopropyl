"""Smoke-test packaged helpers using private regular files only."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import argparse
import subprocess
import sys
import hashlib
import tempfile
from pathlib import Path
from isopropyl.helper_tools import helper

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-all',action='store_true')
    args=parser.parse_args()
    required=['mke2fs','mkntfs','ntfs-tree','mkudffs','wimlib-imagex','7z','qemu-img','gpgv']
    if sys.platform=='darwin':required+=['fls','icat']
    if args.require_all:
        for name in required:
            print(name,helper(name))
    with tempfile.TemporaryDirectory(prefix='isopropyl-helper-check-') as tmp:
        directory=Path(tmp)
        tree=directory/'tree';tree.mkdir();(tree/'nested').mkdir()
        payload=b'ISOpropyl helper validation\x00\xff'*1024
        source=tree/'nested/payload.bin';source.write_bytes(payload)
        ext=directory/'ext.img'
        with ext.open('wb') as stream:stream.truncate(64*1024*1024)
        subprocess.run([helper('mke2fs'),'-q','-F','-t','ext4','-d',str(tree),str(ext)],check=True)
        ntfs=directory/'ntfs.img'
        with ntfs.open('wb') as stream:stream.truncate(64*1024*1024)
        subprocess.run([helper('mkntfs'),'-F','-f','-s','512',str(ntfs)],check=True)
        subprocess.run([helper('ntfs-tree'),str(ntfs),'mkdir','nested'],check=True)
        subprocess.run([helper('ntfs-tree'),str(ntfs),'write','nested/payload.bin',str(source)],check=True)
        assert subprocess.check_output([helper('ntfs-tree'),str(ntfs),'read','nested/payload.bin'])==payload
        from isopropyl.native_filesystems import verify_filesystem
        class RegularImageVerifier:
            def check_cancelled(self):pass
        expected={'nested/payload.bin':(len(payload),hashlib.sha256(payload).hexdigest())}
        for image,kind in ((ext,'ext4'),(ntfs,'ntfs')):
            verify_filesystem(image,expected,kind,RegularImageVerifier())
            if sys.platform!='darwin':continue
            listing=subprocess.check_output([helper('fls'),'-r','-p',str(image)],text=True)
            records=[line for line in listing.splitlines() if line.endswith('\tnested/payload.bin')]
            assert len(records)==1,listing
            inode=records[0].split(':',1)[0].split()[-1]
            assert subprocess.check_output([helper('icat'),str(image),inode])==payload
    print('Native helper regular-image validation passed')
if __name__=='__main__':main()
