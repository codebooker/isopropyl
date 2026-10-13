"""Download pinned native helper sources with mandatory SHA-256 validation."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import argparse
import hashlib
import json
import shutil
import urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',type=Path)
    args=parser.parse_args();args.destination.mkdir(parents=True,exist_ok=True)
    records=json.loads((ROOT/'tools/native-helper-sources.json').read_text())
    for name,record in records.items():
        path=args.destination/record['file']
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==record['sha256']:
            continue
        temporary=path.with_suffix(path.suffix+'.partial')
        digest=hashlib.sha256();size=0
        try:
            with urllib.request.urlopen(record['url'],timeout=60) as response, temporary.open('wb') as output:
                while True:
                    block=response.read(1024*1024)
                    if not block:break
                    size+=len(block)
                    if size>512*1024*1024:raise ValueError('Source archive exceeds size limit')
                    digest.update(block);output.write(block)
            if digest.hexdigest()!=record['sha256']:raise ValueError('Source checksum mismatch: '+name)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    for source in (ROOT/'tools/native').iterdir():
        if source.is_file() and source.suffix in {'.c','.h','.py','.sh','.manifest','.rc','.json'}:
            name='ntfs-tree.c' if source.name=='ntfs_tree.c' else source.name
            shutil.copyfile(source,args.destination/name)
if __name__=='__main__':main()
