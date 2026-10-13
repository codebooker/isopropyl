"""macOS / Windows raw writer CLI; importing this module needs no Qt."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path

from .devices import DeviceDiscoveryError, format_size
from .native_devices import discover
from .native_writer import NativeCancelled, NativeWriteError, NativeWriter, build_plan


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="ISOpropyl native raw writer for macOS and Windows")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="list safe USB/SD whole-disk targets")
    write = commands.add_parser("write", help="write and verify a raw, compressed or sparse disk image")
    tools = {}
    for operation, help_text in [('backup', 'save a verified full-drive raw backup'), ('format_fat32', 'create and verify a blank FAT32 drive with a full overwrite'), ('zero', 'overwrite and verify every drive byte as zero'), ('surface', 'destructively test the full advertised capacity'), ('fast_zero','scan and logically zero every drive byte'), ('capacity','sample drive capacity'), ('restore','restore a blank filesystem')]:
        tools[operation] = commands.add_parser(operation, help=help_text)
        tools[operation].add_argument('--target', required=True)
    tools['surface'].add_argument('--passes',type=int,choices=range(1,5),default=4)
    tools['surface'].add_argument('--capacity-first',action='store_true')
    tools['backup'].add_argument('destination')
    tools['backup'].add_argument('--sparse',action='store_true')
    tools['restore'].add_argument('--filesystem',choices=['fat12','fat16','fat32','exfat','ntfs','udf','ext2','ext3','ext4'],default='fat32')
    tools['restore'].add_argument('--partition-table',choices=['mbr','gpt'],default='mbr')
    tools['restore'].add_argument('--label',default='ISOPROPYL')
    tools['restore'].add_argument('--cluster-size',type=int)
    tools['restore'].add_argument('--full',action='store_true')
    inspection=commands.add_parser('inspect',help='inspect source and checksums');inspection.add_argument('image')
    for command in (listing, write, *tools.values()):
        command.add_argument("--include-usb-hard-drives", action="store_true", help="also allow fixed USB disks")
    write.add_argument("image")
    write.add_argument("--target", required=True, help="exact whole-disk path from the list command")
    write.add_argument("--no-verify",action="store_true",help="skip the extra final full hash; mandatory pre-activation verification remains")
    write.add_argument("--sha256", help="expected image checksum, checked before unmounting")
    write.add_argument('--mode',choices=['auto','dd','iso'],default='dd')
    write.add_argument('--filesystem',choices=['fat32','ntfs'],default='fat32')
    write.add_argument('--partition-table',choices=['mbr','gpt'],default='mbr')
    write.add_argument('--firmware',choices=['uefi','bios','both'],default='uefi')
    write.add_argument('--label',default='ISOPROPYL')
    write.add_argument('--cluster-size',type=int)
    write.add_argument('--persistence-mib',type=int,default=0)
    write.add_argument('--ubuntu-release',default='')
    write.add_argument('--zip-overlay',type=Path)
    args = parser.parse_args(argv)
    writer = NativeWriter()
    writer.final_verification=not getattr(args,"no_verify",False)
    previous = {}
    try:
        if args.command=='inspect':
            from .native_inspection import inspect_source
            print(inspect_source(args.image,writer));return 0
        devices = discover(args.include_usb_hard_drives)
        if args.command == "list":
            for item in devices:
                print(item.device.label + ("  [read-only]" if item.device.read_only else ""))
            if not devices:
                print("No supported removable drives found.")
            return 0
        matches = [item for item in devices if item.device.path == args.target]
        if len(matches) != 1:
            raise NativeWriteError("Select one exact whole-disk path from the list command")
        if args.command != 'write':
            from .native_tools import build_tool_plan
            options={}
            if args.command=='backup':options['sparse']=args.sparse
            if args.command=='surface':options=dict(passes=args.passes,capacity_first=args.capacity_first)
            if args.command=='restore':options=dict(filesystem=args.filesystem,partition_table=args.partition_table,label=args.label,cluster_size=args.cluster_size,quick=not args.full)
            plan = build_tool_plan(args.command, matches[0], include_fixed=args.include_usb_hard_drives,
                                   destination=getattr(args,'destination',None),**options)
        else:
            if args.mode=='dd' and not(args.persistence_mib or args.zip_overlay):
                plan=build_plan(args.image,matches[0],include_fixed=args.include_usb_hard_drives,expected_sha256=args.sha256)
            else:
                from .native_media import NativeMediaOptions,build_media_plan
                options=NativeMediaOptions(final_verification=not args.no_verify,mode=args.mode,filesystem=args.filesystem,partition_table=args.partition_table,firmware=args.firmware,label=args.label,cluster_size=args.cluster_size,persistence_size=args.persistence_mib*1048576,persistence_release=args.ubuntu_release,zip_overlay=args.zip_overlay)
                plan=build_media_plan(args.image,matches[0],options,include_fixed=args.include_usb_hard_drives,expected_sha256=args.sha256)
        writer.privilege_check(writer.host)
        if not sys.stdin.isatty():
            raise NativeWriteError("Erase confirmation requires an interactive terminal")
        if args.command == 'write':
            print(f"Image: {plan.source} ({format_size(plan.size)})")
        print(f"Target: {plan.target.device.label}")
        if args.command != 'backup':
            print('ALL data on this drive will be erased.')
        answer = input('Back up this drive? [y/N]: ' if args.command == 'backup' else 'Erase this drive and continue? [y/N]: ').strip().lower()
        if answer not in {"y", "yes"}:
            raise NativeWriteError("Write cancelled. The target was not changed.")
        confirmation = plan.confirmation
        for number in (signal.SIGINT, signal.SIGTERM):
            previous[number] = signal.signal(number, lambda *_: writer.cancel())
        last = None

        def progress(stage, done, total):
            nonlocal last
            state = (stage, (done * 100 // total) // 5 * 5)
            if state != last:
                print(f"{stage}: {done * 100 // total}%", file=sys.stderr, flush=True)
                last = state

        if args.command != 'write':
            from .native_tools import run_tool
            result = run_tool(plan, confirmation, writer, progress=progress)
            print(f'Backup verified. Drive data SHA-256: {result}' if args.command == 'backup' else result)
        else:
            from .native_media import NativeMediaPlan,run_media
            if isinstance(plan,NativeMediaPlan):checksum=run_media(plan,confirmation,writer,progress=progress)
            else:checksum = writer.run(plan, confirmation, progress=progress)
            print(f"Write verified. SHA-256: {checksum}")
        print('Eject the drive through your operating system before unplugging it.')
        return 0
    except (NativeCancelled, KeyboardInterrupt, EOFError) as error:
        print(str(error) or "Cancelled", file=sys.stderr)
        return 3
    except (NativeWriteError, DeviceDiscoveryError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        if writer.write_started:
            print("The target may be incomplete. Rewrite it before use.", file=sys.stderr)
        return 5 if writer.write_started else 4
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
