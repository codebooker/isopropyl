"""Shared native ISO preparation. Every filesystem and boot patch targets regular files."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from .native_writer import NativeWriteError, build_plan, path_file_identity
from .windows import WindowsCustomization, WindowsBootExOptions
from .native_layout import MIB, Volume, compose_disk

@dataclass(frozen=True)
class NativeMediaOptions:
    mode: str = 'auto'
    filesystem: str = 'fat32'
    partition_table: str = 'mbr'
    firmware: str = 'uefi'
    label: str = 'ISOPROPYL'
    cluster_size: int | None = None
    persistence_size: int = 0
    persistence_release: str = ''
    zip_overlay: Path | None = None
    customization: WindowsCustomization = field(default_factory=WindowsCustomization)
    bootex: WindowsBootExOptions = field(default_factory=WindowsBootExOptions)
    uefi_ntfs_artifact: object | None = None
    allow_unsigned_uefi_ntfs: bool = False
    final_verification: bool = True

@dataclass(frozen=True)
class NativeMediaPlan:
    source: Path
    source_identity: tuple
    target: object
    include_fixed: bool
    expected_sha256: str | None
    options: NativeMediaOptions
    @property
    def customization(self): return self.options.customization
    @property
    def bootex(self): return self.options.bootex
    @property
    def size(self): return self.source_identity[2]
    @property
    def confirmation(self): return f'ERASE {self.target.device.path}'
    @property
    def details(self):
        o=self.options
        return f'{o.mode.upper()} • {o.partition_table.upper()} • {o.filesystem.upper()} • {o.firmware.upper()} • {o.label}'

def build_media_plan(source,target,options=None,*,include_fixed=False,expected_sha256=None):
    from .native_tools import validate_target
    validate_target(target,include_fixed)
    options=options or NativeMediaOptions()
    if options.mode not in {'auto','dd','iso'} or options.filesystem not in {'fat32','ntfs'} or options.partition_table not in {'mbr','gpt'} or options.firmware not in {'uefi','bios','both'}:
        raise NativeWriteError('Invalid media mode, filesystem, partition table or firmware')
    if options.firmware!='uefi' and (options.partition_table!='mbr' or options.filesystem!='fat32'):
        raise NativeWriteError('Experimental native BIOS profiles require MBR and FAT32')
    if options.persistence_size and (options.persistence_size<256*MIB or options.persistence_size%MIB):
        raise NativeWriteError('Persistence requires at least 256 MiB aligned to 1 MiB')
    if not options.label or any(ord(c)<32 for c in options.label) or len(options.label)>(11 if options.filesystem=='fat32' else 32):
        raise NativeWriteError('Invalid filesystem label')
    if type(options.final_verification) is not bool:raise NativeWriteError('Final verification must be enabled or disabled')
    if options.cluster_size is not None and options.cluster_size not in {512,1024,2048,4096,8192,16384,32768,65536}:
        raise NativeWriteError('Invalid allocation-unit size')
    path=Path(source).absolute();identity=path_file_identity(path)
    if path.is_symlink() or identity[2]<512:raise NativeWriteError('Choose a regular nonempty image')
    if expected_sha256 is not None:
        if not re.fullmatch('[0-9a-fA-F]{64}',expected_sha256):raise NativeWriteError('Expected SHA-256 must contain 64 hexadecimal characters')
        expected_sha256=expected_sha256.lower()
    return NativeMediaPlan(path,identity,target,include_fixed,expected_sha256,options)

def _validate_staged_fallbacks(tree,writer,files=None,*,required=True):
    from .native_tree import scan_tree,consume
    from .uefi import (fallback_loader_architecture,fallback_loader_matches_architecture,
        inspect_pe_bytes,MAX_PE_SIZE,PeFormatError)
    if files is None:_,files=scan_tree(tree,writer)
    architectures=[]
    for item in files:
        if len(item.parts)!=3 or tuple(p.casefold() for p in item.parts[:2])!=('efi','boot'):
            continue
        architecture=fallback_loader_architecture(item.parts[-1])
        if not architecture:continue
        if not 0<item.size<=MAX_PE_SIZE:raise NativeWriteError(f'UEFI loader exceeds its supported size: {item.path}')
        payload=bytearray()
        consume(tree,item,writer,lambda data,offset:payload.extend(data))
        try:
            # Full signature reports belong to inspection; this gate checks
            # the staged executable's structure and firmware architecture.
            parsed=inspect_pe_bytes(bytes(payload),authenticode_verifier=lambda *args,**kwargs:None,
                                    authenticode_cancel_check=writer.check_cancelled)
        except PeFormatError as error:raise NativeWriteError(f'Invalid staged UEFI loader {item.path}: {error}') from error
        if parsed.subsystem!=10 or not fallback_loader_matches_architecture(item.parts[-1],parsed.architecture):
            raise NativeWriteError(f'UEFI loader architecture or application subsystem does not match {item.path}')
        if architecture not in architectures:architectures.append(architecture)
    if required and not architectures:raise NativeWriteError('The extracted ISO has no supported native UEFI fallback loader')
    return tuple(architectures)

def _persistence(tree,options,writer):
    from .persistence import (ubuntu_casper_profile,_validate_release_info,_GRUB_CONFIG_PATHS,
        _SYSLINUX_CONFIG_PATHS,transform_grub_config,transform_syslinux_config)
    profile=ubuntu_casper_profile(options.persistence_release)
    if 'x64' not in _validate_staged_fallbacks(tree,writer):raise NativeWriteError('Ubuntu amd64 persistence requires an x64 EFI application')
    required=['.disk/info','casper/vmlinuz','casper/filesystem.squashfs','EFI/BOOT/BOOTX64.EFI']
    from .native_tree import scan_tree
    _,files=scan_tree(tree,writer);index={f.path.casefold():tree.joinpath(*f.parts) for f in files}
    if any(p.casefold() not in index for p in required) or not any(p in index for p in ('casper/initrd','casper/initrd.lz','casper/initrd.gz')):
        raise NativeWriteError('Persistence requires the exact Ubuntu amd64 Casper media profile')
    info=index['.disk/info']
    if info.stat().st_size>4*MIB:raise NativeWriteError('Ubuntu release evidence exceeds its bound')
    _validate_release_info(info.read_bytes(),profile)
    transforms=[]
    for paths,transform in ((_GRUB_CONFIG_PATHS,transform_grub_config),(_SYSLINUX_CONFIG_PATHS,transform_syslinux_config)):
        for name in paths:
            path=index.get(name.casefold())
            if path:
                if path.stat().st_size>4*MIB:raise NativeWriteError('Boot configuration exceeds its bound')
                result=transform(path.read_bytes(),profile.boot_parameter)
                if result.eligible_lines:transforms.append((path,result))
    if not transforms:raise NativeWriteError('No recognized Casper kernel command lines were found')
    for path,result in transforms:
        writer.check_cancelled();path.write_bytes(result.contents)
    return profile

def _windows_bios(image,tree,offset,size,writer):
    from .windows_bios_pbr import classify_windows_bootmgr_bios,plan_fat32_bootmgr_pbr,attest_fat32_bootmgr_pbr
    from .native_tree import scan_tree
    _,files=scan_tree(tree,writer);match=next((f for f in files if f.path.casefold()=='bootmgr'),None)
    if match is None:raise NativeWriteError('Windows BIOS profile requires root bootmgr')
    path=tree.joinpath(*match.parts)
    if path.stat().st_size>0x7E000:raise NativeWriteError('BOOTMGR exceeds its exact experimental profile')
    payload=path.read_bytes()
    classify_windows_bootmgr_bios(payload[:6],file_size=len(payload))
    with image.open('r+b') as stream:
        patch=plan_fat32_bootmgr_pbr(stream.fileno(),volume_offset=offset,volume_size=size)
        for item in patch.writes:
            writer.check_cancelled();stream.seek(item.offset);stream.write(item.data)
        stream.flush();os.fsync(stream.fileno());attest_fat32_bootmgr_pbr(stream.fileno(),patch)

def _syslinux_stage(tree,entries,writer,progress):
    from .boot_identity import analyze_bootloader_members
    from .syslinux_staging import syslinux_staging_analysis_paths,syslinux_staging_read_paths,plan_syslinux_staging
    from .bootloaders import prepare_bundle
    def read(paths):
        result={}
        for name in paths:
            writer.check_cancelled();path=tree.joinpath(*Path(name).parts)
            if path.stat().st_size>4*MIB:raise NativeWriteError('Syslinux configuration exceeds its bounded profile')
            result[name]=path.read_bytes()
        return result
    analysis=analyze_bootloader_members(read(syslinux_staging_analysis_paths(entries)))
    identity=analysis.resolved('Syslinux')
    if identity is None or not identity.dependency_key:raise NativeWriteError('The exact experimental Syslinux build could not be resolved')
    family,version=identity.dependency_key.split(':',1)
    module=prepare_bundle(family,version,'blank-bios-module',cancel_event=writer.cancelled)
    bundle=prepare_bundle(family,version,'matched-bios-payloads',cancel_event=writer.cancelled)
    source=read(syslinux_staging_read_paths(entries,analysis))
    stage=plan_syslinux_staging(entries,analysis,module,bundle,source_files=source,existing_files=source)
    for item in stage.additions:
        writer.check_cancelled();path=tree.joinpath(*Path(item.path).parts);path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(item.data)
    return stage,bundle

def _syslinux_patch(image,offset,size,prepared,writer):
    from .syslinux_fat import map_root_ldlinux,prepare_syslinux_regular_file_plan
    stage,bundle=prepared
    with image.open('r+b') as stream:
        mapping=map_root_ldlinux(stream.fileno(),volume_offset=offset,volume_size=size,expected_file=stage.root_ldlinux_sys.data)
        patch=prepare_syslinux_regular_file_plan(bundle,stream.fileno(),mapping,directory=stage.config_directory)
        payload=patch.syslinux.ldlinux_file
        for index,sector in enumerate(mapping.sectors):
            writer.check_cancelled();chunk=payload[index*512:(index+1)*512]
            if chunk:stream.seek(offset+sector*512);stream.write(chunk)
        for position,data in [(offset+patch.syslinux.backup_boot_sector*512,patch.syslinux.boot_sector),(offset,patch.syslinux.boot_sector),(0,patch.mbr.mbr)]:
            writer.check_cancelled();stream.seek(position);stream.write(data)
        stream.flush();os.fsync(stream.fileno())
        for position,data in [(offset+patch.syslinux.backup_boot_sector*512,patch.syslinux.boot_sector),(offset,patch.syslinux.boot_sector),(0,patch.mbr.mbr)]:
            stream.seek(position)
            if stream.read(len(data))!=data:raise NativeWriteError('Syslinux boot-sector verification failed')
        map_root_ldlinux(stream.fileno(),volume_offset=offset,volume_size=size,expected_file=payload)

def prepare_media_image(plan,workspace,writer,progress=lambda *args:None):
    from .native_inputs import PREPARED_SUFFIXES,prepare_image
    from .native_extract import snapshot_file,extract_iso
    from .images import inspect_image
    from .native_filesystems import construct_volume
    options=plan.options;workspace=Path(workspace).resolve()
    if plan.source.suffix.lower() in PREPARED_SUFFIXES:
        snapshot=prepare_image(plan,workspace,writer,progress,return_source=True)
    else:
        suffix=plan.source.suffix.lower() if plan.source.suffix.lower() in {'.iso','.img','.raw','.usb','.wic'} else '.img'
        snapshot=workspace/('input'+suffix);digest=snapshot_file(plan.source,plan.source_identity,snapshot,writer,progress)
        if plan.expected_sha256 and digest!=plan.expected_sha256:raise NativeWriteError('Source SHA-256 does not match')
    inspection=inspect_image(snapshot,cancel_check=writer.check_cancelled)
    transformed=bool(options.persistence_size or options.zip_overlay or options.customization.enabled or options.bootex.enabled)
    mode=options.mode
    explicit_layout=options.filesystem!='fat32' or options.partition_table!='mbr' or options.firmware!='uefi' or options.label!='ISOPROPYL' or options.cluster_size is not None
    if mode=='auto':mode='dd' if not inspection.is_iso9660 or (inspection.has_mbr or inspection.has_gpt) and not transformed and not explicit_layout else 'iso'
    if mode=='dd':
        if transformed:raise NativeWriteError('Persistence, overlays and installer customization require ISO mode')
        build_plan(snapshot,plan.target,include_fixed=plan.include_fixed)
        return snapshot
    if not inspection.is_iso9660:raise NativeWriteError('Filesystem mode requires an optical ISO')
    tree=workspace/'files';inspection,entries=extract_iso(snapshot,tree,writer,progress)
    if inspection.has_windows_installer:
        from .mac_windows_iso import collect_files,installer_profile,verify_loader,customize_tree,split_large_install
        selected=plan.customization.install_image
        index,(loader,machine),install=installer_profile(collect_files(tree),selected.source_name if selected else None);verify_loader(tree/index[loader],machine)
        if options.firmware!='uefi' and machine!=0x8664:raise NativeWriteError('Experimental Windows BIOS media requires an x64 installer ISO; ARM64 uses UEFI')
        customize_tree(plan,tree,index,install,machine,snapshot,workspace,writer,progress)
        if options.filesystem=='fat32':split_large_install(tree,index,install,writer,progress)
    elif options.customization.enabled or options.bootex.enabled:raise NativeWriteError('Windows settings require a Windows installer ISO')
    if options.zip_overlay:
        from .zip_overlay import build_zip_overlay_plan,apply_zip_overlay
        overlay=build_zip_overlay_plan(Path(options.zip_overlay).absolute(),cancel_check=writer.check_cancelled)
        from .iso import merge_additive_overlay_entries
        from .native_tree import scan_tree
        from .iso import ArchiveEntry,EntryKind
        dirs,staged_files=scan_tree(tree,writer)
        occupied=tuple(ArchiveEntry(d.path,0,EntryKind.DIRECTORY) for d in dirs if d.parts)+tuple(ArchiveEntry(f.path,f.size,EntryKind.FILE) for f in staged_files)
        merged=merge_additive_overlay_entries(occupied,tuple(m.entry for m in overlay.members))
        apply_zip_overlay(overlay,tree,merged.overlay_targets,cancel_check=writer.check_cancelled,
            progress=lambda u:progress('Adding ZIP overlay',u.bytes_done,u.total_bytes))
    syslinux=None
    if options.firmware!='uefi' and not inspection.has_windows_installer:
        if transformed:raise NativeWriteError('Experimental Syslinux media requires an unmodified ISO profile')
        syslinux=_syslinux_stage(tree,entries,writer,progress)
    profile=_persistence(tree,options,writer) if options.persistence_size else None
    from .native_tree import scan_tree
    _,files=scan_tree(tree,writer);content=sum(f.size for f in files)
    fallback_architectures=_validate_staged_fallbacks(tree,writer,files,required=options.firmware!='bios')
    unit=256*MIB;minimum=max(512*MIB,65525*(options.cluster_size or 0)+2*MIB) if options.filesystem=='fat32' else 512*MIB
    needed=max(((minimum+unit-1)//unit)*unit,((content+content//10+64*MIB+unit-1)//unit)*unit)
    reserve=33*512 if options.partition_table=='gpt' else 0
    helper_size=MIB if options.filesystem=='ntfs' and options.firmware!='bios' else 0
    usable=((plan.target.device.size-reserve)//MIB)*MIB
    volume_size=usable-MIB-options.persistence_size-helper_size
    size=volume_size+(MIB if options.filesystem=='fat32' else 0)
    if size<needed:raise NativeWriteError('Constructed filesystem and persistence exceed target capacity')
    fsimage=workspace/'main.fs';offset,length,_=construct_volume(tree,fsimage,size,options.filesystem,writer,progress,label=options.label,cluster_size=options.cluster_size)
    volumes=[Volume(fsimage,offset,length,options.filesystem,options.label)]
    if profile:
        empty=workspace/'persistence-tree';empty.mkdir(mode=0o700);pimage=workspace/'persistence.fs'
        off,count,_=construct_volume(empty,pimage,options.persistence_size,'ext4',writer,progress,label=profile.partition_label)
        volumes.append(Volume(pimage,off,count,'ext4',profile.partition_label))
    if helper_size:
        from .uefi_ntfs import prepare_uefi_ntfs_artifact,_payloads_for,PayloadTrust
        artifact=options.uefi_ntfs_artifact or prepare_uefi_ntfs_artifact(cancel_event=writer.cancelled)
        from .uefi_ntfs import BoundArtifact,UEFI_NTFS_SIZE,UEFI_NTFS_SHA256
        import hashlib
        if type(artifact) is not BoundArtifact or len(artifact.data)!=UEFI_NTFS_SIZE or hashlib.sha256(artifact.data).hexdigest()!=UEFI_NTFS_SHA256:
            raise NativeWriteError('The bound UEFI:NTFS image failed its pinned integrity check')
        arch=fallback_architectures
        payloads=_payloads_for(arch,[f.path for f in files],allow_unsigned_payloads=options.allow_unsigned_uefi_ntfs)
        if not options.allow_unsigned_uefi_ntfs and any(p.trust is PayloadTrust.UNSIGNED for p in payloads):raise NativeWriteError('The selected UEFI:NTFS payload requires unsigned-loader consent')
        boot=workspace/'uefi-ntfs.fs';boot.write_bytes(artifact.data);volumes.append(Volume(boot,0,helper_size,'efi','UEFI_NTFS'))
    image=workspace/'installer.img';starts=compose_disk(volumes,image,plan.target.device.size,options.partition_table,writer,progress,active=options.firmware!='uefi')
    if options.firmware!='uefi':
        if inspection.has_windows_installer:_windows_bios(image,tree,starts[0],length,writer)
        else:_syslinux_patch(image,starts[0],length,syslinux,writer)
    shutil.rmtree(tree);snapshot.unlink(missing_ok=True)
    for volume in volumes:volume.path.unlink(missing_ok=True)
    return image

def run_media(plan,confirmation,writer,*,progress=lambda *args:None):
    if confirmation!=plan.confirmation:raise NativeWriteError('The exact erase confirmation was not supplied')
    writer.check_cancelled();writer.revalidate(plan)
    writer.final_verification=plan.options.final_verification
    with tempfile.TemporaryDirectory(prefix='isopropyl-media-',dir=writer.temp_directory) as directory:
        image=prepare_media_image(plan,Path(directory),writer,progress);raw=build_plan(image,plan.target,include_fixed=plan.include_fixed)
        if writer.host=='darwin' and os.geteuid()!=0:
            from .mac_write import run_macos_write
            return run_macos_write(raw,confirmation,writer,progress=progress,prepared_private=True)
        writer._worker_private_source=True
        return writer.run(raw,confirmation,progress=progress)

def describe_media_plan(plan,writer,progress=lambda *args:None):
    """Inspect a source and explain the resolved layout without opening a target."""
    from .images import inspect_image
    from .native_inputs import PREPARED_SUFFIXES,prepare_image
    from .native_tree import MAX_ENTRIES
    from .mac_windows_iso import FAT_LIMIT
    options=plan.options
    if path_file_identity(plan.source)!=plan.source_identity:raise NativeWriteError('The source changed after selection')
    progress('Inspecting media plan',0,1)
    with tempfile.TemporaryDirectory(prefix='isopropyl-plan-') as directory:
        source=prepare_image(plan,Path(directory),writer,progress,return_source=True) if plan.source.suffix.lower() in PREPARED_SUFFIXES else plan.source
        inspection=inspect_image(source,cancel_check=writer.check_cancelled)
        bootex_facts=None
        if options.bootex.enabled:
            import hashlib
            from .native_writer import BLOCK
            digest=hashlib.sha256()
            with source.open('rb') as original:
                while data:=original.read(BLOCK):writer.check_cancelled();digest.update(data)
            bootex_facts=(source.stat().st_size,digest.hexdigest())
    transformed=bool(options.persistence_size or options.zip_overlay or options.customization.enabled or options.bootex.enabled)
    explicit=options.filesystem!='fat32' or options.partition_table!='mbr' or options.firmware!='uefi' or options.label!='ISOPROPYL' or options.cluster_size is not None
    resolved=options.mode
    if resolved=='auto':resolved='dd' if not inspection.is_iso9660 or (inspection.has_mbr or inspection.has_gpt) and not transformed and not explicit else 'iso'
    rows=[f'Source: {plan.source.name}',f'Target: {plan.target.device.model} · {plan.target.device.path} · {plan.target.device.size:,} bytes',
        f'Resolved method: {resolved.upper()}',f'Image type: {inspection.kind}',f'Architectures: {", ".join(inspection.architectures) or "unknown"}']
    issues=[]
    if resolved=='dd':
        rows += [f'Image bytes: {inspection.size:,}',f'Existing partition map: {inspection.partition_table_kind or "none"}',
            'Source boot records and filesystems are preserved; remaining target metadata is cleared.']
        if transformed:issues.append('ISO transformations require filesystem ISO mode')
        if inspection.is_iso9660 and not (inspection.has_mbr or inspection.has_gpt):issues.append('Optical-only ISO cannot be written in DD mode')
        if inspection.size>plan.target.device.size:issues.append('Decoded image exceeds target capacity')
    else:
        content=sum(m.size for m in inspection.members if m.kind=='file')
        overlay_size=0
        if options.zip_overlay:
            from .zip_overlay import build_zip_overlay_plan
            overlay=build_zip_overlay_plan(Path(options.zip_overlay).absolute(),cancel_check=writer.check_cancelled);overlay_size=overlay.content_bytes
            rows.append(f'Additive ZIP: {overlay.archive.name} · {len(overlay.members)} entries · {overlay.content_bytes:,} bytes')
        content+=overlay_size
        unit=256*MIB;minimum=max(512*MIB,65525*(options.cluster_size or 0)+2*MIB) if options.filesystem=='fat32' else 512*MIB
        main=max(((minimum+unit-1)//unit)*unit,((content+content//10+64*MIB+unit-1)//unit)*unit)
        helper_size=MIB if options.filesystem=='ntfs' and options.firmware!='bios' else 0
        reserve=33*512 if options.partition_table=='gpt' else 0
        capacity=main+options.persistence_size+helper_size+(0 if options.filesystem=='fat32' else MIB)+reserve
        usable=((plan.target.device.size-reserve)//MIB)*MIB
        actual_volume=usable-MIB-options.persistence_size-helper_size
        rows += [f'Partition table: {options.partition_table.upper()}',f'Installer filesystem: {options.filesystem.upper()} · label {options.label}',
            f'Allocation unit: {options.cluster_size or "automatic"}',f'Firmware: {options.firmware.upper()}',
            f'Installer partition capacity: {max(0,actual_volume):,} bytes; remaining space is reserved for selected persistence and boot partitions',
            f'Extracted content: {content:,} bytes',f'Estimated required capacity: {capacity:,} bytes (final filesystem allocation is checked during preparation)']
        if not inspection.is_iso9660:issues.append('Filesystem mode requires an optical ISO')
        if not inspection.contents_scanned:issues.append('The ISO catalog is incomplete')
        if len(inspection.members)>MAX_ENTRIES:issues.append('The ISO exceeds the staging entry bound')
        if capacity>plan.target.device.size:issues.append('Constructed partitions exceed target capacity')
        if options.filesystem=='fat32':
            large=[m.path for m in inspection.members if m.kind=='file' and m.size>FAT_LIMIT]
            if large:
                if inspection.has_windows_installer and all(p.casefold() in {'sources/install.wim','sources/install.esd'} for p in large):rows.append('Large install image: export ESD if needed, split WIM, verify edition metadata and integrity')
                else:issues.append('A file exceeds FAT32’s maximum file size')
        if options.persistence_size:
            rows.append(f'Persistence: {options.persistence_size:,} bytes · ext4 writable · Ubuntu {options.persistence_release} amd64 Casper')
            if options.persistence_release not in {'20.04','22.04','24.04'}:issues.append('Executable persistence requires an explicitly selected supported Ubuntu LTS profile')
            if 'x64' not in inspection.architectures and 'amd64' not in inspection.architectures:issues.append('Executable Casper persistence requires amd64 media')
            rows.append('Persistence checks .disk/info and exact Casper files, transforms recognized boot configurations, and adds a reserved tail partition without shrinking the installer.')
        if helper_size:rows.append('Boot dependency: pinned 1 MiB UEFI:NTFS bridge in a separate EFI partition; firmware trust and DBX policy also apply')
        if options.firmware!='uefi':
            rows.append('BIOS compatibility: experimental exact Windows BOOTMGR or matched Syslinux 6.03 / 6.04-pre1 profile; all boot patches are attested before target access')
            if not inspection.has_windows_installer and not inspection.bootloader_dependency:issues.append('No exact supported Syslinux dependency was detected')
        if options.bootex.enabled:
            rows.append('Windows BootEx: exact reviewed Microsoft ISO SHA-256 and firmware CA 2023 acknowledgment required')
            if not options.bootex.acknowledge_firmware_compatibility:issues.append('CA 2023 firmware acknowledgment is missing')
            from .windows_bootex import profile_for_official_iso,BootExProvenanceError
            try:profile_for_official_iso(*bootex_facts,architecture='arm64' if 'arm64' in inspection.architectures else 'amd64')
            except BootExProvenanceError as error:issues.append(str(error))
        if options.customization.enabled:rows.append('Windows installer customization: shared autounattend settings and selected-edition metadata revalidation')
        if (options.customization.enabled or options.bootex.enabled) and not inspection.has_windows_installer:issues.append('Windows settings require a Windows installer ISO')
    for payload in getattr(inspection,'uefi_payloads',()):
        auth=payload.authenticode
        if auth:rows.append(f'EFI integrity: {payload.path} · {auth.state.value}'+(f' · {auth.error}' if auth.error else ''))
        if payload.dbx:rows.append(f'EFI revocation: {payload.path} · {payload.dbx.state.value}')
    rows.append('Final full verification after activation: '+('enabled' if options.final_verification else 'disabled')+'; verification before activation is mandatory')
    rows.extend('Compatibility issue: '+str(issue) for issue in [*issues,*inspection.bootloader_issues,*inspection.uefi_analysis_issues])
    if not issues:rows.append('Preparation will verify filesystems, exact boot dependencies and final capacity before any target handle is opened.')
    if path_file_identity(plan.source)!=plan.source_identity:raise NativeWriteError('The source changed during plan inspection')
    progress('Inspecting media plan',1,1)
    return '\n'.join(rows)
