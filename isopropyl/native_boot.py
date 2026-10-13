"""Native boot-media preparation, using the exact shared release profiles."""
# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path
import hashlib
import os

from .native_tree import construct_fat32
from .native_writer import NativeWriteError,build_plan
from .fat_image import inspect_regular_fat32_image


def prepare_boot_media(kind,target,workspace,writer,progress=lambda *args:None,architectures=None):
    workspace=Path(workspace).resolve();tree=workspace/'boot-files';image=workspace/'boot-media.img'
    if kind=='uefi-shell':
        from .uefi_shell import prepare_uefi_shell,stage_uefi_shell
        prepared=prepare_uefi_shell(cancel_event=writer.cancelled,
            progress=lambda done,total:progress('Downloading verified EFI Shell',done,total))
        stage_uefi_shell(prepared,tree,architectures=architectures,cancel_event=writer.cancelled)
        construct_fat32(tree,image,min(target.device.size,512*1024*1024),writer,progress)
    elif kind=='grub-rescue':
        from .bootloaders import prepare_bundle
        from .grub_profile import (GRUB_FAMILY,GRUB_VERSION,GRUB_PURPOSE,_validate_bundle,
                                   BOOTSTRAP_SIZE,CORE_OFFSET,CORE_SIZE)
        bundle=prepare_bundle(GRUB_FAMILY,GRUB_VERSION,GRUB_PURPOSE,cancel_event=writer.cancelled,
            progress=lambda done,total:progress('Downloading verified GRUB rescue',done,total))
        boot,core=_validate_bundle(bundle)
        tree.mkdir(mode=0o700)
        construct_fat32(tree,image,target.device.size,writer,progress)
        with image.open('r+b') as output:
            writer.check_cancelled();output.seek(0);output.write(boot[:BOOTSTRAP_SIZE])
            output.seek(CORE_OFFSET);output.write(core);output.flush();os.fsync(output.fileno())
            output.seek(0)
            if output.read(BOOTSTRAP_SIZE)!=boot[:BOOTSTRAP_SIZE]:raise NativeWriteError('GRUB bootstrap verification failed')
            output.seek(CORE_OFFSET)
            if output.read(CORE_SIZE)!=core:raise NativeWriteError('GRUB core verification failed')
            parsed=inspect_regular_fat32_image(output.fileno(),cancel_check=writer.check_cancelled)
            if parsed.entries or parsed.content_bytes:raise NativeWriteError('GRUB blank filesystem changed')
    else:raise NativeWriteError('Unknown boot-media profile')
    return image
