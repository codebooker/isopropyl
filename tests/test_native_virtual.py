# SPDX-License-Identifier: AGPL-3.0-or-later
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from isopropyl.devices import Device
from isopropyl.native_devices import NativeDevice
from isopropyl.native_virtual import convert_private_container, qemu_tool
from isopropyl.native_writer import NativeWriter, NativeWriteError, build_plan
from isopropyl.native_inputs import prepare_image


class VirtualTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        self.writer=NativeWriter(host='linux',privilege_check=lambda host:None)

    def test_json_with_external_backing_or_data_is_rejected_before_conversion(self):
        from isopropyl.virtual import FileIdentity,ToolIdentity,VirtualDiskError
        import json
        image=self.root/'private.qcow2';image.write_bytes(bytes(1024))
        tool=ToolIdentity(image,FileIdentity(0,0,0,0,0))
        for field in ['backing-filename','data-file','encrypted']:
            payload={'format':'qcow2','virtual-size':4096,field:'unsafe'}
            result=subprocess.CompletedProcess([],0,json.dumps(payload).encode(),b'')
            with patch('isopropyl.native_virtual.qemu_tool',return_value=tool), \
                 patch('isopropyl.native_virtual._require_tool'), \
                 patch('isopropyl.native_virtual.run_native_command',return_value=result) as run:
                with self.assertRaises(VirtualDiskError):convert_private_container(image,self.root,self.writer,4096,lambda *args:None)
            self.assertEqual(run.call_count,1)

    @unittest.skipUnless(Path('/usr/bin/qemu-img').is_file(),'requires native QEMU utility')
    def test_real_qemu_containers_are_expanded_to_the_original_disk_bytes(self):
        content=b'A'*512+bytes(512)+b'B'*512+bytes(512)
        raw=self.root/'original.img';raw.write_bytes(content)
        target=NativeDevice(Device('/dev/test',4096,'Flash','','usb','SERIAL','','test',True,True,False,(),(),512))
        for extension,format_name in [('.qcow2','qcow2'),('.qcow','qcow'),('.vhd','vpc'),('.vhdx','vhdx')]:
            with self.subTest(format=format_name):
                container=self.root/('disk'+extension)
                arguments=['/usr/bin/qemu-img','convert','-f','raw','-O',format_name]
                if format_name=='vpc':arguments+=['-o','force_size=on']
                subprocess.run([*arguments,str(raw),str(container)],check=True,capture_output=True)
                workspace=self.root/format_name;workspace.mkdir()
                plan=build_plan(container,target)
                decoded=prepare_image(plan,workspace,self.writer,lambda *args:None)
                self.assertEqual(decoded.source.read_bytes(),content)

    def test_missing_tool_is_an_actionable_error(self):
        with patch.object(Path,'is_file',return_value=False):
            with self.assertRaisesRegex(NativeWriteError,'QEMU'):qemu_tool('win32')
