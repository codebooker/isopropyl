# SPDX-License-Identifier: AGPL-3.0-or-later
import os,tempfile,unittest
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from PyQt6.QtWidgets import QApplication
from isopropyl.native_media import NativeMediaOptions
from isopropyl.native_settings import encode_state,decode_state
from isopropyl.windows import WindowsCustomization,WindowsBootExOptions
from isopropyl.wim import WimEdition,WimSelection

class OptionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])
    def test_elevation_preserves_exact_edition_and_media_settings(self):
        edition=WimEdition(2,'Pro','Pro','Professional','x64',10,0,26100,1)
        custom=WindowsCustomization(local_username='Jack',install_image=WimSelection('sources/install.wim',1234,(edition,),2))
        options=NativeMediaOptions(mode='iso',filesystem='ntfs',partition_table='gpt',persistence_size=1024*1048576,persistence_release='24.04',zip_overlay=Path('/media/a.zip'))
        bootex=WindowsBootExOptions(True,True)
        restored,restored_custom,restored_bootex=decode_state(encode_state(options,custom,bootex))
        self.assertEqual(restored,options);self.assertEqual(restored_custom,custom);self.assertEqual(restored_bootex,bootex)
    def test_dialog_saves_partition_filesystem_and_overlay(self):
        from isopropyl.native_options import MediaOptionsDialog
        dialog=MediaOptionsDialog(NativeMediaOptions())
        dialog.mode.setCurrentIndex(dialog.mode.findData('iso'));dialog.fs.setCurrentIndex(dialog.fs.findData('ntfs'));dialog.table.setCurrentIndex(dialog.table.findData('gpt'));dialog.overlay.setText('/images/add.zip');dialog.label.setText('INSTALL')
        dialog.save()
        self.assertEqual(dialog.options.filesystem,'ntfs');self.assertEqual(dialog.options.partition_table,'gpt');self.assertEqual(dialog.options.zip_overlay,Path('/images/add.zip'));self.assertEqual(dialog.options.label,'INSTALL');dialog.close()
    def test_session_rejects_executable_or_oversized_input(self):
        with self.assertRaises(ValueError):decode_state('a'*32769)
        with self.assertRaises(ValueError):decode_state('import os;os.system("anything")')
    def test_authorized_relaunch_gets_data_only_session_argument(self):
        from isopropyl.native_elevation import request_write_access
        state=encode_state(NativeMediaOptions(mode='iso'),WindowsCustomization(disable_fast_startup=True),WindowsBootExOptions())
        with tempfile.TemporaryDirectory() as d,patch('isopropyl.native_elevation.launch_log_path',return_value=Path(d)/'log'),patch('isopropyl.native_elevation._launch_authorized') as launch,patch('isopropyl.native_elevation.wait_for_ready'):
            request_write_access(host='win32',session_state=state)
        args=launch.call_args.args[0];self.assertIn('--session-state-file',args);self.assertNotIn(state,args)
        import hashlib
        self.assertEqual(args[args.index('--session-state-sha256')+1],hashlib.sha256(state.encode()).hexdigest())

    def test_large_hash_bound_session_file_roundtrip_and_mutation_refusal(self):
        from isopropyl.native_settings import load_state_file
        import hashlib
        options=NativeMediaOptions(mode='iso')
        editions=tuple(WimEdition(i,'Pro','d'*700,'Professional','x64',10,0,26100,1) for i in range(1,129))
        custom=WindowsCustomization(local_username='Jack',install_image=WimSelection('sources/install.wim',1024,editions,1))
        state=encode_state(options,custom,WindowsBootExOptions())
        self.assertGreater(len(state),32768)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'session.txt';path.write_text(state);path.chmod(0o600)
            digest=hashlib.sha256(state.encode()).hexdigest()
            self.assertEqual(load_state_file(path,digest)[1],custom)
            path.write_text(state+' ')
            with self.assertRaises(ValueError):load_state_file(path,digest)
