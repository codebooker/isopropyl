# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import json
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from isopropyl import update_install as updater


class UpdateInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'state';self.state.mkdir()
        self.state_patch=patch.object(updater,'_state_directory',return_value=self.state)
        self.state_patch.start();self.addCleanup(self.state_patch.stop)

    def plan(self,kind='portable-zip'):
        root=self.root/'application';root.mkdir()
        (root/'version').write_text('old')
        work=self.root/'.isopropyl-update-test';work.mkdir(mode=0o700)
        staged=work/'new';staged.mkdir();(staged/'version').write_text('new')
        log=work/'update.log';log.touch()
        return updater.InstallPlan(kind,'2.0',str(root),str(staged),str(work),sys.executable,
            (sys.executable,),str(self.state/'update-status.json'),str(log),token='a'*64)

    def archive(self,names):
        path=self.root/'update.zip'
        with zipfile.ZipFile(path,'w') as archive:
            for name in names:
                # Preserve intentionally hostile raw names: ZipInfo(name)
                # normalizes backslashes on Windows before writing the ZIP.
                info=zipfile.ZipInfo('placeholder')
                info.filename=info.orig_filename=name
                archive.writestr(info,b'content')
        return path

    def test_archive_rejects_traversal_links_and_case_aliases(self):
        for index,names in enumerate([['../escape'],['/absolute'],['a\\b'],['C:escape'],
                                     ['CON.txt'],['A/one','a/two'],['same','same']]):
            with self.subTest(names=names):
                with self.assertRaises(updater.UpdateInstallError):updater._extract(self.archive(names),self.root/str(index))
        path=self.root/'symlink.zip'
        info=zipfile.ZipInfo('link');info.external_attr=(stat.S_IFLNK|0o777)<<16
        with zipfile.ZipFile(path,'w') as archive:archive.writestr(info,'/outside')
        with self.assertRaises(updater.UpdateInstallError):updater._extract(path,self.root/'links')
        self.assertFalse((self.root.parent/'escape').exists())

    def test_raw_zip_names_are_rejected_before_windows_reader_normalization(self):
        for index,name in enumerate(('a\\b','safe\x00escape')):
            with self.subTest(name=name):
                archive=self.archive([name])
                # Verify both the local header and central directory contain
                # hostile raw bytes, independent of ZipInfo writer defaults.
                self.assertGreaterEqual(archive.read_bytes().count(name.encode()),2)
                # Exercise Windows ZipInfo parsing even on POSIX test hosts.
                with patch.object(zipfile.os,'sep','\\'):
                    with zipfile.ZipFile(archive) as source:
                        entry,=source.infolist()
                        self.assertEqual(entry.orig_filename,name)
                        self.assertNotEqual(entry.filename,name)
                    destination=self.root/f'raw-{index}'
                    with self.assertRaises(updater.UpdateInstallError):updater._extract(archive,destination)
                self.assertEqual(list(destination.iterdir()),[])

    def test_regular_zip_entries_keep_their_original_name_and_file_type(self):
        archive=self.archive(['package/module.py'])
        destination=updater._extract(archive,self.root/'regular')
        path=destination/'package/module.py'
        self.assertTrue(stat.S_ISREG(path.lstat().st_mode))
        self.assertEqual(path.read_bytes(),b'content')

    def test_checksum_is_rechecked_before_archive_is_consumed(self):
        payload=self.root/'asset.zip';payload.write_bytes(b'changed')
        installation=updater.Installation('portable-zip',True,'',str(self.root/'application'),sys.executable,())
        with self.assertRaisesRegex(updater.UpdateInstallError,'SHA-256'):
            updater.prepare_install(payload,'0'*64,'portable-zip','2.0',installation=installation)
        status=updater.read_update_status();self.assertEqual(status['state'],'failed')
        self.assertTrue(Path(status['log_path']).is_file())
        self.assertFalse(any(path.name=='payload.zip' for path in self.root.rglob('*')))

    def test_busy_handoff_never_starts_installer(self):
        with patch.object(updater.subprocess,'Popen') as process:
            with self.assertRaisesRegex(updater.UpdateInstallError,'current operation'):
                updater.launch_install(self.plan(),busy=True)
        process.assert_not_called()

    def test_portable_swap_preserves_settings_sfx_flag_and_unknown_user_data(self):
        plan=self.plan();root=Path(plan.root)
        (root/'isopropyl.ini').write_text('preferences');(root/'ready.txt').write_text('old-sfx-version')
        (root/'my-image.iso').write_bytes(b'valuable user data')
        with patch.object(updater,'_health'):
            updater.apply_install(plan,restart=lambda value:self.assertEqual((root/'version').read_text(),'new'))
        self.assertEqual((root/'isopropyl.ini').read_text(),'preferences')
        self.assertEqual((root/'ready.txt').read_text(),'old-sfx-version')
        self.assertEqual((Path(plan.work)/'rollback/application/my-image.iso').read_bytes(),b'valuable user data')
        self.assertEqual(updater.read_update_status()['state'],'installed')

    def test_failed_new_startup_restores_original_tree_before_old_restart(self):
        plan=self.plan();root=Path(plan.root);observed=[]
        def restart(value):
            observed.append((root/'version').read_text())
            if len(observed)==1:raise updater.UpdateInstallError('startup failed')
        with patch.object(updater,'_health'):
            with self.assertRaisesRegex(updater.UpdateInstallError,'previous installation was restored'):
                updater.apply_install(plan,restart=restart)
        self.assertEqual(observed,['new','old']);self.assertEqual((root/'version').read_text(),'old')
        self.assertEqual(updater.read_update_status()['state'],'rolled-back')

    def test_failed_swap_restores_old_tree_even_before_new_tree_was_installed(self):
        plan=self.plan();Path(plan.staged).rename(Path(plan.work)/'missing')
        with self.assertRaises(updater.UpdateInstallError):updater.apply_install(plan,restart=lambda value:None)
        self.assertEqual((Path(plan.root)/'version').read_text(),'old')

    def test_cancelled_preparation_can_be_discarded_but_helper_owned_transaction_cannot(self):
        plan=self.plan();updater.discard_update(plan);self.assertFalse(Path(plan.work).exists())
        Path(plan.root).rename(self.root/'previous')
        plan=self.plan();(Path(plan.work)/'launched').touch()
        with self.assertRaisesRegex(updater.UpdateInstallError,'already owns'):updater.discard_update(plan)
        self.assertTrue(Path(plan.work).is_dir())

    def test_failed_handoff_terminates_exact_helper_before_releasing_ownership(self):
        plan=self.plan();updater._json_write(Path(plan.work)/'plan.json',updater.asdict(plan))
        process=Mock();process.poll.return_value=None
        with patch.object(updater,'_helper_python',return_value=sys.executable), \
             patch.object(updater.subprocess,'Popen',return_value=process), \
             patch.object(updater.time,'monotonic',side_effect=[0,31]):
            with self.assertRaisesRegex(updater.UpdateInstallError,'did not become ready'):updater.launch_install(plan)
        process.terminate.assert_called_once();process.wait.assert_called_once_with(timeout=15)
        self.assertFalse((Path(plan.work)/'launched').exists())

    def test_gui_ready_confirmation_requires_private_plan_token_and_pending_status(self):
        plan=self.plan();work=Path(plan.work)
        updater._json_write(work/'plan.json',updater.asdict(plan));updater._status(plan,'installing','test')
        env={'ISOPROPYL_UPDATE_READY_FILE':str(work/'application-ready'),'ISOPROPYL_UPDATE_TOKEN':'wrong'}
        with patch.dict(os.environ,env):
            with self.assertRaisesRegex(updater.UpdateInstallError,'token'):updater.notify_update_ready()
        self.assertFalse((work/'application-ready').exists())
        env['ISOPROPYL_UPDATE_TOKEN']=plan.token
        with patch.dict(os.environ,env):self.assertTrue(updater.notify_update_ready())
        self.assertEqual((work/'application-ready').read_text(),'ready')

    def test_mac_pointer_and_bundle_version_roll_back_together(self):
        from dataclasses import replace
        plan=self.plan('offline-wheelhouse');app=self.root/'ISOpropyl.app';resources=app/'Contents/Resources'
        resources.mkdir(parents=True);pointer=resources/'runtime.txt';pointer.write_text(plan.root+'\n')
        plist=app/'Contents/Info.plist';original=plistlib.dumps({'CFBundleShortVersionString':'1.0'})
        plist.write_bytes(original)
        plan=replace(plan,pointer=str(pointer),old_pointer=pointer.read_text())
        calls=[]
        def restart(value):
            calls.append(pointer.read_text())
            if len(calls)==1:
                self.assertEqual(plistlib.loads(plist.read_bytes())['CFBundleShortVersionString'],'2.0')
                raise updater.UpdateInstallError('startup failure')
        with patch.object(updater,'_run'):
            with self.assertRaises(updater.UpdateInstallError):updater.apply_install(plan,restart=restart)
        self.assertEqual(pointer.read_text(),plan.old_pointer);self.assertEqual(plist.read_bytes(),original)
        self.assertEqual(len(calls),2)

    def test_debian_install_failure_keeps_package_manager_log_and_restarts_status_ui(self):
        plan=self.plan('deb');restart=Mock()
        with patch.object(updater,'_run',side_effect=updater.UpdateInstallError('dependency failure')):
            with self.assertRaisesRegex(updater.UpdateInstallError,'package manager'):updater.apply_install(plan,restart=restart)
        restart.assert_called_once_with(plan)
        self.assertEqual(updater.read_update_status()['state'],'failed')

    def test_debian_install_resolves_dependencies_without_removing_other_packages(self):
        plan=self.plan('deb')
        with patch.object(updater,'_run') as run:
            updater.apply_install(plan,restart=lambda value:None)
        argv=run.call_args.args[0]
        self.assertEqual(argv[:2],['/usr/bin/pkexec','/usr/bin/apt-get'])
        self.assertIn('--no-remove',argv);self.assertIn('--no-install-recommends',argv)
        self.assertEqual(argv[-2:],['install',Path(plan.staged)])

    def test_debian_preparation_rejects_wrong_architecture_before_handoff(self):
        asset=self.root/'asset.deb';asset.write_bytes(b'official package fixture')
        install=updater.Installation('deb',True,'','/usr',sys.executable,('/usr/bin/isopropyl',))
        metadata=SimpleNamespace(stdout='Package: isopropyl\nVersion: 2.0-1\nArchitecture: arm64\n')
        host=SimpleNamespace(stdout='amd64\n')
        with patch.object(updater,'_run'),patch.object(updater.subprocess,'run',side_effect=[metadata,host]), \
             self.assertRaisesRegex(updater.UpdateInstallError,'architecture'):
            updater.prepare_install(asset,hashlib.sha256(asset.read_bytes()).hexdigest(),'deb','2.0',installation=install)

    def test_real_exact_parent_watcher_and_independent_windows_helper_runtime(self):
        plan=self.plan();work=Path(plan.work)
        python=updater._helper_python(plan)
        if sys.platform=='win32':
            probe=subprocess.run([python,'-I','-c',
                'import ctypes,json,zipfile,subprocess,sys;print(json.dumps(sys.path))'],
                check=True,stdout=subprocess.PIPE,text=True)
            for entry in json.loads(probe.stdout):
                self.assertTrue(Path(entry).resolve().is_relative_to((work/'helper-runtime').resolve()),entry)
        helper=work/'standalone.py';helper.write_bytes(Path(updater.__file__).read_bytes())
        child=work/'child.py'
        child.write_text('''import os,runpy,sys
from pathlib import Path
module=runpy.run_path(sys.argv[1])
pid=os.getppid();token=''
if sys.platform=='win32':
    kernel,handle=module['_windows_process'](pid)
    try:token=str(module['_windows_process_token'](kernel,handle))
    finally:kernel.CloseHandle(handle)
wait=module['_parent_watcher'](pid,token)
Path(sys.argv[2]).write_text('ready')
wait()
Path(sys.argv[3]).write_text('parent exited')
''')
        fixture=work/'parent.py'
        fixture.write_text('''import subprocess,sys,time
from pathlib import Path
subprocess.Popen([sys.executable,'-I',sys.argv[1],*sys.argv[2:5]])
while not Path(sys.argv[5]).exists():time.sleep(.05)
''')
        ready=work/'ready';done=work/'done';exit_now=work/'exit-now'
        parent=subprocess.Popen([python,'-I',str(fixture),str(child),str(helper),str(ready),str(done),str(exit_now)])
        try:
            deadline=time.monotonic()+30
            while not ready.exists() and time.monotonic()<deadline:
                if parent.poll() is not None:self.fail('Fixture parent exited before readiness')
                time.sleep(.05)
            self.assertTrue(ready.exists());self.assertFalse(done.exists())
            time.sleep(.1);self.assertFalse(done.exists())
            exit_now.touch();parent.wait(timeout=10)
            deadline=time.monotonic()+10
            while not done.exists() and time.monotonic()<deadline:time.sleep(.05)
            self.assertEqual(done.read_text(),'parent exited')
        finally:
            if parent.poll() is None:parent.terminate();parent.wait(timeout=10)


if __name__=='__main__':unittest.main()
