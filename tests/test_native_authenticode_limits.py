# SPDX-License-Identifier: AGPL-3.0-or-later
import ctypes as c
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from isopropyl import native_authenticode as auth
from tests.test_portable_fs_windows import Call

class JobLimitsTests(unittest.TestCase):
    def make_api(self,assign=True,query=True):
        saved={}
        def configure(job,kind,pointer,size):saved['limits']=pointer._obj;return True
        def inspect(job,kind,pointer,size,returned):
            observed=pointer._obj;requested=saved['limits']
            observed.Basic.Flags=requested.Basic.Flags;observed.Basic.Active=1
            observed.Basic.ProcessTime=requested.Basic.ProcessTime;observed.ProcessMemory=requested.ProcessMemory
            return query
        return SimpleNamespace(CreateJobObjectW=Call(lambda *a:17),SetInformationJobObject=Call(configure),
            GetCurrentProcess=Call(lambda:22),AssignProcessToJobObject=Call(lambda *a:assign),
            QueryInformationJobObject=Call(inspect),CloseHandle=Call(lambda *a:True)),saved
    def test_nested_job_is_assigned_verified_and_retained(self):
        api,saved=self.make_api()
        with patch.object(c,'WinDLL',return_value=api,create=True):auth.limit_current_process(128*1024**2,7)
        self.assertEqual(api.AssignProcessToJobObject.calls,[(17,22)])
        self.assertEqual(saved['limits'].Basic.Flags,0x100|8|2)
        self.assertEqual(saved['limits'].ProcessMemory,128*1024**2)
        self.assertEqual(saved['limits'].Basic.ProcessTime,70_000_000)
        self.assertFalse(api.CloseHandle.calls);self.assertIn(17,auth._jobs);auth._jobs.remove(17)
    def test_assignment_failure_preserves_windows_last_error_and_closes_job(self):
        api,_=self.make_api(assign=False)
        with patch.object(c,'WinDLL',return_value=api,create=True),patch.object(c,'get_last_error',return_value=5,create=True):
            with self.assertRaises(OSError) as caught:auth.limit_current_process(128*1024**2,7)
        self.assertEqual(caught.exception.errno,5);self.assertIn('nested jobs',str(caught.exception))
        self.assertEqual(api.CloseHandle.calls,[(17,)])
    def test_failed_bound_query_closes_job_and_fails_closed(self):
        api,_=self.make_api(query=False)
        with patch.object(c,'WinDLL',return_value=api,create=True),patch.object(c,'get_last_error',return_value=87,create=True):
            with self.assertRaisesRegex(OSError,'verify'):auth.limit_current_process(128*1024**2,7)
        self.assertEqual(api.CloseHandle.calls,[(17,)])

    def test_unapplied_memory_or_descendant_bound_is_rejected(self):
        api,_=self.make_api()
        def incomplete(job,kind,pointer,size,returned):
            pointer._obj.Basic.Flags=2
            pointer._obj.Basic.Active=4
            pointer._obj.Basic.ProcessTime=70_000_000
            pointer._obj.ProcessMemory=128*1024**2
            return True
        api.QueryInformationJobObject=Call(incomplete)
        with patch.object(c,'WinDLL',return_value=api,create=True):
            with self.assertRaisesRegex(OSError,'required bounds'):auth.limit_current_process(128*1024**2,7)
        self.assertEqual(api.CloseHandle.calls,[(17,)])
