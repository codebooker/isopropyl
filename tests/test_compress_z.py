# SPDX-License-Identifier: AGPL-3.0-or-later
"""External BSD compress fixtures exercise width growth and dictionary reset."""
import hashlib,io,json,unittest
from pathlib import Path
from isopropyl.compress_z import CompressReader
ROOT=Path(__file__).with_name('data')/'compress'
class CompressTests(unittest.TestCase):
    def test_external_dictionary_growth_clear_and_streaming_boundaries(self):
        for fixture in json.loads((ROOT/'manifest.json').read_text()):
            with self.subTest(fixture=fixture['file']):
                with (ROOT/fixture['file']).open('rb') as source:
                    reader=io.BufferedReader(CompressReader(source),buffer_size=257)
                    digest=hashlib.sha256();size=0
                    while data:=reader.read(997):digest.update(data);size+=len(data)
                self.assertEqual(size,fixture['size']);self.assertEqual(digest.hexdigest(),fixture['sha256'])
    def test_valid_nine_bit_literal_stream(self):
        # Hand-encoded independent LZW vector: A, B, dictionary[257] = AB.
        bits=65|(66<<9)|(257<<18)
        payload=b'\x1f\x9d\x89'+bits.to_bytes(4,'little')
        self.assertEqual(io.BufferedReader(CompressReader(io.BytesIO(payload))).read(),b'ABAB')
    def test_malformed_dictionary_and_header_fail(self):
        for payload in (b'',b'bad',b'\x1f\x9d\x88',b'\x1f\x9d\x89\xff\x01'):
            with self.subTest(payload=payload),self.assertRaises(OSError):
                io.BufferedReader(CompressReader(io.BytesIO(payload))).read()
    def test_cancellation_during_decode(self):
        def cancel():raise InterruptedError('cancelled')
        with self.assertRaises(InterruptedError):
            io.BufferedReader(CompressReader(io.BytesIO(b'\x1f\x9d\x89A\x00'),cancel)).read()
