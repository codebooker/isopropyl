"""Streaming UNIX compress (.Z) LZW decoding with bounded dictionaries."""
# SPDX-License-Identifier: AGPL-3.0-or-later
import io


class CompressReader(io.RawIOBase):
    def __init__(self,source,cancel_check=None):
        header=source.read(3)
        if len(header)!=3 or header[:2]!=b'\x1f\x9d' or header[2]&0x60 or not 9<=header[2]&0x1f<=16:
            raise OSError('Invalid UNIX compress header')
        self.source=source;self.cancel_check=cancel_check or (lambda:None)
        self.maximum=header[2]&0x1f;self.block=bool(header[2]&0x80)
        self.prefix=[0]*(1<<self.maximum);self.suffix=bytearray(1<<self.maximum)
        self.width=9;self.next=257 if self.block else 256;self.previous=None
        self.group=b'';self.position=0;self.pending=bytearray();self.eof=False

    def readable(self):return True

    def code(self):
        if self.next>(1<<self.width)-1 and self.width<self.maximum:
            self.width+=1;self.group=b'';self.position=0
        if not self.group or self.position+self.width>len(self.group)*8:
            self.group=self.source.read(self.width);self.position=0
            if len(self.group)*8<self.width:return None
        start=self.position//8;shift=self.position%8
        value=int.from_bytes(self.group[start:start+3],'little')>>shift
        self.position+=self.width
        return value&((1<<self.width)-1)

    def expand(self,code):
        if code>=self.next:raise OSError('Invalid compress dictionary reference')
        output=bytearray()
        while code>=256:
            if len(output)>len(self.prefix):raise OSError('Cyclic compress dictionary')
            output.append(self.suffix[code]);code=self.prefix[code]
        output.append(code);output.reverse();return output

    def readinto(self,buffer):
        if self.closed:raise ValueError('Decoder is closed')
        while len(self.pending)<len(buffer) and not self.eof:
            self.cancel_check();code=self.code()
            if code is None:self.eof=True;break
            if self.block and code==256:
                self.next=257;self.width=9;self.previous=None;self.group=b'';self.position=0
                continue
            if self.previous is None:
                if code>=256:raise OSError('Compress stream must start with a literal')
                current=bytearray([code])
            elif code==self.next:
                current=self.expand(self.previous);current.append(current[0])
            else:current=self.expand(code)
            if self.previous is not None and self.next<len(self.prefix):
                self.prefix[self.next]=self.previous;self.suffix[self.next]=current[0];self.next+=1
            self.previous=code;self.pending.extend(current)
        size=min(len(buffer),len(self.pending));buffer[:size]=self.pending[:size];del self.pending[:size]
        return size
