"""Bounded regular ar inventory; never follows thin-archive references."""
import hashlib
from pathlib import Path
from .integrity import IntegrityError

CHUNK = 1024 * 1024
MAX_ARCHIVE = 2_000_000_000
MAX_MEMBERS = 40000
MAX_NAMES = 4 * 1024 * 1024


def archive_members(path):
    result=[];seen=set();names=b'';have_names=False;name_bytes=0;count=0
    with Path(path).open('rb') as handle:
        total=handle.seek(0,2);handle.seek(0)
        if total>MAX_ARCHIVE:raise IntegrityError('Archive size limit exceeded')
        def read(length):
            data=handle.read(length)
            if len(data)!=length:raise IntegrityError('Truncated ar member')
            return data
        if read(8)!=b'!<arch>\n':raise IntegrityError('Unsupported or thin archive')
        while handle.tell()<total:
            count+=1
            if count>MAX_MEMBERS:raise IntegrityError('Archive member limit exceeded')
            header=read(60)
            if header[58:60]!=b'`\n':raise IntegrityError('Malformed ar member')
            try:
                size_text=header[48:58].decode('ascii').strip()
                if not size_text or not all('0'<=c<='9' for c in size_text):raise ValueError()
                size=int(size_text);name=header[:16].decode('ascii').strip()
            except (UnicodeError,ValueError) as exc:
                raise IntegrityError('Malformed ar header') from exc
            end=handle.tell()+size
            if end+(size%2)>total:raise IntegrityError('Truncated ar member or padding')
            remaining=size
            if name=='//':
                if have_names or size>CHUNK:raise IntegrityError('Archive name table limit or duplicate')
                names=read(size);have_names=True
            elif name in ('/','/SYM64/'):
                handle.seek(end)  # Symbol index is not an object member.
            else:
                try:
                    if name.startswith('/') and name[1:].isdigit():
                        start=int(name[1:])
                        if start>=len(names) or (start and names[start-1]!=10):raise ValueError()
                        stop=names.find(b'/\n',start,min(len(names),start+4098))
                        if stop<0:raise ValueError()
                        name=names[start:stop].decode('utf-8')
                    elif name.startswith('#1/'):
                        digits=name[3:]
                        if not digits.isascii() or not digits.isdigit():raise ValueError()
                        length=int(digits)
                        if not 0<length<=min(size,4096):raise ValueError()
                        name=read(length).rstrip(b'\0').decode('utf-8');remaining-=length
                    else:name=name.rstrip('/')
                except (UnicodeError,ValueError) as exc:
                    raise IntegrityError('Invalid ar long name') from exc
                if not name or len(name.encode('utf-8'))>4096 or any(ord(c)<32 or ord(c)==127 for c in name):
                    raise IntegrityError('Invalid ar member name')
                name_bytes+=len(name.encode('utf-8'))
                if name_bytes>MAX_NAMES:raise IntegrityError('Archive member name budget exceeded')
                if name in seen:raise IntegrityError('Ambiguous duplicate archive member')
                seen.add(name);digest=hashlib.sha256();body_size=remaining
                while remaining:
                    amount=min(CHUNK,remaining);digest.update(read(amount));remaining-=amount
                result.append({'name':name,'sha256':digest.hexdigest(),'size':body_size})
            if handle.tell()!=end:raise IntegrityError('Invalid ar member boundary')
            if size%2 and read(1)!=b'\n':raise IntegrityError('Invalid ar padding')
    return result
