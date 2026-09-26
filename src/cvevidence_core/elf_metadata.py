"""Bounded ELF program-header metadata; never loads or executes a product.

Layout: https://gabi.xinuos.com/elf/{02-eheader,07-pheader,08-dynamic}.html
Names in DT_NEEDED are declarations, not resolved deployed dependencies.
"""
import struct
import json
from pathlib import Path


class ELFError(ValueError):pass


def inspect(path):
    with Path(path).open('rb') as f:
        size=f.seek(0,2);budget=2*1024*1024
        def read(offset,length):
            nonlocal budget
            if offset<0 or length<0 or offset+length>size or length>budget:
                raise ELFError('ELF bounds or read limit')
            budget-=length;f.seek(offset);data=f.read(length)
            if len(data)!=length:raise ELFError('ELF truncated')
            return data
        ident=read(0,16)
        if ident[:4]!=b'\x7fELF' or ident[4] not in (1,2) or ident[5] not in (1,2) or ident[6]!=1:
            raise ELFError('Unsupported ELF identity')
        wide=ident[4]==2;endian='<' if ident[5]==1 else '>'
        fmt=endian+('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH')
        header=struct.unpack(fmt,read(16,struct.calcsize(fmt)))
        kind,machine,version,_,phoff,_,_,ehsize,phsize,phnum,_,_,_=header
        expected_ph=56 if wide else 32
        if version!=1 or ehsize!=(64 if wide else 52) or phnum>1024 or (phnum and phsize!=expected_ph):
            raise ELFError('Unsupported ELF header')
        loads=[];dynamic=[]
        for i in range(phnum):
            values=struct.unpack(endian+('IIQQQQQQ' if wide else 'IIIIIIII'),read(phoff+i*phsize,phsize))
            if wide:ptype,_,offset,address,_,filesz,memsz,_=values
            else:ptype,offset,address,_,filesz,memsz,_,_=values
            if offset+filesz>size or (ptype==1 and filesz>memsz):raise ELFError('Invalid ELF segment')
            if ptype==1:loads.append((offset,address,filesz))
            if ptype==2:dynamic.append((offset,filesz))
        result={'class_bits':64 if wide else 32,'byte_order':'little' if endian=='<' else 'big',
                'machine_id':machine,'elf_type':kind,'needed':[],'soname':None,
                'dynamic_status':'NO_DYNAMIC_SEGMENT','runtime_resolution_verified':False}
        if not dynamic:return result
        if len(dynamic)!=1:raise ELFError('Ambiguous dynamic segment')
        offset,length=dynamic[0];entry=16 if wide else 8
        if length%entry or length//entry>4096:raise ELFError('Dynamic entry limit')
        tags={};terminated=False
        for pos in range(offset,offset+length,entry):
            tag,value=struct.unpack(endian+('qQ' if wide else 'iI'),read(pos,entry))
            if tag==0:terminated=True;break
            tags.setdefault(tag,[]).append(value)
        if not terminated:raise ELFError('Unterminated dynamic table')
        wanted=tags.get(1,[])+tags.get(14,[])
        if len(wanted)>128 or len(tags.get(14,[]))>1:raise ELFError('ELF name limit')
        if wanted:
            if len(tags.get(5,[]))!=1 or len(tags.get(10,[]))!=1:raise ELFError('Missing dynamic strings')
            address=tags[5][0];length=tags[10][0]
            if not 0<length<=1024*1024:raise ELFError('ELF string table limit')
            offsets={off+address-va for off,va,n in loads if va<=address and address+length<=va+n}
            if len(offsets)!=1:raise ELFError('Ambiguous or unmapped ELF strings')
            strings=read(offsets.pop(),length)
            def name(index):
                if index>=length:raise ELFError('Invalid ELF string index')
                end=strings.find(b'\0',index,min(length,index+4097))
                if end<0:raise ELFError('Unterminated ELF name')
                try:value=strings[index:end].decode('utf-8')
                except UnicodeError as exc:raise ELFError('Unsupported ELF name encoding') from exc
                if not value or any(ord(c)<32 or ord(c)==127 for c in value):raise ELFError('Invalid ELF name')
                return value
            result['needed']=[name(i) for i in tags.get(1,[])]
            result['soname']=name(tags[14][0]) if 14 in tags else None
        result['dynamic_status']='READ'
        return result


def inventory(context):
    """Bounded metadata coverage, not a binary-to-build or CVE proof."""
    rows=[];used=0;probed=0;output_bytes=0
    files=[r for r in context.sources.values() if r['kind']=='file']
    def priority(row):
        p=row['path'].lower()
        return (0 if '.so' in p or '/bin/' in '/'+p or p.endswith('.elf') else 1,p)
    selected=sorted(files,key=priority)[:128]
    for row in selected:
        if len(rows)>=12:break
        if row['size']>16*1024*1024 or used+row['size']>64*1024*1024:continue
        path,checked=context.source(row['source_id']);used+=row['size'];probed+=1
        with path.open('rb') as f:magic=f.read(4)
        if magic!=b'\x7fELF':continue
        item={'source_id':row['source_id'],'path':row['path'],'sha256':checked['sha256'],
              'same_build_verified':False,'cve_applicability_verified':False}
        try:item.update(status='READ',metadata=inspect(path))
        except ELFError:item.update(status='UNSUPPORTED_OR_MALFORMED',metadata=None)
        encoded=len(json.dumps(item,ensure_ascii=False).encode())
        if output_bytes+encoded>32000:
            item.update(status='METADATA_LIMIT',metadata=None)
        output_bytes+=len(json.dumps(item,ensure_ascii=False).encode())
        rows.append(item)
    return {'files':rows,'probed_files':probed,'total_files':len(files),
            'coverage_limited':probed<len(files),
            'note':'ELF 架構與動態依賴名稱來自檔案結構；尚未確認實際載入版本、同一建置、可達路徑或 CVE 適用性。無 dynamic segment 不代表沒有靜態整合的元件。'}
