"""Bounded ELF program-header metadata; never loads or executes a product.

Layout: https://gabi.xinuos.com/elf/{02-eheader,07-pheader,08-dynamic}.html
Names in DT_NEEDED are declarations, not resolved deployed dependencies.
"""
import struct
import json
from pathlib import Path


class ELFError(ValueError):pass


def _symbols(read,wide,endian,shoff,shsize,shnum):
    """Section-backed dynamic symbols only, not disassembly or runtime binding."""
    if not shoff and not shnum:return {'status':'NO_SECTION_TABLE','imports':[],'definitions':[],'coverage_limited':True}
    if not shoff or not 0<shnum<=4096 or shsize!=(64 if wide else 40):raise ELFError('Section table limit')
    sections=[struct.unpack(endian+('IIQQQQIIQQ' if wide else 'IIIIIIIIII'),
                           read(shoff+i*shsize,shsize)) for i in range(shnum)]
    tables=[s for s in sections if s[1]==11]
    if not tables:return {'status':'NO_DYNAMIC_SYMBOL_TABLE','imports':[],'definitions':[],'coverage_limited':True}
    if len(tables)!=1:raise ELFError('Ambiguous dynamic symbol table')
    s=tables[0];offset,length,link,entry=s[4],s[5],s[6],s[9]
    if s[2]&0x800 or entry!=(24 if wide else 16) or length<entry or length%entry or length//entry>16384 or link>=len(sections):
        raise ELFError('Dynamic symbol table limit')
    strings_section=sections[link]
    if strings_section[1]!=3 or strings_section[2]&0x800 or not 0<strings_section[5]<=1024*1024:
        raise ELFError('Invalid symbol string section')
    strings=read(strings_section[4],strings_section[5])
    if strings[0]!=0 or strings[-1]!=0:raise ELFError('Invalid symbol strings')
    groups={'imports':[],'definitions':[]};counts={'imports':0,'definitions':0}
    for i in range(length//entry):
        row=struct.unpack(endian+('IBBHQQ' if wide else 'IIIBBH'),read(offset+i*entry,entry))
        if wide:name_index,info,_,section,_,_=row
        else:name_index,_,_,info,_,section=row
        if not name_index:continue
        if name_index>=len(strings) or section==65535 or (shnum<=section<0xff00):raise ELFError('Invalid symbol index')
        end=strings.find(b'\0',name_index,min(len(strings),name_index+1025))
        if end<0:raise ELFError('Symbol name limit')
        try:name=strings[name_index:end].decode('utf-8')
        except UnicodeError as exc:raise ELFError('Symbol encoding unsupported') from exc
        if not name or any(ord(c)<32 or ord(c)==127 for c in name):raise ELFError('Invalid symbol name')
        if info>>4==0:continue
        group='imports' if section==0 else 'definitions';counts[group]+=1
        if len(groups[group])<128:groups[group].append({'name':name,'type':info&15,'binding':info>>4})
    return {'status':'READ',**groups,'counts':counts,'coverage_limited':any(n>128 for n in counts.values()),
            'runtime_binding_verified':False,'call_path_verified':False}


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
        kind,machine,version,_,phoff,shoff,_,ehsize,phsize,phnum,shsize,shnum,_=header
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
        def complete():
            try:result['symbols']=_symbols(read,wide,endian,shoff,shsize,shnum)
            except ELFError:result['symbols']={'status':'UNSUPPORTED_OR_LIMITED','imports':[],'definitions':[],'coverage_limited':True}
            return result
        if not dynamic:return complete()
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
        return complete()


def inventory(context):
    """Bounded metadata coverage, not a binary-to-build or CVE proof."""
    rows=[];used=0;probed=0;output_bytes=0
    files=[r for r in context.sources.values() if r['kind']=='file']
    by_hash={}
    for source in files:by_hash.setdefault(source['sha256'],[]).append(source)
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
        matches=[r for r in by_hash[row['sha256']] if r['source_id']!=row['source_id']]
        item['identical_delivered_files']=[]
        for match in matches[:8]:
            if used+match['size']>64*1024*1024:break
            context.source(match['source_id']);used+=match['size']
            item['identical_delivered_files'].append({'source_id':match['source_id'],'path':match['path']})
        item['matches_coverage_limited']=len(matches)>len(item['identical_delivered_files'])
        try:item.update(status='READ',metadata=inspect(path))
        except ELFError:item.update(status='UNSUPPORTED_OR_MALFORMED',metadata=None)
        encoded=len(json.dumps(item,ensure_ascii=False).encode())
        if output_bytes+encoded>32000:
            item.update(status='METADATA_LIMIT',metadata=None)
        output_bytes+=len(json.dumps(item,ensure_ascii=False).encode())
        rows.append(item)
    return {'files':rows,'probed_files':probed,'total_files':len(files),
            'coverage_limited':probed<len(files),
            'note':'ELF 架構、動態依賴與符號來自檔案結構；符號存在不代表路徑可達，未列出也不代表未使用（可能靜態整合、動態查找或讀取受限）。尚未確認實際載入版本、同一建置或 CVE 適用性。'}
