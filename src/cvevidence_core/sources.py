"""Read-only tools; no paths or shell commands accepted from the model."""
from __future__ import annotations
import difflib,json
from .integrity import InputPackage,IntegrityError,digest
MAX_TEXT_BYTES=3_000_000

def list_sources(context:InputPackage,contains:str='',limit:int=100)->dict:
 if not isinstance(contains,str) or len(contains)>200 or not 1<=limit<=300:raise ValueError('Invalid list arguments')
 rows=[r for r in context.sources.values() if contains.casefold() in r['path'].casefold()]
 return {'sources':rows[:limit],'total':len(rows),'truncated':len(rows)>limit,'context_hash':context.context_hash}

def text_lines(context,source_id):
 p,item=context.source(source_id)
 if item['size']>MAX_TEXT_BYTES:raise ValueError('Text source exceeds limit')
 data=p.read_bytes()
 if b'\0' in data:raise ValueError('Binary source cannot be read as text')
 try:return data.decode('utf-8').splitlines()
 except UnicodeDecodeError as e:raise ValueError('Source is not UTF-8 text') from e

def read_excerpt(context:InputPackage,source_id:str,start_line:int=1,end_line:int=60)->dict:
 if type(start_line) is not int or type(end_line) is not int or start_line<1 or end_line<start_line or end_line-start_line>=200:raise ValueError('Invalid line range')
 lines=text_lines(context,source_id)
 if start_line>len(lines):raise ValueError('Line range exceeds source')
 end_line=min(end_line,len(lines));excerpt='\n'.join(lines[start_line-1:end_line]);row=context.sources[source_id]
 payload={'source_id':source_id,'file_sha256':row['sha256'],'start_line':start_line,'end_line':end_line,'text':excerpt,'context_hash':context.context_hash}
 return {'excerpt_id':'X-'+digest(payload)[:24],**payload}

def search_sources(context:InputPackage,term:str,source_ids:list[str]|None=None,limit:int=30)->dict:
 if not isinstance(term,str) or not term or len(term)>200 or not 1<=limit<=100:raise ValueError('Invalid literal search')
 ids=source_ids if source_ids is not None else list(context.sources)
 if len(ids)>40000:raise ValueError('Too many sources')
 matches=[];skipped=0
 for sid in ids:
  if sid not in context.sources:raise IntegrityError('Unknown source_id')
  if context.sources[sid]['kind']!='file':continue
  try:lines=text_lines(context,sid)
  except ValueError as e:
   if isinstance(e,IntegrityError):raise
   skipped+=1;continue
  for n,line in enumerate(lines,1):
   if term.casefold() in line.casefold():
    matches.append(read_excerpt(context,sid,max(1,n-2),min(len(lines),n+2)))
    if len(matches)>=limit:return {'matches':matches,'truncated':True,'skipped_nontext_or_large':skipped}
 return {'matches':matches,'truncated':False,'skipped_nontext_or_large':skipped}

def compare_sources(context:InputPackage,left_id:str,right_id:str)->dict:
 left,_=context.source(left_id);right,_=context.source(right_id)
 a=context.sources[left_id];b=context.sources[right_id]
 result={'left_id':left_id,'right_id':right_id,'left_sha256':a['sha256'],'right_sha256':b['sha256'],'identical_bytes':a['sha256']==b['sha256'],'context_hash':context.context_hash}
 try:
  lines=list(difflib.unified_diff(text_lines(context,left_id),text_lines(context,right_id),fromfile=left_id,tofile=right_id,n=3))
  result.update(diff='\n'.join(lines[:200]),truncated=len(lines)>200)
 except ValueError as e:
  if isinstance(e,IntegrityError):raise
  result.update(diff=None,truncated=False)
 return result

def verify_excerpt(context:InputPackage,excerpt:dict)->bool:
 try:return read_excerpt(context,excerpt['source_id'],excerpt['start_line'],excerpt['end_line'])==excerpt
 except (KeyError,ValueError,OSError):return False
