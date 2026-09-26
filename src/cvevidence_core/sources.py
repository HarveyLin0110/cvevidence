"""Read-only tools; no paths or shell commands accepted from the model."""
from __future__ import annotations
import difflib,json
from .integrity import InputPackage,IntegrityError,digest
MAX_TEXT_BYTES=3_000_000
MAX_SEARCH_BYTES=16_000_000
MAX_SEARCH_FILES=500

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
 return {'excerpt_id':'X-'+digest({k:v for k,v in payload.items() if k!='context_hash'})[:24],**payload}

def search_sources(context:InputPackage,term:str,source_ids:list[str]|None=None,limit:int=30)->dict:
 if not isinstance(term,str) or not term or len(term)>200 or type(limit) is not int or not 1<=limit<=100:raise ValueError('Invalid literal search')
 ids=source_ids if source_ids is not None else list(context.sources)
 if len(ids)>40000:raise ValueError('Too many sources')
 if any(sid not in context.sources for sid in ids):raise IntegrityError('Unknown source_id')
 ids=list(dict.fromkeys(sid for sid in ids if context.sources[sid]['kind']=='file'))
 all_files={sid for sid,row in context.sources.items() if row['kind']=='file'}
 hits=[];skipped=[];scanned=0;attempted=0;used=0;total_hits=0;needle=term.casefold()
 for sid in ids:
  if attempted>=MAX_SEARCH_FILES:break
  row=context.sources[sid]
  if row['size']>MAX_TEXT_BYTES:
   attempted+=1;skipped.append(sid);continue
  if used+row['size']>MAX_SEARCH_BYTES:break
  attempted+=1;used+=row['size']
  try:lines=text_lines(context,sid)
  except ValueError as e:
   if isinstance(e,IntegrityError):raise
   skipped.append(sid);continue
  scanned+=1;locations=[];count=0
  for n,line in enumerate(lines,1):
   if needle in line.casefold():
    count+=1
    if len(locations)<limit:locations.append(n)
  if count:hits.append((sid,locations,len(lines),count));total_hits+=count
 # One excerpt from each matching file before taking a second from any file.
 matches=[]
 for offset in range(limit):
  for sid,locations,length,count in hits:
   if offset>=len(locations):continue
   n=locations[offset];matches.append(read_excerpt(context,sid,max(1,n-2),min(length,n+2)))
   if len(matches)>=limit:break
  if len(matches)>=limit:break
 unsearched=len(ids)-attempted
 return {'matches':matches,'truncated':total_hits>len(matches) or bool(unsearched or skipped),
         'skipped_nontext_or_large':len(skipped),'skipped_source_ids':skipped[:20],
         'searched_file_count':scanned,'scope_file_count':len(ids),'context_file_count':len(all_files),
         'scope_covers_all_files':set(ids)==all_files,'unsearched_file_count':unsearched,
         'coverage_limited':bool(unsearched or skipped),'searched_bytes':used,
         'total_matching_lines':total_hits,'matching_file_count':len(hits),
         'matching_sources':[{'source_id':sid,'path':context.sources[sid]['path'],'matching_lines':count}
                             for sid,_,_,count in hits[:60]],
         'matching_sources_truncated':len(hits)>60,
         'note':'片段優先涵蓋不同檔案，再取同檔其他命中；可指定來源继续 READ／SEARCH。計數只涵蓋本次選取與已讀文字，未查、過大或非文字檔不能推論沒有其他副本；搜尋不證明成品綁定。'}

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
