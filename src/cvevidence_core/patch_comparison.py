"""Literal before/after hunk observations, never patch execution or a verdict."""
from pathlib import PurePosixPath
import re
from .integrity import IntegrityError,digest
from .public_reader import _source
from .sources import text_lines

MAX_HUNKS=64
MAX_SOURCE_BYTES=1_000_000
MAX_HUNK_LINES=200
NOTE=('只逐行比較完整 diff 區塊（含上下文），不忽略空白、不執行 patch。'
      '檔名僅篩選候選；未匹配不證明沒有修補，匹配也不證明語意、編譯、同建置、全部副本或部署。')


def hunks(text):
    """Reject an incomplete/unsupported unified diff as a whole, not a prefix."""
    lines=text.splitlines();rows=[];path=None;i=0;file_seen=False;active=False;had_hunk=False
    while i<len(lines):
        line=lines[i]
        if line.startswith('diff --git '):
            if active and not had_hunk:raise ValueError('PATCH_TRUNCATED')
            path=None;file_seen=False;active=True;had_hunk=False
        elif line.startswith('--- '):
            if file_seen:raise ValueError('PATCH_HEADERS')
            if i+1>=len(lines) or not lines[i+1].startswith('+++ '):raise ValueError('PATCH_HEADERS')
            old=line[4:];new=lines[i+1][4:]
            # Quoted paths, additions/deletions and renames need another reader.
            if (not old.startswith('a/') or not new.startswith('b/') or old[2:]!=new[2:]
                    or not re.fullmatch(r'[\w./-]{1,1000}',new[2:]) or '..' in PurePosixPath(new[2:]).parts):
                raise ValueError('PATCH_PATH_KIND')
            path=new[2:];file_seen=True;i+=1
        elif line.startswith('@@'):
            m=re.fullmatch(r'@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@.*',line)
            if not m or not file_seen:raise ValueError('PATCH_HUNK_HEADER')
            old_count=int(m[2] or 1);new_count=int(m[4] or 1)
            if (not 1<=old_count<=MAX_HUNK_LINES or not 1<=new_count<=MAX_HUNK_LINES
                    or len(rows)>=MAX_HUNKS):raise ValueError('PATCH_LIMIT')
            before=[];after=[];start=i+1;changed=False;i+=1
            while len(before)<old_count or len(after)<new_count:
                if i>=len(lines):raise ValueError('PATCH_TRUNCATED')
                part=lines[i]
                if part=='\\ No newline at end of file':i+=1;continue
                if not part or part[0] not in ' +-':raise ValueError('PATCH_TRUNCATED')
                if part[0] in ' -':before.append(part[1:])
                if part[0] in ' +':after.append(part[1:])
                changed|=part[0] in '+-';i+=1
                if len(before)>old_count or len(after)>new_count:raise ValueError('PATCH_COUNTS')
            if not changed:raise ValueError('PATCH_UNCHANGED')
            rows.append({'path':path,'patch_start_line':start,'patch_end_line':i,
                         'before':before,'after':after})
            had_hunk=True
            continue
        elif line.startswith(('GIT binary patch','Binary files ','@@@')):
            raise ValueError('PATCH_KIND')
        elif active and line.startswith(('+','-')) and line!='-- ':
            raise ValueError('PATCH_COUNTS')
        i+=1
    if active and not had_hunk:raise ValueError('PATCH_TRUNCATED')
    if not rows:raise ValueError('NO_UNIFIED_HUNKS')
    return rows


def _locations(lines,block):
    # Save at most two: duplicates disqualify a unique whole-hunk observation.
    hits=[]
    for i,line in enumerate(lines):
        if line==block[0] and lines[i:i+len(block)]==block:
            hits.append({'start_line':i+1,'end_line':i+len(block)})
            if len(hits)==2:break
    return hits


def compare(context,source_id,bundle):
    """Only model-read scoped sources are submitted by the caller."""
    _,item=context.source(source_id);candidates=[]
    for source in bundle.get('sources',[]):
        if 'diff --git ' not in source.get('text',''):continue
        s=_source(bundle,source['source_id'])
        if s.get('truncated'):continue
        try:blocks=hunks(s['text'])
        except ValueError:continue
        selected=[h for h in blocks if PurePosixPath(h['path']).name==PurePosixPath(item['path']).name]
        if selected:candidates.append((s,selected))
    if not candidates:return []
    if item['size']>MAX_SOURCE_BYTES:return [{'source_id':source_id,'status':'SOURCE_BYTE_LIMIT','note':NOTE}]
    try:lines=text_lines(context,source_id)
    except IntegrityError:raise
    except (ValueError,OSError):return [{'source_id':source_id,'status':'SOURCE_UNREADABLE','note':NOTE}]
    output=[]
    for source,blocks in candidates:
        observations=[]
        for h in blocks:
            before=_locations(lines,h['before']);after=_locations(lines,h['after'])
            status=('BEFORE_ONLY' if len(before)==1 and not after else
                    'AFTER_ONLY' if len(after)==1 and not before else
                    'AMBIGUOUS' if before or after else 'NOT_MATCHED')
            observations.append({k:h[k] for k in ('path','patch_start_line','patch_end_line')}|
                {'before_locations':before,'after_locations':after,'status':status})
        states={h['status'] for h in observations}
        status=('AFTER_TEXT_MATCH' if states=={'AFTER_ONLY'} else 'BEFORE_TEXT_MATCH'
                if states=={'BEFORE_ONLY'} else 'PARTIAL_OR_DIFFERENT')
        payload={'context_hash':context.context_hash,'source_id':source_id,'path':item['path'],
            'file_sha256':item['sha256'],'public_source_id':source['source_id'],
            'public_text_sha256':source['text_sha256'],'status':status,'hunks':observations,
            'candidate_selection':'BASENAME_HINT_ONLY','comparison_scope':'SAVED_SOURCE_FULL_TEXT',
            'source_byte_limit':MAX_SOURCE_BYTES,'semantic_verification':False,
            'same_build_verified':False,'all_product_copies_verified':False,'note':NOTE}
        output.append({**payload,'comparison_id':'M-'+digest(payload)[:24]})
    return output


def check_exclusions(rows,excerpts,comparisons):
    """New generic proposals must not close unknowns on an unchecked exclusion.

    The current mechanical capability is intentionally narrow. Runtime successes,
    absence of observed attacks, configuration semantics and equivalent rewrites
    need further review, not a fabricated automatic exclusion or new user files.
    Existing immutable proposals are not rewritten.
    """
    accepted=[]
    for row in rows:
        if row['state']!='OBSERVED_EXCLUSION':continue
        unresolved=[r['condition_id'] for r in rows if r.get('necessity')=='REQUIRED'
            and r['layer'] in ('PC1','PC2') and r['state'] not in ('OBSERVED_SUPPORT','OBSERVED_EXCLUSION')]
        if unresolved:
            raise ValueError(f"{row['condition_id']} 只有原碼修補線索，其他必要產品／實作條件尚未完成：{', '.join(unresolved)}。原碼比對不能繞过產品身分、成品綁定、必要路徑或證據矛盾。請保留 patch 比較與引文，把本條件依實際原因記為 USER_MATERIAL_MISSING（缺成品綁定）、CAPABILITY_GAP 或 NOT_REVIEWED；有使用者缺口時 REVIEW 後只 ASK_USER 一個最關鍵條件，不能因為找到修補原碼而停止補件。")
        ids={excerpts[x]['source_id'] for x in row['citations'] if x in excerpts}
        matched=[c for c in comparisons if c.get('source_id') in ids and c['status']=='AFTER_TEXT_MATCH']
        if row['layer']!='PC2' or not matched:
            raise ValueError(f"{row['condition_id']} 排除依據尚無可核對的完整修補區塊比較。通用查核目前只接納 PC2 已引用原文與公開 patch 全部對應區塊逐行匹配的排除線索；其他排除方法、等效改寫、配置封閉或正常測試，保留 NOT_REVIEWED／CAPABILITY_GAP 並說明已有觀察及待覆核範圍，不改成缺件。正常輸入成功、未看到惡意輸入或沒有 TLS 均不能排除其他入口。")
        accepted.append({'condition_id':row['condition_id'],'comparison_ids':[c['comparison_id'] for c in matched],
                         'scope':'MATCHED_SOURCE_TEXT_ONLY','formal_verdict_unchanged':True})
    return accepted
