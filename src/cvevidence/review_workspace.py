"""Local operator review UI, separate from automatic engineering assessments."""
import json
from uuid import uuid4
from cvevidence_core.integrity import digest

RELATIONS = {'UNRESOLVED':'尚無法確認', 'SUPPORTED':'原文足以支持此條件',
             'EXCLUDED':'原文足以排除此條件', 'CONFLICT':'證據存在矛盾'}


def report_text(record):
    receipt = record['receipt']
    rows = ['人工條件覆核（獨立紀錄；未改變工程判定）',
            '覆核紀錄：'+record['review_id'], 'AI 紀錄：'+record['ai_id'],
            '時間：'+record['created_at'], '覆核者（自行填寫，未驗證身分）：'+receipt['reviewer'],
            '證據包：'+record['dossier_hash']]
    for row in receipt['conditions']:
        rows += [row['condition_id']+' · '+RELATIONS[row['relation']], '理由：'+row['rationale'],
                 '核對原文：'+', '.join(row['excerpt_ids'])]
    rows.append('此紀錄保存本機操作員的判讀與原文核對，不代表自動語意證明、身分認證或正式安全核准。')
    return '\n'.join(rows)


def review_workspace(st, runner, run, ai_record):
    if not ai_record or not ai_record.get('result'):
        return None
    ai = ai_record['result']['analyses'][0]['ai']
    dossier = ai.get('condition_dossier')
    if not dossier:
        return None
    ai_id = ai_record['request']['ai_id']
    if ai_record['request']['parent_run_id'] != run.run_id or dossier.get('context_hash') != run.input_package.context_hash or dossier.get('cve_id') != run.cve_id:
        st.error('覆核案件與證據包範圍不一致。')
        return None
    st.subheader('工程師條件覆核')
    st.caption('針對目前選取的 AI 紀錄逐條確認；保存時會重查原文，原工程判定保持不變。覆核者姓名為本機自行填寫，尚未連接公司登入。')
    try:
        records, rejected = runner.condition_reviews(run.run_id, ai_id)
    except (ValueError, OSError, KeyError, TypeError):
        st.error('覆核歷史無法核對，未附加至報告。')
        return None
    if rejected:
        st.warning('部分覆核紀錄無法核對，已排除；原檔保留。')
    selected = None
    if records:
        by_id = {r['review_id']:r for r in records}
        fresh = st.session_state.pop('review-new-'+ai_id, None)
        if fresh in by_id:
            st.session_state['review-selection-'+ai_id] = fresh
        chosen = st.selectbox('報告附加的人工覆核', ['']+list(by_id), index=1,
            format_func=lambda x:'不附加人工覆核' if not x else by_id[x]['created_at'][:19]+' · '+by_id[x]['receipt']['reviewer']+' · '+x[:8],
            key='review-selection-'+ai_id)
        selected = by_id.get(chosen)
        if selected:
            with st.expander('查看已保存的逐條覆核'):
                st.text(report_text(selected))
            st.download_button('下載人工覆核紀錄',json.dumps(selected,ensure_ascii=False,indent=2),
                file_name=selected['review_id']+'-review.json',mime='application/json',key='review-download-'+ai_id)
    else:
        st.info('尚無人工覆核紀錄。可展開下方逐條記錄，或先保留待覆核報告。')
    with st.expander('新增逐條覆核', expanded=False):
        with st.form('review-form-'+ai_id):
            reviewer = st.text_input('覆核者姓名／公司識別', max_chars=100)
            decisions = []
            for row in dossier['conditions']:
                cid = row['condition_id']
                st.text(cid+' · '+row['layer']+' · '+row['requirement'])
                st.caption('AI 觀察：'+row['explanation'])
                for evidence in row.get('evidence',[]):
                    st.text(evidence['path']+':'+str(evidence['start_line'])+'–'+str(evidence['end_line']))
                    with st.expander(cid+' 覆核原文 '+evidence['excerpt_id']):
                        st.code(evidence['text'],language=None)
                relation = st.selectbox(cid+' 覆核判讀',list(RELATIONS),format_func=RELATIONS.get,key='review-relation-'+ai_id+'-'+cid)
                rationale = st.text_area(cid+' 判讀理由',max_chars=2000,key='review-reason-'+ai_id+'-'+cid)
                decisions.append(dict(condition_id=cid,relation=relation,rationale=rationale))
            confirmed = st.checkbox('我已逐條核對材料，了解此紀錄不會直接改變正式工程判定。')
            submitted = st.form_submit_button('保存人工覆核')
        if submitted:
            if not confirmed or not reviewer.strip() or any(not r['rationale'].strip() for r in decisions):
                st.error('請填寫覆核者、每項理由，並確認已核對材料。')
            else:
                decision = dict(dossier_hash=dossier['dossier_hash'],reviewer=reviewer.strip(),conditions=decisions)
                token_key = 'review-submit-'+ai_id+'-'+digest(decision)
                review_id = st.session_state.setdefault(token_key,str(uuid4()))
                try:
                    saved = runner.review_conditions(run.run_id,ai_id,decision,review_id=review_id)
                except (ValueError, OSError, RuntimeError, KeyError, TypeError):
                    st.error('覆核未保存：請確認條件、引用材料與案件範圍；支持／排除／矛盾必須有可核對原文。')
                else:
                    st.session_state['review-new-'+ai_id] = saved['review_id']
                    st.rerun()
    return selected
