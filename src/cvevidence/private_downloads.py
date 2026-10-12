"""Deliver account reports in the authorized UI, never in global media storage.

Streamlit's native media endpoint serves a known file URL without rechecking
the caller's principal. Component code is constant; report bytes travel only
as per-session component data over the already-authorized workspace channel.
"""
import base64
import hashlib
import re

MAX_INLINE_BYTES = 32 * 1024 * 1024
JS = """
export default function(component) {
    const {parentElement, data} = component;
    const link = document.createElement("a");
    link.textContent = data.label;
    link.download = data.filename;
    link.href = "data:" + data.mime + ";base64," + data.content;
    link.className = "report-download";
    parentElement.appendChild(link);
    return () => { link.removeAttribute("href"); link.remove(); };
}
"""
CSS = """
.report-download {
    display: inline-block; padding: .45rem .8rem; border: 1px solid #738c894d;
    border-radius: .5rem; color: inherit; background: transparent;
    font: inherit; text-decoration: none; cursor: pointer;
}
.report-download:hover { border-color: #227868; color: #227868; }
.report-download:focus-visible { outline: 2px solid #227868; outline-offset: 2px; }
"""


def download_button(st, label, data, *, file_name, mime, key=None):
    """Keep local downloads compatible; account-mode exports use session data.

    No fallback to global media if authorization or inline rendering fails.
    This does not revoke files already delivered to an authorized browser.
    """
    if '_account_principal' not in st.session_state:
        return st.download_button(label, data, file_name=file_name, mime=mime, key=key)
    identity = st.session_state['_account_principal']
    if not isinstance(identity, str) or not re.fullmatch(r'[a-f0-9]{64}', identity):
        st.error('尚未確認帳號，未提供下載內容。請重新登入。')
        return
    if (not isinstance(label, str) or not isinstance(file_name, str)
            or not file_name or len(file_name) > 240
            or any(c in file_name for c in '/\\\r\n\x00')
            or mime not in ('application/json', 'text/plain')
            or not isinstance(data, (str, bytes))):
        st.error('下載格式無法核對，未提供內容。')
        return
    raw = data.encode('utf-8') if isinstance(data, str) else data
    if len(raw) > MAX_INLINE_BYTES:
        st.error('這份報告超過網頁下載的 32 MiB 上限，請由管理員從該帳號工作區匯出。原紀錄仍保留。')
        return
    from streamlit.components.v2 import component
    render = component('cvevidence_private_report', js=JS, css=CSS)
    # Never embed report content, identity, or user text in component assets.
    token = hashlib.sha256((identity + '\0' + (key or label) + '\0' + file_name).encode()).hexdigest()
    return render(key='private-download-' + token, data={
        'label': label, 'filename': file_name, 'mime': mime,
        'content': base64.b64encode(raw).decode('ascii'),
    }, width='content', height='content')
