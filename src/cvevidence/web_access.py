"""Fail-closed identity policy for the separate hosted entry point."""
import hashlib
import re

def principal(user, allowed_emails):
    email = user.get("email", "")
    subject = user.get("sub", "")
    if (user.get("is_logged_in") is not True or user.get("email_verified") is not True
            or not isinstance(email, str) or not isinstance(subject, str) or not subject):
        raise ValueError("Verified Google identity required")
    if email.casefold() not in {e.strip().casefold() for e in allowed_emails if isinstance(e, str)}:
        raise ValueError("Account is not allowed")
    return hashlib.sha256(("google:" + subject).encode()).hexdigest()

def release_label(value):
    return value if re.fullmatch(r"[a-f0-9]{7,40}", value or "") else "unversioned"


def deployment_policy(secrets):
    """Validate operator configuration without returning or displaying secrets."""
    from urllib.parse import urlsplit
    try:
        allowed = secrets['deployment']['allowed_emails']
        auth = secrets['auth']
        google = auth['google']
        redirect = auth['redirect_uri']
        cookie = auth['cookie_secret']
        if not isinstance(allowed, list) or not allowed or any(
                not isinstance(e,str) or not re.fullmatch(r'[^\s@]+@[^\s@]+',e.strip()) for e in allowed):
            raise ValueError('Invalid allowlist')
        if not isinstance(redirect,str) or not isinstance(cookie,str) or len(cookie)<32:
            raise ValueError('Invalid auth configuration')
        url=urlsplit(redirect)
        if (url.scheme!='https' or not url.hostname or url.username or url.password
                or not url.path.endswith('/oauth2callback') or url.query or url.fragment):
            raise ValueError('Invalid callback')
        if google['server_metadata_url']!='https://accounts.google.com/.well-known/openid-configuration':
            raise ValueError('Invalid provider')
        if any(not isinstance(google[k],str) or not google[k].strip() for k in ('client_id','client_secret')):
            raise ValueError('Invalid client')
        return tuple(e.strip().casefold() for e in allowed)
    except (KeyError,TypeError,ValueError,AttributeError) as exc:
        raise ValueError('Team login configuration is incomplete') from exc


def bind_session(state,identity):
    """Discard drafts, uploads and cached results on a principal transition."""
    if identity is not None and not re.fullmatch(r'[a-f0-9]{64}',identity):
        raise ValueError('Invalid principal')
    if identity is None or state.get('_account_principal')!=identity:
        for key in list(state):del state[key]
    state['_account_principal']=identity


def account_root(root,identity):
    from pathlib import Path
    if not isinstance(identity,str) or not re.fullmatch(r'[a-f0-9]{64}',identity):
        raise ValueError('Invalid principal')
    root=Path(root)
    if root.is_symlink():raise ValueError('Account store cannot be a symlink')
    root.mkdir(parents=True,exist_ok=True,mode=0o700)
    child=root/identity
    if child.is_symlink():raise ValueError('Account store cannot be a symlink')
    child.mkdir(exist_ok=True,mode=0o700)
    if child.resolve().parent!=root.resolve():raise ValueError('Invalid account store')
    return child
