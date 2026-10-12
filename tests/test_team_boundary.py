import copy
from pathlib import Path
from unittest.mock import patch
import pytest
from cvevidence.web_access import deployment_policy,bind_session,account_root,principal


def config():
    return {'deployment':{'allowed_emails':['a@example.com']},'auth':{
        'redirect_uri':'https://intranet.example.com/oauth2callback','cookie_secret':'x'*32,
        'google':{'server_metadata_url':'https://accounts.google.com/.well-known/openid-configuration',
                  'client_id':'TEST_ONLY','client_secret':'TEST_ONLY'}}}


@pytest.mark.parametrize('path,value',[
    (('deployment','allowed_emails'),'a@example.com'),
    (('deployment','allowed_emails'),['']),
    (('deployment','allowed_emails'),[123]),
    (('auth','redirect_uri'),123),
    (('auth','redirect_uri'),'https://user:secret@example.com/oauth2callback'),
    (('auth','redirect_uri'),'https://example.com/oauth2callback?secret=hidden'),
    (('auth','cookie_secret'),123),
    (('auth','google','client_id'),False),
    (('auth','google'),[]),
])
def test_bad_configuration_is_a_fixed_error(path,value):
    settings=config();node=settings
    for key in path[:-1]:node=node[key]
    node[path[-1]]=value
    with pytest.raises(ValueError,match='^Team login configuration is incomplete$'):
        deployment_policy(settings)


def test_valid_config_and_principal_transition():
    assert deployment_policy(config())==('a@example.com',)
    a='a'*64;b='b'*64
    state={'draft':'PRIVATE','cached':object()}
    bind_session(state,a);assert state=={'_account_principal':a}
    state['draft']='preserved';bind_session(state,a);assert state['draft']=='preserved'
    bind_session(state,b);assert state=={'_account_principal':b}
    state['draft']='PRIVATE';bind_session(state,None);assert state=={'_account_principal':None}
    with pytest.raises(ValueError):principal({'is_logged_in':'true','email_verified':True,'sub':'one','email':'a@example.com'},['a@example.com'])


def test_account_roots_cannot_alias_another_account(tmp_path):
    first=account_root(tmp_path/'team','a'*64)
    (first/'private.txt').write_text('PRIVATE')
    second=account_root(tmp_path/'team','b'*64)
    assert not (second/'private.txt').exists()
    second.rmdir();second.symlink_to(first,target_is_directory=True)
    with pytest.raises(ValueError):account_root(tmp_path/'team','b'*64)
    with pytest.raises(ValueError):account_root(tmp_path/'team','../outside')
    assert (first/'private.txt').read_text()=='PRIVATE'


@pytest.mark.parametrize('user,configured',[(None,False),(None,True),({'is_logged_in':True,'email_verified':True,'email':'other@example.com','sub':'other'},True)])
def test_team_entry_does_not_open_workspace_before_authorization(tmp_path,user,configured):
    from streamlit.testing.v1 import AppTest
    import streamlit as st
    from types import SimpleNamespace
    from collections import UserDict
    class User(UserDict):
        @property
        def is_logged_in(self):return self.data.get('is_logged_in',False)
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'team_app.py'),default_timeout=15)
    settings=config() if configured else {'deployment':{'allowed_emails':123}}
    for key,value in settings.items():app.secrets[key]=value
    with patch.object(st,'user',User(user or {})),patch('cvevidence.workspace.workspace') as workspace:
        app.run()
    assert not app.exception
    workspace.assert_not_called()
    assert app.error if not configured or user else any(b.label=='使用 Google 登入' for b in app.button)


def test_authorized_entry_binds_workspace_to_subject(tmp_path,monkeypatch):
    from streamlit.testing.v1 import AppTest
    import streamlit as st
    from collections import UserDict
    class User(UserDict):
        @property
        def is_logged_in(self):return True
    user=User(is_logged_in=True,email_verified=True,email='a@example.com',sub='one')
    monkeypatch.setenv('CVEVIDENCE_WEB_STORE',str(tmp_path/'team'))
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'team_app.py'),default_timeout=15)
    for key,value in config().items():app.secrets[key]=value
    with patch.object(st,'user',user),patch('cvevidence.runtime_guard.current',return_value=True),patch('cvevidence.workspace.workspace') as workspace:
        app.run()
    assert not app.exception and not app.error
    workspace.assert_called_once()
    assert workspace.call_args.kwargs['store_root']==tmp_path/'team'/principal(user,['a@example.com'])
    assert app.session_state['_account_principal']==principal(user,['a@example.com'])
