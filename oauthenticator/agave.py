"""
Custom Authenticator to use Agave OAuth with JupyterHub
"""


import json
import os
import urllib
import time

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Set

from .oauth2 import OAuthLoginHandler, OAuthenticator

class AgaveMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://{}/oauth2/authorize".format(os.environ.get('AGAVE_BASE_URL'))
    _OAUTH_ACCESS_TOKEN_URL = "https://{}/token".format(os.environ.get('AGAVE_BASE_URL'))


class AgaveLoginHandler(OAuthLoginHandler, AgaveMixin):
    pass


class AgaveOAuthenticator(OAuthenticator):

    login_service = os.environ.get('AGAVE_LOGIN_BUTTON_TEXT')
    # login_service = "Agave {} tenant".format(os.environ.get('AGAVE_TENANT_NAME'))
    client_id_env = 'AGAVE_CLIENT_ID'
    client_secret_env = 'AGAVE_CLIENT_SECRET'
    login_handler = AgaveLoginHandler

    team_whitelist = Set(
        config=True,
        help="Automatically whitelist members of selected teams",
    )

    @gen.coroutine
    def authenticate(self, handler):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            grant_type="authorization_code",
            code=code,
            redirect_uri=self.oauth_callback_url,
            client_id=self.client_id,
            client_secret=self.client_secret
        )

        url = url_concat(
            "https://{}/oauth2/token".format(os.environ.get('AGAVE_BASE_URL')), params)
        self.log.info(url)

        bb_header = {"Content-Type":
                     "application/x-www-form-urlencoded;charset=utf-8"}
        req = HTTPRequest(url,
                          method="POST",
                          validate_cert=eval(os.environ.get('OAUTH_VALIDATE_CERT', 'True')),
#                          auth_username=self.client_id,
#                          auth_password=self.client_secret,
                          body=urllib.parse.urlencode(params).encode('utf-8'),
                          headers=bb_header
                          )

        resp = yield http_client.fetch(req, validate_cert=eval(os.environ.get('OAUTH_VALIDATE_CERT', 'True')))
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        refresh_token = resp_json['refresh_token']
        expires_in = resp_json['expires_in']
        try:
            expires_in = int(expires_in)
        except ValueError:
            expires_in = 3600
        created_at = time.time()
        expires_at = time.ctime(created_at + expires_in)
        self.log.info(str(resp_json)) 
        
        # Determine who the logged in user is
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(access_token)
                   }
        req = HTTPRequest("https://{}/profiles/v2/me".format(os.environ.get('AGAVE_BASE_URL')),
                          validate_cert=eval(os.environ.get('OAUTH_VALIDATE_CERT', 'True')),
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req, validate_cert=eval(os.environ.get('OAUTH_VALIDATE_CERT', 'True')))
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = resp_json["result"]["username"]

        ensure_token_dir(username)
        save_token(access_token, refresh_token, username, created_at, expires_in, expires_at)
        return username


def ensure_token_dir(username):
    tenant_id = os.environ.get('AGAVE_TENANT_ID')
    try:
        os.makedirs(os.path.join('/tokens', tenant_id, username))
    except OSError:
        pass


def save_token(access_token, refresh_token, username, created_at, expires_in, expires_at):
    tenant_id = os.environ.get('AGAVE_TENANT_ID')
    # agavepy file
    d = [{'token': access_token,
         'refresh_token': refresh_token,
         'tenant_id': tenant_id,
         'api_key': os.environ.get('AGAVE_CLIENT_ID'),
         'api_secret': os.environ.get('AGAVE_CLIENT_SECRET'),
         'api_server': 'https://{}'.format(os.environ.get('AGAVE_BASE_URL')),
         'verify': eval(os.environ.get('OAUTH_VALIDATE_CERT', 'True')),
         }]
    with open(os.path.join('/tokens', tenant_id, username, '.agpy'), 'w') as f:
        json.dump(d, f)
    # cli file
    d = {'tenant_id': tenant_id,
         'baseurl': 'https://{}'.format(os.environ.get('AGAVE_BASE_URL')),
         'devurl': '',
         'apikey': os.environ.get('AGAVE_CLIENT_ID'),
         'username': username,
         'access_token': access_token,
         'refresh_token': refresh_token,
         'created_at': created_at,
         'expires_in': expires_in,
         'expires_at': expires_at
         }
    with open(os.path.join('/tokens', tenant_id, username, 'current'), 'w') as f:
        json.dump(d, f)


class LocalAgaveOAuthenticator(LocalAuthenticator,
                                   AgaveOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
