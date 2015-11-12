"""
Custom Authenticator to use Agave OAuth with JupyterHub
"""


import json
import urllib

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Set

from .oauth2 import OAuthLoginHandler, OAuthenticator

class AgaveMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://{}/oauth2/authorize".format(AgaveOAuthenticator.agave_base_url)
    _OAUTH_ACCESS_TOKEN_URL = "https://{}/token".format(AgaveOAuthenticator.agave_base_url)


class AgaveLoginHandler(OAuthLoginHandler, AgaveMixin):
    pass


class AgaveOAuthenticator(OAuthenticator):

    login_service = "Agave {} teant".format(self.agave_tenant_name)
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
            callbackUrl=self.oauth_callback_url
        )

        url = url_concat(
            "https://{}/token".format(self.agave_base_url), params)
        self.log.info(url)

        bb_header = {"Content-Type":
                     "application/x-www-form-urlencoded;charset=utf-8"}
        req = HTTPRequest(url,
                          method="POST",
                          auth_username=self.client_id,
                          auth_password=self.client_secret,
                          body=urllib.parse.urlencode(params).encode('utf-8'),
                          headers=bb_header
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "Bearer {}".format(access_token)
                   }
        req = HTTPRequest("https://{}/profiles/v2/me".format(AGAVE_BASE_URL),
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = resp_json["result"]["username"]
        return username


class LocalAgaveOAuthenticator(LocalAuthenticator,
                                   AgaveOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
