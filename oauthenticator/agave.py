"""
Custom Authenticator to use Agave OAuth with JupyterHub
"""

import grp
import json
import os
import pwd
import sys
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

        self.ensure_token_dir(username)
        self.ensure_data_dir(username)
        self.save_token(access_token, refresh_token, username, created_at, expires_in, expires_at)
        return username

    def ensure_token_dir(self, username):
        tenant_id = os.environ.get('AGAVE_TENANT_ID')
        try:
            os.makedirs(os.path.join('/tokens', tenant_id, username))
        except OSError as e:
            self.log.info("Got error trying to make token dir: {}".format(e))

    def ensure_data_dir(self, username):
        tenant_id = os.environ.get('AGAVE_TENANT_ID')
        data_dir = os.environ.get('AGAVE_USER_DATA_DIR_BASE_PATH')
        if data_dir:
            # this is a hack for the public tenant.
            data_dir = os.path.join(data_dir, username)
            # run the homegen container to create the user dir using the nfs user account. this will break if other tenants use the AGAVE_USER_DATA_DIR env.
            import docker
            cli = docker.AutoVersionClient('unix://var/run/docker.sock')
            volumes = ['/corral-repl']
            binds = {'/corral-repl': {'bind': '/corral-repl', 'ro': False}}
            host_config = cli.create_host_config(binds=binds)
            container = cli.create_container(image='agaveapi/homegen',
                                             volumes=volumes,
                                             host_config=host_config,
                                             command='mkdir -p {}'.format(data_dir))
            cli.start(container=container.get('Id'))
        else:
            data_dir = os.path.join('/home/apim/jupyterhub_userdata', tenant_id, username)
            try:
                os.makedirs(data_dir)
            except FileExistsError as e:
                self.log.info("Got FileExists error trying to make user's data dir: {}".format(e))
                pass
            try:
                uid, gid = self.get_uid_gid()
                os.chown(data_dir, uid, gid)
                self.log.info('set ownership permissions for: {} to uid: {} and gid: {}'.format(data_dir, uid, gid))
            except OSError as e:
                self.log.info("OSError setting permissions on userdata dirs: {}".format(e))
            except PermissionError as e:
                self.log.info("PermissionError setting permissions on userdata dirs: {}".format(e))

    def get_uid_gid(self):
        """look up uid and gid of apim home dir. If this path doesn't exist, stat_info will contain the root user and group
        (that is, uid = 0 = gid)."""
        # first, see if they are defined in the environment
        uid = os.environ.get('jupyteruser_uid')
        gid = os.environ.get('jupyteruser_gid')
        if uid and gid:
            self.log.info('Tenant set custom UID and GID for jupyteruser. UID: {} GID: {}'.format(uid, gid))
            try:
                uid = int(uid)
                gid = int(gid)
                self.log.info('Cast to int and returning UID: {}, GID:{}'.format(uid, gid))
                return uid, gid
            except Exception as e:
                self.log.info("Got exception {} casting to int".format(e))
        # otherwise, try to derive them from existing file ownerships
        stat_info = os.stat('/home/apim/jupyterhub_config.py')
        uid = stat_info.st_uid
        gid = stat_info.st_gid
        self.log.info("Used the /home/apim/jupyterhub_config.py file to determine UID: {}, GID:{}".format(uid, gid))
        return uid, gid

    def save_token(self, access_token, refresh_token, username, created_at, expires_in, expires_at):
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
        self.log.info("Saved agavepy cache file to {}".format(os.path.join('/tokens', tenant_id, username, '.agpy')))
        self.log.info("agavepy cache file data: {}".format(d))
        # cli file
        d = {'tenantid': tenant_id,
             'baseurl': 'https://{}'.format(os.environ.get('AGAVE_BASE_URL')),
             'devurl': '',
             'apikey': os.environ.get('AGAVE_CLIENT_ID'),
             'username': username,
             'access_token': access_token,
             'refresh_token': refresh_token,
             'created_at': str(int(created_at)),
             'apisecret': os.environ.get('AGAVE_CLIENT_SECRET'),
             'expires_in': str(expires_in),
             'expires_at': str(expires_at)
             }
        with open(os.path.join('/tokens', tenant_id, username, 'current'), 'w') as f:
            json.dump(d, f)
        self.log.info("Saved CLI cache file to {}".format(os.path.join('/tokens', tenant_id, username, 'current')))
        self.log.info("CLI cache file data: {}".format(d))
        # try to set the ownership of the cache files to the apim user and an appropriate group. We need to ignore
        # permission errors for portability.
        try:
            uid, gid = self.get_uid_gid()
            os.chown(os.path.join('/tokens', tenant_id, username, '.agpy'), uid, gid)
            os.chown(os.path.join('/tokens', tenant_id, username, 'current'), uid, gid)
        # if we get a permission error, ignore it because we may be in a different enviornment without an apim user and
        # thus trying to set ownership to root.
        except OSError as e:
            self.log.info("OSError setting permissions on cache files: {}".format(e))
        except PermissionError as e:
            self.log.info("PermissionError setting permissions on cache files: {}".format(e))

class LocalAgaveOAuthenticator(LocalAuthenticator,
                                   AgaveOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
