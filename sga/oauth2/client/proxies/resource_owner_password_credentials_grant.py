from django.conf import settings
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponse
from functools import update_wrapper
from sga_oauth.client import oauth_settings
from sga_oauth.shared.exceptions import OauthAccessTokenNoValid, OauthError
from sga_oauth.shared.helpers.generators import generate_nonce
from sga_oauth.shared.helpers.request import fetch_oauth
from sga_oauth.shared.helpers.signature import sign_request
from django.conf.urls import patterns, url, include
import time


class OauthClient():

    def __init__(self, settings, session):
        '''
        Settings
        '''
        self.name = 'test'
        self.app_name = 'test'
        AVALAIBLE_SIGNATURES = {
                        'HMAC-SHA1': 'HMAC-SHA1',
                        'RSA-SHA1': 'RSA-SHA1',
                        'PLAINTEXT': 'PLAINTEXT'
                      }
        self.NAMESPACE = 'test'
        self.OAUTH_URL = '127.0.0.1'
        self.OAUTH_REQUEST_TOKEN_PATH = '/oauthserver/request'
        self.OAUTH_AUTHORIZATION_REQUEST_TOKEN_PATH = '/oauthserver/authorization?oauth_token=%s'
        self.OAUTH_ACCESS_TOKEN_PATH = '/oauthserver/access'
        self.OAUTH_PORT = '8001'
        self.OAUTH_CONSUMER_KEY = ''
        self.OAUTH_CONSUMER_SECRET = ''
        self.OAUTH_CALLBACK_URL = 'http://127.0.0.1:8000/oauthclient/callback/test/?oauth_token=%s&oauth_verifier=%s'
        self.SIGNATURE_METHOD = AVALAIBLE_SIGNATURES['HMAC-SHA1']

    def get_provider_time(self, method_name, parameters=None):


    def authorization_request_and_response(self):
        '''
        4.3.1. Authorization Request and Response

        The method through which the client obtains the resource owner
        credentials is beyond the scope of this specification.  The client
        MUST discard the credentials once an access token has been obtained.
        '''
        

    def access_token_request(self):
        '''
        4.3.2. Access Token Request
        
        
           The client makes a request to the token endpoint by adding the
           following parameters using the "application/x-www-form-urlencoded"
           format per Appendix B with a character encoding of UTF-8 in the HTTP
           request entity-body:
        
           grant_type
                 REQUIRED.  Value MUST be set to "password".
        
           username
                 REQUIRED.  The resource owner username.
        
           password
                 REQUIRED.  The resource owner password.
        
           scope
                 OPTIONAL.  The scope of the access request as described by
                 Section 3.3.
        
           If the client type is confidential or the client was issued client
           credentials (or assigned other authentication requirements), the
           client MUST authenticate with the authorization server as described
           in Section 3.2.1.
        
           For example, the client makes the following HTTP request using
           transport-layer security (with extra line breaks for display purposes
           only):
        
             POST /token HTTP/1.1
             Host: server.example.com
             Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
             Content-Type: application/x-www-form-urlencoded
        
             grant_type=password&username=johndoe&password=A3ddj3w
        
           The authorization server MUST:
        
           o  require client authentication for confidential clients or for any
              client that was issued client credentials (or with other
              authentication requirements),
        
           o  authenticate the client if client authentication is included, and
        
           o  validate the resource owner password credentials using its
              existing password validation algorithm.
        
           Since this access token request utilizes the resource owner's
           password, the authorization server MUST protect the endpoint against
           brute force attacks (e.g., using rate-limitation or generating
           alerts).
        '''


    def access_token_response(self, request, namespace):
        '''
        HTTP/1.1 200 OK
        Content-Type: application/json;charset=UTF-8
        Cache-Control: no-store
        Pragma: no-cache
        
        {
        "access_token":"2YotnFZFEjr1zCsicMWpAA",
        "token_type":"example",
        "expires_in":3600,
        "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
        "example_parameter":"example_value"
        }
        '''


    '''
    Urls
    '''
    def get_urls(self):
        namespace = self.NAMESPACE
        urlpatterns = patterns('',
           url(r'^obtain_request_token/%s/' % namespace,
               self.obtain_request_token,
               name='sgaoauth_%s_obtain_request_token' % namespace,),
           url(r'^callback/%s/' % namespace,
               self.callback,
               name='sgaoauth_%s_oauth_callback' % namespace,),
        )
        return urlpatterns

    @property
    def urls(self):
        return self.get_urls(), self.app_name, self.name
