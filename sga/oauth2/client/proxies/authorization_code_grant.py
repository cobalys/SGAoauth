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


service = OAuth2Service(
           name='example',
           consumer_key='123',
           consumer_secret='456',
           access_token_url='http://example.com/token',
           authorize_url='http://example.com/authorize')


class OauthAutorizationCodeClient():

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


    def get_tokens(self):
        namespace = self.NAMESPACE
        return HttpResponseRedirect(reverse('sgaoauth_%s_obtain_request_token' % namespace))

    '''
    Views
    '''
    def authorization_request(self, request, namespace):
        '''
        4.1.1. Authorization Request

        The client constructs the request URI by adding the following
        parameters to the query component of the authorization endpoint URI
        using the "application/x-www-form-urlencoded" format, per Appendix B:

        response_type
             REQUIRED.  Value MUST be set to "code".

        client_id
             REQUIRED.  The client identifier as described in Section 2.2.

        redirect_uri
             OPTIONAL.  As described in Section 3.1.2.
        scope
             OPTIONAL.  The scope of the access request as described by
             Section 3.3.

        state
             RECOMMENDED.  An opaque value used by the client to maintain
             state between the request and callback.  The authorization
             server includes this value when redirecting the user-agent back
             to the client.  The parameter SHOULD be used for preventing
             cross-site request forgery as described in Section 10.12.

        The client directs the resource owner to the constructed URI using an
        HTTP redirection response, or by other means available to it via the
        user-agent.

        For example, the client directs the user-agent to make the following
        HTTP request using TLS (with extra line breaks for display purposes
        only):

        GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
            &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
        Host: server.example.com

        The authorization server validates the request to ensure that all
        required parameters are present and valid.  If the request is valid,
        the authorization server authenticates the resource owner and obtains
        an authorization decision (by asking the resource owner or by
        establishing approval via other means).

        When a decision is established, the authorization server directs the
        user-agent to the provided client redirection URI using an HTTP
        redirection response, or by other means available to it via the
        user-agent.
        '''
        parameters = urllib.urlencode({
                    'response_type': 'code',
                    'client_id': ,
                    'redirect_uri': ,
                    'scope': ,
                    'state':
                      })
        return HttpResponseRedirect()



    def request_access_token(self, request, namespace):
        '''
        4.1.3. Access Token Request

        The client makes a request to the token endpoint by sending the
        following parameters using the "application/x-www-form-urlencoded"
        format per Appendix B with a character encoding of UTF-8 in the HTTP
        request entity-body:

        grant_type
              REQUIRED.  Value MUST be set to "authorization_code".

        code
              REQUIRED.  The authorization code received from the
              authorization server.

        redirect_uri
              REQUIRED, if the "redirect_uri" parameter was included in the
              authorization request as described in Section 4.1.1, and their
              values MUST be identical.

        client_id
              REQUIRED, if the client is not authenticating with the
              authorization server as described in Section 3.2.1.

        If the client type is confidential or the client was issued client
        credentials (or assigned other authentication requirements), the
        client MUST authenticate with the authorization server as described
        in Section 3.2.1.

        For example, the client makes the following HTTP request using TLS
        (with extra line breaks for display purposes only):

          POST /token HTTP/1.1
          Host: server.example.com
          Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
          Content-Type: application/x-www-form-urlencoded

          grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
          &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb

        The authorization server MUST:

        o  require client authentication for confidential clients or for any
           client that was issued client credentials (or with other
           authentication requirements),

        o  authenticate the client if client authentication is included,

        o  ensure that the authorization code was issued to the authenticated
           confidential client, or if the client is public, ensure that the
           code was issued to "client_id" in the request,

        o  verify that the authorization code is valid, and

        o  ensure that the "redirect_uri" parameter is present if the
           "redirect_uri" parameter was included in the initial authorization
           request as described in Section 4.1.1, and if included ensure that
           their values are identical.
        '''
        parameters = urllib.urlencode({
                    'response_type': 'code',
                    'client_id': ,
                    'redirect_uri': ,
                    'scope': ,
                    'state':
                      })
        return HttpResponseRedirect()




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
