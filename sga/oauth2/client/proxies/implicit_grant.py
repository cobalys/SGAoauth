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


    def get_tokens(self):
        namespace = self.NAMESPACE
        return HttpResponseRedirect(reverse('sgaoauth_%s_obtain_request_token' % namespace))

    '''
    Views
    '''
    def authorization_request(self, request, namespace):
        '''
        4.2.1. Authorization Request

        The client constructs the request URI by adding the following
        parameters to the query component of the authorization endpoint URI
        using the "application/x-www-form-urlencoded" format, per Appendix B:

         response_type
              REQUIRED.  Value MUST be set to "token".

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

         GET /authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz
             &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
         Host: server.example.com

        The authorization server validates the request to ensure that all
        required parameters are present and valid.  The authorization server
        MUST verify that the redirection URI to which it will redirect the
        access token matches a redirection URI registered by the client as
        described in Section 3.1.2.

        If the request is valid, the authorization server authenticates the
        resource owner and obtains an authorization decision (by asking the
        resource owner or by establishing approval via other means).

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


    def access_token_response(self, request, namespace):
        '''

     HTTP/1.1 302 Found
     Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
               &state=xyz&token_type=example&expires_in=3600
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
