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
    '''
    7.  Accessing Protected Resources

    After successfully receiving the Access Token and Token Secret, the
    Consumer is able to access the Protected Resources on behalf of the User.
    The request MUST be signed per Signing Requests, and contains the following
    parameters:

        oauth_consumer_key:
            The Consumer Key.
        oauth_token:
            The Access Token.
        oauth_signature_method:
            The signature method the Consumer used to sign the request.
        oauth_signature:
            The signature as defined in Signing Requests.
        oauth_timestamp:
            As defined in Nonce and Timestamp.
        oauth_nonce:
            As defined in Nonce and Timestamp.
        oauth_version:
            OPTIONAL. If present, value MUST be 1.0. Service Providers MUST
            assume the protocol version to be 1.0 if this parameter is not
            present.
            Service Providers' response to non-1.0 value is left undefined.
        Additional parameters:
            Any additional parameters, as defined by the Service Provider.
    '''
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
        namespace = self.NAMESPACE
        path_request = '/get_provider_time/'
        url = self.OAUTH_URL
        oauth_port = self.OAUTH_PORT
        try:
            oauth_token = self.session.get('OAUTH_ACCESS_TOKEN')[namespace]
        except:
            raise OauthAccessTokenNoValid
        parameters = {
                      'oauth_token': oauth_token,
                      'oauth_consumer_key': self.settings['OAUTH_CONSUMER_KEY'],
                      'oauth_signature_method': 'HMAC-SHA1',
                      'oauth_timestamp': int(time.time()),
                      'oauth_nonce': generate_nonce(length=8),
                      'oauth_version': '1.0'
                      }
        oauth_signature = sign_request('POST',
                                       parameters,
                                       self.OAUTH_CONSUMER_SECRET)
        parameters['oauth_signature'] = oauth_signature
        result, status = fetch_oauth(url,
                                     oauth_port,
                                     path_request,
                                     'POST',
                                     parameters)
        if status == 401:
            raise OauthAccessTokenNoValid
        elif status == 200:
            return result
        else:
            raise OauthError

    def get_tokens(self):
        namespace = self.NAMESPACE
        return HttpResponseRedirect(reverse('sgaoauth_%s_obtain_request_token' % namespace))

    '''
    Views
    '''
    def obtain_request_token(self, request, namespace):
        """
        6.1.1.  Consumer Obtains a Request Token
        To obtain a Request Token, the Consumer sends an HTTP request to the
        Service Provider's Request Token URL. The Service Provider documentation
        specifies the HTTP method for this request, and HTTP POST is RECOMMENDED.
        The request MUST be signed and contains the following parameters:

        Variables:
            oauth_consumer_key:
                The Consumer Key.
            oauth_signature_method:
                The signature method the Consumer used to sign the request.
            oauth_signature:
                The signature as defined in Signing Requests.
            oauth_timestamp:
                As defined in Nonce and Timestamp.
            oauth_nonce:
                As defined in Nonce and Timestamp.
            oauth_version:
                OPTIONAL. If present, value MUST be 1.0 . Service Providers MUST
                assume the protocol version to be 1.0 if this parameter is not
                present. Service Providers' response to non-1.0 value is left
                undefined.
            oauth_callback:
                An absolute URL to which the Service Provider will redirect the
                User back when the Obtaining User Authorization step is completed.
                If the Consumer is unable to receive callbacks or a callback URL
                has been established via other means, the parameter value MUST be
                set to oob (case sensitive), to indicate an out-of-band
                configuration.
            Additional parameters:
                Any additional parameters, as defined by the Service Provider

        Args:
            request:
        Returns:
            the result of directs_user_service_provider(oauth_token).
        Raises:
            TypeError: if n is not a number.
            ValueError: if n is negative.
        """
        url = self.OAUTH_URL
        path_request = self.OAUTH_REQUEST_TOKEN_PATH
        oauth_port = self.OAUTH_PORT

        #Variables
        oauth_consumer_key = self.OAUTH_CONSUMER_KEY
        oauth_signature_method = self.SIGNATURE_METHOD
        oauth_consumer_secret = self.OAUTH_CONSUMER_SECRET
        oauth_callback = self.OAUTH_CALLBACK_URL
        oauth_timestamp = int(time.time())
        oauth_nonce = generate_nonce(length=8)

        parameters = {
                      'oauth_consumer_key': oauth_consumer_key,
                      'oauth_signature_method': oauth_signature_method,
                      'oauth_consumer_secret': oauth_consumer_secret,
                      'oauth_timestamp': oauth_timestamp,
                      'oauth_nonce': oauth_nonce,
                      'oauth_callback': oauth_callback,
                      }

        oauth_signature = sign_request('POST',
                                       parameters,
                                       oauth_consumer_secret)
        parameters['oauth_signature'] = oauth_signature
        result, status = fetch_oauth(url,
                                     oauth_port,
                                     path_request,
                                     'POST',
                                     parameters)
        if status == 200:
            i = result.split('&')
            parameters = {a.split('=')[0].strip(): a.split('=')[1].strip() for a in i}
            oauth_token = parameters['oauth_token']
            return self.directs_user_service_provider(oauth_token, namespace)
        elif status == 401:
            return HttpResponse('Invalid Token', status=401)
        else:
            return HttpResponse('Unknown error', status=400)

    def directs_user_service_provider(self, oauth_token, namespace):
        '''
        6.2.1.  Consumer Directs the User to the Service Provider
        In order for the Consumer to be able to exchange the Request Token for an
        Access Token, the Consumer MUST obtain approval from the User by directing
        the User to the Service Provider. The Consumer constructs an HTTP GET
        request to the Service Provider's User Authorization URL with the following
        Once the request URL has been constructed the Consumer redirects the User
        to the URL via the User's web browser. If the Consumer is incapable of
        automatic HTTP redirection, the Consumer SHALL notify the User how to
        manually go to the constructed request URL.
        Note: If a Service Provider knows a Consumer to be running on a mobile
        device or set-top box, the Service Provider SHOULD ensure that the User
        Authorization URL and Request Token are suitable for manual entry.

        Args:
            oauth_token:
                OPTIONAL. The Request Token obtained in the previous step. The
                Service Provider MAY declare this parameter as REQUIRED, or accept
                requests to the User Authorization URL without it, in which case it
                will prompt the User to enter it manually.
            Additional parameters:
                Any additional parameters, as defined by the Service Provider. 
        Returns:
            HttpResponseRedirect to the authorization url.
        Raises:
            TypeError: if n is not a number.
            ValueError: if n is negative.
            parameter:

        '''
        namespace = self.NAMESPACE
        path_authorize = self.OAUTH_AUTHORIZATION_REQUEST_TOKEN_PATH
        url_server = self.OAUTH_URL
        port_server = self.OAUTH_PORT
        url = 'http://%s:%s%s' % (url_server, port_server, path_authorize)
        return HttpResponseRedirect(url % oauth_token)

    def callback(self, request, namespace):
        '''
        6.2.3.  Service Provider Directs the User Back to the Consumer
        After the User authenticates with the Service Provider and grants
        permission for Consumer access, the Consumer MUST be notified that the
        Request Token has been authorized and ready to be exchanged for an Access
        Token. If the User denies access, the Consumer MAY be notified that the
        Request Token has been revoked.
        To make sure that the User granting access is the same User returning back
        to the Consumer to complete the process, the Service Provider MUST generate
        a verification code: an unguessable value passed to the Consumer via the
        User and REQUIRED to complete the process.
        If the Consumer provided a callback URL (using the oauth_callback parameter
        in Section 6.1.1 or by other means), the Service Provider uses it to
        constructs an HTTP request, and directs the User's web browser to that URL
        with the following parameters added:

            oauth_token:
                The Request Token the User authorized or denied.
            oauth_verifier:
                The verification code.

        The callback URL MAY include Consumer provided query parameters. The
        Service Provider MUST retain them unmodified and append the OAuth
        parameters to the existing query.

        If the Consumer did not provide a callback URL, the Service Provider
        SHOULD display the value of the verification code, and instruct the User
        to manually inform the Consumer that authorization is completed. If the
        Service Provider knows a Consumer to be running on a mobile device or
        set-top box, the Service Provider SHOULD ensure that the verifier value
        is suitable for manual entry.
        '''
        namespace = self.NAMESPACE
        #Variables
        oauth_verifier = request.GET.get('oauth_verifier')
        oauth_token = request.GET.get('oauth_token')
        oauth_consumer_key = self.OAUTH_CONSUMER_KEY
        oauth_signature_method = self.SIGNATURE_METHOD
        oauth_consumer_secret = self.OAUTH_CONSUMER_SECRET
        oauth_nonce = generate_nonce(length=8)
        oauth_timestamp = int(time.time())
        parameters = {
                        'oauth_token': oauth_token,
                        'oauth_consumer_key': oauth_consumer_key, 
                        'oauth_signature_method': oauth_signature_method,
                        'oauth_timestamp': oauth_timestamp,
                        'oauth_nonce': oauth_nonce,
                        'oauth_verifier': oauth_verifier,
                      }
        oauth_signature = sign_request('POST',
                                       parameters,
                                       oauth_consumer_secret)
        parameters['oauth_signature'] = oauth_signature
        #Delete Session
        oauth_port = self.OAUTH_PORT
        url = self.OAUTH_URL
        path_request = self.OAUTH_ACCESS_TOKEN_PATH
        return self.obtain_access_token(url,
                                        oauth_port,
                                        path_request,
                                        parameters,
                                        request,
                                        namespace)

    def obtain_access_token(self,
                            url,
                            oauth_port,
                            path_request,
                            parameters,
                            request,
                            namespace):
        '''
        6.3.1.  Consumer Requests an Access Token
        The Request Token and Token Secret MUST be exchanged for an Access Token
        and Token Secret.
        To request an Access Token, the Consumer makes an HTTP request to the
        Service Provider's Access Token URL. The Service Provider documentation
        specifies the HTTP method for this request, and HTTP POST is RECOMMENDED.
        The request MUST be signed per Signing Requests, and contains the
        following parameters:

        oauth_consumer_key:
            The Consumer Key.
        oauth_token:
            The Request Token obtained previously.
        oauth_signature_method:
            The signature method the Consumer used to sign the request.
        oauth_signature:
            The signature as defined in Signing Requests.
        oauth_timestamp:
            As defined in Nonce and Timestamp.
        oauth_nonce:
            As defined in Nonce and Timestamp.
        oauth_version:
            OPTIONAL. If present, value MUST be 1.0 . Service Providers MUST
            assume the protocol version to be 1.0 if this parameter is not present.
            Service Providers' response to non-1.0 value is left undefined.
        oauth_verifier:
            The verification code received from the Service Provider in the
            Service Provider Directs the User Back to the Consumer step.

        No additional Service Provider specific parameters are allowed when
        requesting an Access Token to ensure all Token related information is
        present prior to seeking User approval.
        '''
        result, status = fetch_oauth(url, oauth_port, path_request, 'POST', parameters)
        if status == 200:
            i = result.split('&')
            parameters = {a.split('=')[0].strip(): a.split('=')[1].strip() for a in i}
            if 'OAUTH_ACCESS_TOKEN' not in request.session:
                request.session['OAUTH_ACCESS_TOKEN'] = {}
            request.session['OAUTH_ACCESS_TOKEN'][namespace] = parameters['oauth_token']
            return HttpResponseRedirect('/') #TODO: Return to initial request
        elif status == 401:
            return HttpResponse('Invalid Token', status=401)
        else:
            return HttpResponse(result, status=401)

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
