from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from sga_oauth.shared.exceptions import OauthAccessTokenNoValid, OauthError
from sga_oauth.shared.helpers.generators import generate_nonce
from sga_oauth.shared.helpers.request import fetch_oauth
from sga_oauth.shared.helpers.signature import sign_request
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
        self.settings = settings
        self.session = session

    def method(self, method_name, parameters=None):
        url = self.settings['OAUTH_URL']
        path_request = self.settings['METHODS'][method_name]
        oauth_port = self.settings['OAUTH_PORT']
        namespace = self.settings['NAMESPACE']
        try:
            oauth_token = self.session.get('OAUTH_ACCESS_TOKEN')[namespace]
        except Exception, e:
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
                                       self.settings['OAUTH_CONSUMER_SECRET'])

        parameters['oauth_signature'] = oauth_signature
        result, status = fetch_oauth(url, oauth_port, path_request, 'POST', parameters)
        if status == 401:
            raise OauthAccessTokenNoValid
        elif status == 200:
            return result
        else:
            raise OauthError

    def get_tokens(self):
        return HttpResponseRedirect(reverse('sga_oauth_obtain_request_token',
                                    kwargs={
                                            'namespace': self.settings['NAMESPACE'],
                                            }))
