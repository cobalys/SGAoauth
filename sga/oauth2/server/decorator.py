from sga_oauth.shared.helpers.validators import check_signature, check_timestamp
from sga_oauth.shared.persistence.models import AccessToken, Nonce,\
    ConsumerToken
from sga_oauth.shared.reposes import HttpInvalidSignature, \
    HttpInvalidExpiredToken, HttpInvalidUsedNonce
from urllib import unquote


try:
    from urllib.parse import urlparse
except ImportError: # Python 2
    from urlparse import urlparse


def oauth_service(function):

    def wrap(request, *args, **kwargs):
        a = request.META.get('HTTP_AUTHORIZATION').replace('OAuth', '')
        i = a.split(',')
        parameters = {unquote(a.split('=')[0]).strip():
                      unquote(a.split('=')[1]).strip() for a in i}
        oauth_consumer_key = parameters['oauth_consumer_key']
        oauth_access_key = parameters['oauth_token']

        try:
            consumer_token = ConsumerToken.objects.get(oauth_key=oauth_consumer_key)
            access_token = AccessToken.objects.get(oauth_key=oauth_access_key,
                                                   consumer=consumer_token)
        except Exception, e:
            return HttpInvalidExpiredToken()

        
        
        oauth_timestamp = parameters['oauth_timestamp']
        
        if not check_signature(parameters['oauth_signature'],
                              request.method,
                              request,
                              parameters,
                              consumer_token.oauth_secret):
            return HttpInvalidSignature()
        
        oauth_nonce = parameters['oauth_nonce']
        
        if not check_timestamp(oauth_timestamp):
            return HttpInvalidExpiredToken()
        
        if Nonce.objects.filter(nounce_key=oauth_nonce):
            return HttpInvalidUsedNonce()
        else:
            nonce = Nonce()
            nonce.nonce_key = oauth_nonce
            nonce.save()

        return function(request, *args, **kwargs)

    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap

