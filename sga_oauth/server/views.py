from datetime import datetime
from django.conf import settings
from django.contrib import auth
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.template.context import RequestContext
from django.template.loader import get_template
from django.views.decorators.csrf import csrf_exempt
from sga_oauth.server import oauth_settings
from sga_oauth.shared.helpers.encode import url_with_querystring
from sga_oauth.shared.helpers.generators import generate_verifier
from sga_oauth.shared.helpers.validators import check_signature, check_timestamp
from sga_oauth.shared.persistence.models import ConsumerToken, Nonce, \
    RequestToken, AccessToken
from sga_oauth.shared.reposes import HttpMissingRequiredParameter, \
    HttpInvalidConsumerKey, HttpInvalidSignature, HttpInvalidExpiredToken, \
    HttpInvalidUsedNonce
from urllib import urlencode, unquote


@csrf_exempt
def grant_request_token(request):
    '''
    6.1.2.  Service Provider Issues an Unauthorized Request Token

    The Service Provider verifies the signature and Consumer Key. If
    successful, it generates a Request Token and Token Secret and returns them
    to the Consumer in the HTTP response body as defined in Service Provider
    Response Parameters.
    The Service Provider MUST ensure the Request Token cannot be exchanged for
    an Access Token until the User successfully grants access in Obtaining User
    Authorization.
    The response contains the following parameters:

        oauth_token:
            The Request Token.
        oauth_token_secret:
            The Token Secret.
        oauth_callback_confirmed:
            MUST be present and set to true. The Consumer MAY use this to
            confirm that the Service Provider received the callback value.
        Additional parameters:
            Any additional parameters, as defined by the Service Provider.

    If the request fails verification or is rejected for other reasons, the
    Service Provider SHOULD respond with the appropriate response code as
    defined in HTTP Response Codes. The Service Provider MAY include some
    further details about why the request was rejected in the HTTP response
    body as defined in Service Provider Response Parameters.
    '''
    http_authorization = request.META.get('HTTP_AUTHORIZATION').replace('OAuth', '')
    i = http_authorization.split(',')
    parameters = {unquote(http_authorization.split('=')[0]).strip():
                  unquote(http_authorization.split('=')[1]).strip() 
                  for http_authorization in i}
    try:
        oauth_consumer_key = parameters['oauth_consumer_key']
        oauth_timestamp = parameters['oauth_timestamp']
        oauth_signature = parameters['oauth_signature']
        oauth_nonce = parameters['oauth_nonce']
        oauth_callback = parameters['oauth_callback']
    except Exception, e:
        return HttpMissingRequiredParameter()

    try:
        consumer = ConsumerToken.objects.get(oauth_key=oauth_consumer_key)
    except Exception, e:
        return HttpInvalidConsumerKey()

    if not check_signature(oauth_signature,
                          request.method,
                          request,
                          parameters,
                          consumer.oauth_secret):
        return HttpInvalidSignature()

    if not check_timestamp(oauth_timestamp):
        return HttpInvalidExpiredToken()
    if Nonce.objects.filter(nounce_key=oauth_nonce):
        return HttpInvalidUsedNonce()
    else:
        nonce = Nonce()
        nonce.nonce_key = oauth_nonce
        nonce.save()
    #Create Token
    oauth_timestamp = datetime.fromtimestamp(int(parameters['oauth_timestamp']))
    request_token = RequestToken()
    request_token.consumer = consumer
    request_token.timastamp_created = oauth_timestamp
    request_token.generate_tokens()
    request_token.callback = oauth_callback
    request_token.save()

    result = urlencode({
        'oauth_token': request_token.oauth_key,
        'oauth_token_secret': request_token.oauth_secret,
        'oauth_callback_confirmed': 'true'
    })
    return HttpResponse(result, content_type='application/x-www-form-urlencoded')


@csrf_exempt
@login_required
def grant_user_authorization(request):
    '''
    6.2.2.  Service Provider Authenticates the User and Obtains Consent
    The Service Provider verifies the User's identity and asks for consent as
    detailed. OAuth does not specify how the Service Provider authenticates the
    User.
    However, it does define a set of REQUIRED steps:

        The Service Provider MUST first verify the User's identity before
        asking for consent.
        It MAY prompt the User to sign in if the User has not already done so.
        The Service Provider presents to the User information about the
        Consumer requesting access (as registered by the Consumer Developer).
        The information includes the duration of the access and the Protected
        Resources provided.
        The information MAY include other details specific to the Service
        Provider.
        The User MUST grant or deny permission for the Service Provider to give
        the Consumer access to the Protected Resources on behalf of the User.
        If the User denies the Consumer access, the Service Provider MUST NOT
        allow access to the Protected Resources.

    When displaying any identifying information about the Consumer to the User
    based on the Consumer Key, the Service Provider MUST inform the User if it
    is unable to assure the Consumer's true identity. The method in which the
    Service Provider informs the User and the quality of the identity assurance
    is beyond the scope of this specification.
    '''
    oauth_token = request.GET.get('oauth_token', None)
    try:
        request_token = RequestToken.objects.get(oauth_key=oauth_token)
    except:
        return HttpInvalidExpiredToken()
    callback = request_token.callback

    request_token.is_approved = True
    request_token.user = request.user
    request_token.verifier = generate_verifier()
    request_token.save()
    callback = callback % (request_token.oauth_key, request_token.verifier)
    return HttpResponseRedirect(callback)


@csrf_exempt
def grant_access_token(request):
    '''
    6.3.2.  Service Provider Grants an Access Token
    The Service Provider MUST ensure that:

        The request signature has been successfully verified.
        The Request Token has never been exchanged for an Access Token.
        The Request Token matches the Consumer Key.
        The verification code received from the Consumer has been
        successfully verified.

    If successful, the Service Provider generates an Access Token and Token
    Secret and returns them in the HTTP response body as defined in Service
    Provider Response Parameters. The Access Token and Token Secret are stored
    by the Consumer and used when signing Protected Resources requests.
    The response contains the following parameters:

        oauth_token:
            The Access Token.
        oauth_token_secret:
            The Token Secret.
        Additional parameters:
            Any additional parameters, as defined by the Service Provider.

    If the request fails verification or is rejected for other reasons, the
    Service Provider SHOULD respond with the appropriate response code as
    defined in HTTP Response Codes. The Service Provider MAY include some
    further details about why the request was rejected in the HTTP response
    body as defined in Service Provider Response Parameters.
    '''
    http_authorization = request.META.get('HTTP_AUTHORIZATION').replace('OAuth', '')
    i = http_authorization.split(',')
    parameters = {unquote(http_authorization.split('=')[0]).strip():
                  unquote(http_authorization.split('=')[1]).strip()
                  for http_authorization in i}

    try:
        oauth_token = parameters['oauth_token']
        oauth_timestamp = parameters['oauth_timestamp']
        oauth_signature = parameters['oauth_signature']
        oauth_nonce = parameters['oauth_nonce']
    except:
        return HttpMissingRequiredParameter()

    try:
        request_token = RequestToken.objects.get(oauth_key=oauth_token)
        consumer = request_token.consumer
    except Exception, e:
        return HttpInvalidExpiredToken()

    if not check_signature(oauth_signature,
                          request.method,
                          request,
                          parameters,
                          consumer.oauth_secret):
        return HttpInvalidSignature()

    if not check_timestamp(oauth_timestamp):
        return HttpInvalidExpiredToken()

    if Nonce.objects.filter(nounce_key=oauth_nonce):
        return HttpInvalidUsedNonce()
    else:
        nonce = Nonce()
        nonce.nonce_key = oauth_nonce
        nonce.save()

    if parameters['oauth_verifier'] != request_token.verifier:
        raise Exception("Bad Verifier")

    if not request_token.is_approved:
        return HttpInvalidExpiredToken()

    access_token = AccessToken()
    access_token.consumer = request_token.consumer
    access_token.generate_tokens()
    access_token.save()
    request_token.delete()

    result = urlencode({
        'oauth_token': access_token.oauth_key,
        'oauth_token_secret': access_token.oauth_secret
    })
    return HttpResponse(result, content_type='application/x-www-form-urlencoded')
