from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from sga.oauth1.shared.helpers.codecs import encode_parameter, decode_parameter, \
    decode_request_query
from sga_oauth.shared.helpers.encode import encode_oauth
from urlparse import urlparse
import binascii
import hmac
import urllib
try:
    from hashlib import sha1
    sha = sha1
except ImportError:
    import sha


def sign_hmac_sha1(signature_base_string,
                   oauth_consumer_secret,
                   token_shared_secret=''):
    key = '&'.join((
                   encode_parameter(oauth_consumer_secret),
                   encode_parameter(token_shared_secret)
                   ))
    text = signature_base_string
    digest = hmac.new(key, text, sha).digest()
    return binascii.b2a_base64(digest)[:-1]


def sign_rsa_sha1(signature_base_string, rsa_privatekey):
    key = RSA.importKey(rsa_privatekey)
    h = SHA.new(signature_base_string)
    p = PKCS1_v1_5.new(key)
    return binascii.b2a_base64(p.sign(h))[:-1]


def verify_rsa_sha1(signature_base_string, rsa_publickey, signature):
    key = RSA.importKey(rsa_publickey)
    h = SHA.new(signature_base_string)
    p = PKCS1_v1_5.new(key)
    signature = binascii.a2b_base64(urllib.unquote(signature))
    return p.verify(h, signature)


def sign_plaintext(oauth_consumer_secret, token_shared_secret=''):
    return '%s&%s' % (oauth_consumer_secret, token_shared_secret)


def get_base_uri(authenticated_request):
    port_header = authenticated_request
    host_header = authenticated_request
    resource_uri = authenticated_request
    parsed_url = urlparse(resource_uri)
    scheme = parsed_url.scheme.lower()
    host = parsed_url.netloc.lower()
    port = parsed_url.port
    path = parsed_url.path

    if host_header != host or port != port_header:
        raise Exception

    if port == 80 or port == 443:
        base_uri = "%s://%s%s" % (scheme, host, port, path)
    else:
        base_uri = "%s://%s:%s%s" % (scheme, host, port, path)
    return base_uri



def get_parameters(authenticated_request):
    '''
    '''
    parameters = {}
    parsed_url = urlparse(authenticated_request.uri)
    query_components = decode_request_query(parsed_url.query)
    authorization_header_parameters = authenticated_request.authorization_header_parameters

    if authenticated_request.headers."Content-Type" == '"application/x-www-form-urlencoded"':
        entity_body_parameters = authenticated_request.body_parameters

    parameters.update(query_components)
    parameters.update(authorization_header_parameters)
    parameters.update(entity_body_parameters)

    try:
        del parameters['oauth_signature']
    except:
        pass

    parameters = {encode_parameter(k):
                  encode_oauth(v)
                  for k, v in parameters.iteritems()}
    sorted(parameters)
    return ', '.join('%s=%s' % (k, v) for k, v in d.iteritems())



def get_base_string(authenticated_request):
    request_method = authenticated_request.request_method.upper()
    base_uri = get_base_uri(authenticated_request)
    parameters = get_parameters(authenticated_request)
    base_string = "%s&%s&%s"
    return base_string % (base_string, base_uri, parameters)




def sign_request(authenticated_request,
                 oauth_consumer_secret,
                 token_shared_secret=None):
    oauth_signature_method = authenticated_request.oauth_signature_method
    signature_base_string = get_base_string(authenticated_request)
    if oauth_signature_method == 'hm1':
        return sign_hmac_sha1(signature_base_string,
                              oauth_consumer_secret,
                              token_shared_secret)
    elif oauth_signature_method == 'rsa':
        return sign_rsa_sha1()
    elif oauth_signature_method == 'plaintext':
        return sign_plaintext(oauth_consumer_secret,
                              token_shared_secret)


def verify_signature(authenticated_request,
                 oauth_consumer_secret,
                 token_shared_secret=None,
                 rsa_publickey=None):
    oauth_signature_method = authenticated_request.oauth_signature_method
    signature_base_string = get_base_string(authenticated_request)
    oauth_signature = authenticated_request.oauth_signature
    if oauth_signature_method == 'hm1':
        return (sign_hmac_sha1(signature_base_string,
                              oauth_consumer_secret,
                              token_shared_secret) == oauth_signature)
    elif oauth_signature_method == 'rsa':
        return verify_rsa_sha1(signature_base_string, 
                               rsa_publickey, 
                               oauth_signature)
    elif oauth_signature_method == 'plaintext':
        return (sign_plaintext(oauth_consumer_secret,
                              token_shared_secret) == oauth_signature)


