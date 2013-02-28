from Crypto.Hash import SHA
from Crypto.PublicKey import DSA
from sga_oauth.shared.helpers.encode import encode_oauth
import hmac
import urllib
try:
    from hashlib import sha1
    sha = sha1
except ImportError:
    import sha



def hmac_sha1(signature_base_string):
    key = '&'.join(
                   encode_parameter(oauth_consumer_secret),
                   encode_parameter(token_shared-secret)
                   )
    text = signature_base_string
    digest = hmac.new(key, text, sha).digest()
    binascii.b2a_base64(hashed.digest())[:-1]



def sign_request():
    signature_base_string = get_base_string()
    if hmac_sha1:
        return hmac_sha1(signature_base_string)
    else:
        return sign_rsa_sha1()
    


def sign_rsa_sha1():
    key = rsa_privatekey
    text = signature_base_string
    hash = SHA.new(text).digest()
    signature = key.sign(hash, '')[0]
    binascii.b2a_base64(signature)[:-1]



def verify_rsa_sha1():
    key = rsa_privatekey
    text = signature_base_string
    hash = SHA.new(text).digest()
    signature = key.verify(hash, '')[0]
    binascii.b2a_base64(signature)[:-1]



def sign_rsa_sha1(oauth_consumer_secret, oauth_token_secret, signature):
    '''
    K     is set to the client's RSA private key,
    
    M     is set to the value of the signature base string from
          Section 3.4.1.1, and
    S     is the result signature used to set the value of the
          "oauth_signature" protocol parameter, after the result octet
          string is base64-encoded per [RFC2045] section 6.8.
      
    S = RSASSA-PKCS1-V1_5-SIGN (K, M)
    '''
    text = encode_secrets(oauth_consumer_secret, oauth_token_secret)
    hash = SHA.new(text).digest()
    signature = private_key.sign(hash, K)
    return signature #base64-encoded







def get_base_string()
    #The HTTP request method (e.g., "GET", "POST", etc.).
    request_method = 
    "&"
    #The authority as declared by the HTTP "Host" request header field.
    host =
    "&" 
    #The path and query components of the request resource URI.
    "&" 
    #The protocol parameters excluding the "oauth_signature".
    "&"
    parameter = get_parameters()
    #Parameters included in the request entity-body if they comply with the strict restrictions defined in Section 3.4.1.3.


def get_parameters():
    parameters = {}
    parameters.update(get_parameters)
    parameters.update(authorization_parameters)
    parameters.update(body_parameters)
    try:
        del parameters['oauth_signature']
    except:
        pass
    #Encoded
    d = {encode_parameter(k): encode_oauth(v) for k, v in parameters.iteritems()}
    #Sorted
    sorted(d)
    #Concatenated Pairs
    return ', '.join('%s=%s' % (k, v) for k, v in d.iteritems())



def encode_parameter(s):
    if isinstance(s, basestring):
        return urllib.quote(s.encode('utf8'), safe='~')
    else:
        return s
