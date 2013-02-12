from sga_oauth.shared.helpers.encode import encode_oauth, encode_parameters, \
    encode_secrets
import binascii
import hmac

try:
    from hashlib import sha1
    sha = sha1
except ImportError:
    import sha


def sign_request(method, parameters, oauth_consumer_secret, oauth_token_secret=''):
    try:
        del parameters['oauth_signature']
    except:
        pass
    sig = (
        encode_oauth(method),
        encode_parameters(parameters),
    )
    key = encode_secrets(oauth_consumer_secret, oauth_token_secret)
    raw = '&'.join(sig)
    hashed = hmac.new(key, raw, sha)
    return hashed.hexdigest()

